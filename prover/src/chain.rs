//! Genesis, wejscia, ziarno, c i pokrycie, rekord odcinka (SPEC.md §6-8, §10).

use crate::json::Json;
use crate::node;
use crate::sha256::{self, Backend};
use crate::util;

pub fn format_id(tag: &str, kind: &str) -> Result<&'static str, String> {
    match (tag, kind) {
        ("p0", "genesis") => Ok("sigelith-hourglass-p0-genesis"),
        ("p0", "segment") => Ok("sigelith-hourglass-p0-segment"),
        ("v1", "genesis") => Ok("sigelith-hourglass-genesis-v1"),
        ("v1", "segment") => Ok("sigelith-hourglass-segment-v1"),
        _ => Err(format!("nieznany format {tag}/{kind}")),
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Btc {
    pub height: u64,
    pub hash: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Checkpoint {
    pub n: u64,
    pub sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Inputs {
    pub btc: Btc,
    pub checkpoint: Checkpoint,
    pub utc: String,
}

impl Btc {
    pub fn new(height: u64, hash: &str) -> Result<Btc, String> {
        if !util::is_hex64(hash) {
            return Err("btc.hash: oczekiwane 64 znaki hex".into());
        }
        Ok(Btc { height, hash: hash.to_string() })
    }

    fn json(&self) -> Json {
        Json::obj(vec![("hash", Json::str(&self.hash)), ("height", Json::Int(self.height as i64))])
    }
}

impl Checkpoint {
    pub fn new(n: u64, sha256: &str) -> Result<Checkpoint, String> {
        if n < 1 || !util::is_hex64(sha256) {
            return Err("checkpoint: n >= 1 i 64 znaki hex".into());
        }
        Ok(Checkpoint { n, sha256: sha256.to_string() })
    }

    fn json(&self) -> Json {
        Json::obj(vec![("n", Json::Int(self.n as i64)), ("sha256", Json::str(&self.sha256))])
    }
}

impl Inputs {
    pub fn json(&self) -> Json {
        Json::obj(vec![("btc", self.btc.json()), ("checkpoint", self.checkpoint.json()), ("utc", Json::str(&self.utc))])
    }
}

/// x_j = SHA-256(JCS(inputs)).
pub fn inputs_digest(backend: Backend, inputs: &Inputs) -> [u8; 32] {
    sha256::digest(backend, inputs.json().canonical().as_bytes())
}

/// chi_j = SHA-256(P|seed| ‖ BE64(j) ‖ phi_{j-1} ‖ x_j).
pub fn seed(backend: Backend, tag: &str, j: u64, prev_root: &[u8; 32], inputs: &Inputs) -> Result<[u8; 32], String> {
    let mut buf = node::sep(tag, "seed")?;
    buf.extend_from_slice(&j.to_be_bytes());
    buf.extend_from_slice(prev_root);
    buf.extend_from_slice(&inputs_digest(backend, inputs));
    Ok(sha256::digest(backend, &buf))
}

pub struct Genesis {
    pub tag: String,
    pub n: u32,
    pub t: u32,
    pub lambda: u32,
    pub checkpoint: Checkpoint,
    pub btc: Btc,
    pub utc: String,
    pub k_assumed: u64,
    pub s_self: u64,
}

impl Genesis {
    pub fn json(&self) -> Result<Json, String> {
        Ok(Json::obj(vec![
            ("v", Json::str(format_id(&self.tag, "genesis")?)),
            ("hash", Json::str("sha-256")),
            ("n", Json::Int(i64::from(self.n))),
            ("t", Json::Int(i64::from(self.t))),
            ("lambda", Json::Int(i64::from(self.lambda))),
            ("checkpoint", self.checkpoint.json()),
            ("btc", self.btc.json()),
            ("utc", Json::str(&self.utc)),
            ("k_assumed", Json::Int(self.k_assumed as i64)),
            ("s_self_nodes_per_s", Json::Int(self.s_self as i64)),
        ]))
    }

    /// phi_0 = SHA-256(P|genesis| ‖ JCS(genesis)).
    pub fn root(&self, backend: Backend) -> Result<[u8; 32], String> {
        let mut buf = node::sep(&self.tag, "genesis")?;
        buf.extend_from_slice(self.json()?.canonical().as_bytes());
        Ok(sha256::digest(backend, &buf))
    }
}

/// Minimalne liczby wielkie: tylko mnozenie przez mala liczbe, przesuniecie i porownanie.
struct Big(Vec<u32>);

impl Big {
    fn one() -> Big {
        Big(vec![1])
    }

    fn mul_small(&mut self, m: u32) {
        let mut carry = 0u64;
        for limb in self.0.iter_mut() {
            let v = u64::from(*limb) * u64::from(m) + carry;
            *limb = v as u32;
            carry = v >> 32;
        }
        if carry > 0 {
            self.0.push(carry as u32);
        }
        self.trim();
    }

    fn shl(&mut self, bits: u32) {
        let words = (bits / 32) as usize;
        let rem = bits % 32;
        if rem > 0 {
            let mut carry = 0u32;
            for limb in self.0.iter_mut() {
                let v = (*limb << rem) | carry;
                carry = *limb >> (32 - rem);
                *limb = v;
            }
            if carry > 0 {
                self.0.push(carry);
            }
        }
        let mut shifted = vec![0u32; words];
        shifted.extend_from_slice(&self.0);
        self.0 = shifted;
        self.trim();
    }

    fn trim(&mut self) {
        while self.0.len() > 1 && *self.0.last().unwrap() == 0 {
            self.0.pop();
        }
    }

    fn le(&self, other: &Big) -> bool {
        if self.0.len() != other.0.len() {
            return self.0.len() < other.0.len();
        }
        for (a, b) in self.0.iter().rev().zip(other.0.iter().rev()) {
            if a != b {
                return a < b;
            }
        }
        true
    }
}

/// Najwieksze p (promile), dla ktorego p^t * 2^lambda <= 1000^t - dokladnie, jak w spec §6.
pub fn claim_permille(t: u32, lambda: u32) -> u32 {
    let mut limit = Big::one();
    for _ in 0..t {
        limit.mul_small(1000);
    }
    let fits = |p: u32| {
        let mut v = Big::one();
        for _ in 0..t {
            v.mul_small(p);
        }
        v.shl(lambda);
        v.le(&limit)
    };
    let (mut lo, mut hi) = (0u32, 1000u32);
    while lo < hi {
        let mid = (lo + hi).div_ceil(2);
        if fits(mid) {
            lo = mid;
        } else {
            hi = mid - 1;
        }
    }
    lo
}

pub fn node_count(n: u32) -> u64 {
    (1u64 << (n + 1)) - 1
}

/// Pokrycie: floor(1000 * N * 10^6 / (najwyzsza predkosc * mikrosekundy)).
pub fn coverage_permille(n: u32, max_speed: u64, start_us: i64, end_us: i64) -> u64 {
    let wall = (end_us - start_us).max(1) as u128;
    let num = 1000u128 * u128::from(node_count(n)) * 1_000_000u128;
    (num / (u128::from(max_speed.max(1)) * wall)) as u64
}

pub struct Gap {
    pub from_node: u64,
    pub utc_stop: String,
    pub utc_resume: String,
    pub reason: String,
}

pub struct Record {
    pub tag: String,
    pub j: u64,
    pub n: u32,
    pub t: u32,
    pub lambda: u32,
    pub prev_root: [u8; 32],
    pub inputs: Inputs,
    pub seed: [u8; 32],
    pub root: [u8; 32],
    pub proof_sha256: [u8; 32],
    pub utc_end: String,
    pub gaps: Vec<Gap>,
    pub speed_min: u64,
    pub speed_median: u64,
    pub speed_max: u64,
    pub ptb_offset_us: Option<i64>,
    pub k_assumed: u64,
}

impl Record {
    pub fn json(&self) -> Result<Json, String> {
        let start = util::parse_utc(&self.inputs.utc)?;
        let end = util::parse_utc(&self.utc_end)?;
        let gaps = self
            .gaps
            .iter()
            .map(|g| {
                Json::obj(vec![
                    ("from_node", Json::Int(g.from_node as i64)),
                    ("utc_stop", Json::str(&g.utc_stop)),
                    ("utc_resume", Json::str(&g.utc_resume)),
                    ("reason", Json::str(&g.reason)),
                ])
            })
            .collect();
        Ok(Json::obj(vec![
            ("v", Json::str(format_id(&self.tag, "segment")?)),
            ("j", Json::Int(self.j as i64)),
            ("n", Json::Int(i64::from(self.n))),
            ("t", Json::Int(i64::from(self.t))),
            ("lambda", Json::Int(i64::from(self.lambda))),
            ("prev_root", Json::str(&crate::hex::encode(&self.prev_root))),
            ("inputs", self.inputs.json()),
            ("seed", Json::str(&crate::hex::encode(&self.seed))),
            ("root", Json::str(&crate::hex::encode(&self.root))),
            ("proof", Json::obj(vec![
                ("file", Json::str(&proof_file_name(self.j))),
                ("sha256", Json::str(&crate::hex::encode(&self.proof_sha256))),
            ])),
            ("utc_end", Json::str(&self.utc_end)),
            ("gaps", Json::Arr(gaps)),
            ("speed", Json::obj(vec![
                ("nodes_per_s_min", Json::Int(self.speed_min as i64)),
                ("nodes_per_s_median", Json::Int(self.speed_median as i64)),
                ("nodes_per_s_max", Json::Int(self.speed_max as i64)),
            ])),
            ("ptb_offset_us", self.ptb_offset_us.map_or(Json::Null, Json::Int)),
            ("k_assumed", Json::Int(self.k_assumed as i64)),
            ("claim_permille", Json::Int(i64::from(claim_permille(self.t, self.lambda)))),
            ("coverage_permille", Json::Int(coverage_permille(self.n, self.speed_max, start, end) as i64)),
        ]))
    }
}

pub fn record_file_name(j: u64) -> String {
    format!("{j:06}.json")
}

pub fn proof_file_name(j: u64) -> String {
    format!("{j:06}.proof")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn claim_permille_matches_spec_table() {
        assert_eq!(claim_permille(8, 4), 707);
        assert_eq!(claim_permille(64, 40), 648);
        assert_eq!(claim_permille(128, 40), 805);
        assert_eq!(claim_permille(128, 100), 581);
        assert_eq!(claim_permille(256, 100), 762);
        assert_eq!(claim_permille(512, 100), 873);
    }
}
