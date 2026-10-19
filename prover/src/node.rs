//! Etykieta wezla odcinka (SPEC.md §1-3).
//!
//! ℓ_v = SHA-256( P|node| ‖ χ ‖ enc(v) ‖ etykiety rodzicow ‖ zera ), wejscie o stalej dlugosci
//! L = |P|node|| + 32 + 9 + 32·max(2, n). Bufor z gotowym dopelnieniem SHA-256 powstaje raz na
//! odcinek; dla n <= 32 pierwszy blok zalezy tylko od glebokosci wezla, wiec jego stan
//! (midstate) liczy sie raz dla kazdej glebokosci - tak jak zrobilby to kazdy szybki prover.

use crate::sha256::{self, Backend, IV};

pub const LABEL: usize = 32;
pub const MAX_N: u32 = 48;

pub fn tag_prefix(tag: &str) -> Result<&'static str, String> {
    match tag {
        "p0" => Ok("sigelith-hourglass-p0"),
        "v1" => Ok("sigelith-hourglass-v1"),
        other => Err(format!("nieznany tag {other}")),
    }
}

pub fn sep(tag: &str, kind: &str) -> Result<Vec<u8>, String> {
    Ok(format!("{}|{}|", tag_prefix(tag)?, kind).into_bytes())
}

pub fn max_parents(n: u32) -> usize {
    std::cmp::max(2, n as usize)
}

pub fn input_length(tag: &str, n: u32) -> Result<usize, String> {
    Ok(sep(tag, "node")?.len() + LABEL + 9 + LABEL * max_parents(n))
}

pub struct NodeHasher {
    backend: Backend,
    buf: Vec<u8>,
    enc_off: usize,
    parents_off: usize,
    parents_cap: usize,
    dirty_end: usize,
    midstates: Option<Vec<[u32; 8]>>,
    /// Liczba policzonych etykiet (do pomiarow).
    pub calls: u64,
}

impl NodeHasher {
    pub fn new(backend: Backend, tag: &str, n: u32, chi: &[u8; 32], use_midstate: bool) -> Result<Self, String> {
        if !(1..=MAX_N).contains(&n) {
            return Err(format!("n poza zakresem 1..{MAX_N}"));
        }
        let sep = sep(tag, "node")?;
        let l = input_length(tag, n)?;
        let padded = (l + 9).div_ceil(64) * 64;
        let mut buf = vec![0u8; padded];
        buf[..sep.len()].copy_from_slice(&sep);
        buf[sep.len()..sep.len() + LABEL].copy_from_slice(chi);
        buf[l] = 0x80;
        buf[padded - 8..].copy_from_slice(&((l as u64) * 8).to_be_bytes());
        let enc_off = sep.len() + LABEL;
        let parents_off = enc_off + 9;
        let mut hasher = NodeHasher {
            backend,
            buf,
            enc_off,
            parents_off,
            parents_cap: max_parents(n),
            dirty_end: parents_off,
            midstates: None,
            calls: 0,
        };
        // Pierwszy blok = separator, ziarno i poczatek enc(v): glebokosc oraz najstarsze bajty
        // wartosci bitow, ktore dla n <= 32 sa zerami.
        let bit_bytes_in_first = 64usize.min(enc_off + 9).saturating_sub(enc_off + 1);
        if use_midstate && enc_off < 64 && bit_bytes_in_first <= 4 && n <= 32 && padded > 64 {
            let mut ms = Vec::with_capacity(n as usize + 1);
            for depth in 0..=n {
                hasher.buf[enc_off] = depth as u8;
                let mut st = IV;
                sha256::compress_blocks(backend, &mut st, &hasher.buf[..64]);
                ms.push(st);
            }
            hasher.buf[enc_off] = 0;
            hasher.midstates = Some(ms);
        }
        Ok(hasher)
    }

    /// Liczba kompresji SHA-256 na jedna etykiete.
    pub fn compressions_per_label(&self) -> usize {
        self.buf.len() / 64 - usize::from(self.midstates.is_some())
    }

    /// Etykieta wezla (depth, bits) z etykietami rodzicow w kolejnosci ze spec §2.
    pub fn label(&mut self, depth: u32, bits: u64, parents: &[[u8; LABEL]]) -> [u8; LABEL] {
        assert!(parents.len() <= self.parents_cap, "za duzo rodzicow");
        let e = self.enc_off;
        self.buf[e] = depth as u8;
        self.buf[e + 1..e + 9].copy_from_slice(&bits.to_be_bytes());
        let mut off = self.parents_off;
        for p in parents {
            self.buf[off..off + LABEL].copy_from_slice(p);
            off += LABEL;
        }
        if off < self.dirty_end {
            self.buf[off..self.dirty_end].fill(0);
        }
        self.dirty_end = off;
        self.calls += 1;
        let (mut st, start) = match &self.midstates {
            Some(ms) => (ms[depth as usize], 64),
            None => (IV, 0),
        };
        sha256::compress_blocks(self.backend, &mut st, &self.buf[start..]);
        sha256::state_bytes(&st)
    }
}
