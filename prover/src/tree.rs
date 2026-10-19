//! Odcinek: post-order ze stosem, gorne poziomy drzewa, poddrzewa, kontrole i dowod
//! (SPEC.md §4-5).

use std::collections::{BTreeMap, HashMap, HashSet};

use crate::node::{self, NodeHasher, LABEL};
use crate::sha256::{self, Backend};

/// Etykiety wezlow o glebokosci <= depth_max (gorne poziomy drzewa).
pub struct Top {
    pub depth_max: u32,
    labels: Vec<[u8; LABEL]>,
    /// Wezly ustawione od ostatniego odczytu `take_journal` (zapis do pliku przy zapisie stanu).
    journal: Vec<(u32, u64)>,
}

impl Top {
    pub fn new(depth_max: u32) -> Top {
        Top { depth_max, labels: vec![[0u8; LABEL]; (1usize << (depth_max + 1)) - 1], journal: Vec::new() }
    }

    fn idx(depth: u32, bits: u64) -> usize {
        ((1u64 << depth) - 1 + bits) as usize
    }

    pub fn set(&mut self, depth: u32, bits: u64, label: [u8; LABEL]) {
        if depth <= self.depth_max {
            self.labels[Self::idx(depth, bits)] = label;
            self.journal.push((depth, bits));
        }
    }

    /// Ustawienie z pliku (bez dziennika).
    pub fn restore(&mut self, depth: u32, bits: u64, label: [u8; LABEL]) -> Result<(), String> {
        if depth > self.depth_max || bits >= (1u64 << depth) {
            return Err(format!("plik gornych poziomow: zly wezel ({depth}, {bits})"));
        }
        self.labels[Self::idx(depth, bits)] = label;
        Ok(())
    }

    /// Wpisy (glebokosc, bity, etykieta) dopisane od ostatniego wywolania.
    pub fn take_journal(&mut self) -> Vec<(u32, u64, [u8; LABEL])> {
        let out = self.journal.iter().map(|&(d, b)| (d, b, self.get(d, b))).collect();
        self.journal.clear();
        out
    }

    pub fn get(&self, depth: u32, bits: u64) -> [u8; LABEL] {
        self.labels[Self::idx(depth, bits)]
    }
}

/// Stan liczenia odcinka: nastepny lisc i stos (glebokosc, bity, etykieta).
/// Stos przed lisciem u to dokladnie jego rodzice - z tego stanu liczenie mozna wznowic.
pub struct Progress {
    pub next_leaf: u64,
    pub meta: Vec<(u32, u64)>,
    pub labels: Vec<[u8; LABEL]>,
}

impl Progress {
    pub fn new() -> Progress {
        Progress { next_leaf: 0, meta: Vec::new(), labels: Vec::new() }
    }
}

/// Liczy liscie od `prog.next_leaf`. Co 4096 lisci pyta `keep_going(next_leaf)`;
/// zwraca Some(korzen) po ostatnim lisciu, None po przerwaniu (stan w `prog`).
pub fn advance(
    h: &mut NodeHasher,
    n: u32,
    prog: &mut Progress,
    mut top: Option<&mut Top>,
    mut keep_going: impl FnMut(u64) -> bool,
) -> Option<[u8; LABEL]> {
    let leaves = 1u64 << n;
    while prog.next_leaf < leaves {
        let u = prog.next_leaf;
        let label = h.label(n, u, &prog.labels);
        if let Some(t) = top.as_deref_mut() {
            t.set(n, u, label);
        }
        prog.meta.push((n, u));
        prog.labels.push(label);
        while prog.meta.len() >= 2 && prog.meta[prog.meta.len() - 1].0 == prog.meta[prog.meta.len() - 2].0 {
            let (d, _) = prog.meta.pop().unwrap();
            let right = prog.labels.pop().unwrap();
            let (_, left_bits) = prog.meta.pop().unwrap();
            let left = prog.labels.pop().unwrap();
            let (pd, pb) = (d - 1, left_bits >> 1);
            let plabel = h.label(pd, pb, &[left, right]);
            if let Some(t) = top.as_deref_mut() {
                t.set(pd, pb, plabel);
            }
            prog.meta.push((pd, pb));
            prog.labels.push(plabel);
        }
        prog.next_leaf += 1;
        if prog.next_leaf & 0xFFF == 0 && prog.next_leaf < leaves && !keep_going(prog.next_leaf) {
            return None;
        }
    }
    assert!(prog.meta.len() == 1 && prog.meta[0].0 == 0, "blad wewnetrzny: stos po odcinku");
    Some(prog.labels[0])
}

/// Korzen odcinka bez przerw (do testow i pomiarow).
pub fn root(h: &mut NodeHasher, n: u32, top: Option<&mut Top>) -> [u8; LABEL] {
    let mut prog = Progress::new();
    advance(h, n, &mut prog, top, |_| true).expect("bez przerw")
}

/// gamma_i = pierwsze n bitow SHA-256(P|challenge| ‖ chi ‖ phi ‖ BE32(i)), i = 1..t (§5).
pub fn challenges(backend: Backend, tag: &str, n: u32, chi: &[u8; 32], root: &[u8; 32], t: u32) -> Result<Vec<u64>, String> {
    let sep = node::sep(tag, "challenge")?;
    let mut buf = Vec::with_capacity(sep.len() + 68);
    let mut out = Vec::with_capacity(t as usize);
    for i in 1..=t {
        buf.clear();
        buf.extend_from_slice(&sep);
        buf.extend_from_slice(chi);
        buf.extend_from_slice(root);
        buf.extend_from_slice(&i.to_be_bytes());
        let h = sha256::digest(backend, &buf);
        let head = u64::from_be_bytes(h[..8].try_into().unwrap());
        out.push(head >> (64 - n));
    }
    Ok(out)
}

/// Lewe rodzenstwo na sciezce od korzenia do wezla (depth, bits), od korzenia w dol.
fn left_siblings(top: &Top, depth: u32, bits: u64) -> (Vec<(u32, u64)>, Vec<[u8; LABEL]>) {
    let mut meta = Vec::new();
    let mut labels = Vec::new();
    for i in 1..=depth {
        let prefix = bits >> (depth - i);
        if prefix & 1 == 1 {
            meta.push((i, prefix - 1));
            labels.push(top.get(i, prefix - 1));
        }
    }
    (meta, labels)
}

/// Przelicza poddrzewo wezla (wd, wb) i zwraca etykiety z `wanted` (glebokosci > wd).
fn subtree_collect(
    h: &mut NodeHasher,
    n: u32,
    wd: u32,
    wb: u64,
    top: &Top,
    wanted: &HashSet<(u32, u64)>,
) -> HashMap<(u32, u64), [u8; LABEL]> {
    let (mut meta, mut labels) = left_siblings(top, wd, wb);
    let base = meta.len();
    let mut out = HashMap::new();
    for u in (wb << (n - wd))..((wb + 1) << (n - wd)) {
        let label = h.label(n, u, &labels);
        if wanted.contains(&(n, u)) {
            out.insert((n, u), label);
        }
        meta.push((n, u));
        labels.push(label);
        while meta.len() - base >= 2 && meta[meta.len() - 1].0 == meta[meta.len() - 2].0 {
            let (d, _) = meta.pop().unwrap();
            let right = labels.pop().unwrap();
            let (_, left_bits) = meta.pop().unwrap();
            let left = labels.pop().unwrap();
            let (pd, pb) = (d - 1, left_bits >> 1);
            let plabel = h.label(pd, pb, &[left, right]);
            if wanted.contains(&(pd, pb)) {
                out.insert((pd, pb), plabel);
            }
            meta.push((pd, pb));
            labels.push(plabel);
        }
    }
    out
}

/// Dowod odcinka (§5): dla kazdej kontroli etykiety rodzenstwa na glebokosci n, n-1, ..., 1.
/// Rodzenstwo nad `top.depth_max` bierze z gornych poziomow, glebsze - z przeliczonych poddrzew.
pub fn make_proof(h: &mut NodeHasher, n: u32, top: &Top, chals: &[u64]) -> Vec<u8> {
    let dt = top.depth_max;
    let mut deep: HashMap<(u32, u64), [u8; LABEL]> = HashMap::new();
    if dt < n {
        let mut by_ancestor: BTreeMap<u64, HashSet<(u32, u64)>> = BTreeMap::new();
        for &u in chals {
            let set = by_ancestor.entry(u >> (n - dt)).or_default();
            for d in (dt + 1)..=n {
                set.insert((d, (u >> (n - d)) ^ 1));
            }
        }
        for (ancestor, wanted) in &by_ancestor {
            deep.extend(subtree_collect(h, n, dt, *ancestor, top, wanted));
        }
    }
    let mut proof = Vec::with_capacity(chals.len() * n as usize * LABEL);
    for &u in chals {
        for d in (1..=n).rev() {
            let sib = (d, (u >> (n - d)) ^ 1);
            let label = if d <= dt { top.get(sib.0, sib.1) } else { deep[&sib] };
            proof.extend_from_slice(&label);
        }
    }
    proof
}

/// Sprawdzenie dowodu (§5) - prover sprawdza wlasny dowod przed publikacja.
pub fn verify(h: &mut NodeHasher, backend: Backend, tag: &str, n: u32, t: u32, chi: &[u8; 32], root: &[u8; 32], proof: &[u8]) -> Result<bool, String> {
    if proof.len() != t as usize * n as usize * LABEL {
        return Ok(false);
    }
    for (idx, u) in challenges(backend, tag, n, chi, root, t)?.into_iter().enumerate() {
        let base = idx * n as usize * LABEL;
        let sib = |k: usize| -> [u8; LABEL] { proof[base + LABEL * k..base + LABEL * (k + 1)].try_into().unwrap() };
        // sib(k) = rodzenstwo na glebokosci n - k
        let mut parents = Vec::new();
        for i in 1..=n {
            if (u >> (n - i)) & 1 == 1 {
                parents.push(sib((n - i) as usize));
            }
        }
        let mut cur = h.label(n, u, &parents);
        for d in (1..=n).rev() {
            let prefix = u >> (n - d);
            let s = sib((n - d) as usize);
            let pair = if prefix & 1 == 1 { [s, cur] } else { [cur, s] };
            cur = h.label(d - 1, prefix >> 1, &pair);
        }
        if &cur != root {
            return Ok(false);
        }
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verify_accepts_own_proofs_and_rejects_changes() {
        let n = 9;
        let b = Backend::best();
        let mut h = NodeHasher::new(b, "p0", n, &chi(3), true).unwrap();
        let mut top = Top::new(4);
        let r = root(&mut h, n, Some(&mut top));
        let chals = challenges(b, "p0", n, &chi(3), &r, 16).unwrap();
        let mut proof = make_proof(&mut h, n, &top, &chals);
        assert!(verify(&mut h, b, "p0", n, 16, &chi(3), &r, &proof).unwrap());
        proof[100] ^= 1;
        assert!(!verify(&mut h, b, "p0", n, 16, &chi(3), &r, &proof).unwrap());
    }

    fn chi(i: u8) -> [u8; 32] {
        sha256::digest(Backend::Portable, &[b'c', i])
    }

    #[test]
    fn proof_from_subtrees_equals_proof_from_full_tree() {
        for backend in Backend::available_all() {
            let n = 10;
            let mut h = NodeHasher::new(backend, "p0", n, &chi(1), true).unwrap();
            let mut full = Top::new(n);
            let r1 = root(&mut h, n, Some(&mut full));
            let chals = challenges(backend, "p0", n, &chi(1), &r1, 32).unwrap();
            let p_full = make_proof(&mut h, n, &full, &chals);
            for dt in [0, 3, 7, 9] {
                let mut part = Top::new(dt);
                let r2 = root(&mut h, n, Some(&mut part));
                assert_eq!(r1, r2);
                assert_eq!(make_proof(&mut h, n, &part, &chals), p_full, "dt {dt}");
            }
        }
    }

    #[test]
    fn midstate_does_not_change_labels() {
        for backend in Backend::available_all() {
            for n in [1u32, 2, 5, 16, 32, 33] {
                let mut a = NodeHasher::new(backend, "p0", n, &chi(n as u8), true).unwrap();
                let mut b = NodeHasher::new(backend, "p0", n, &chi(n as u8), false).unwrap();
                let parents: Vec<[u8; 32]> = (0..node::max_parents(n)).map(|i| chi(i as u8)).collect();
                for depth in [0u32, n / 2, n] {
                    let bits = if depth == 0 { 0 } else { (1u64 << depth) - 1 };
                    for m in [0usize, 1, 2, node::max_parents(n)] {
                        if m > node::max_parents(n) {
                            continue;
                        }
                        assert_eq!(a.label(depth, bits, &parents[..m]), b.label(depth, bits, &parents[..m]));
                    }
                }
            }
        }
    }

    #[test]
    fn resume_gives_the_same_root() {
        let n = 14;
        let mut h = NodeHasher::new(Backend::best(), "p0", n, &chi(7), true).unwrap();
        let whole = root(&mut h, n, None);
        let mut prog = Progress::new();
        let mut stops = 0;
        let mut r = None;
        while r.is_none() {
            r = advance(&mut h, n, &mut prog, None, |leaf| leaf % (4096 * 3) != 0);
            stops += 1;
        }
        assert!(stops > 1);
        assert_eq!(r.unwrap(), whole);
    }
}
