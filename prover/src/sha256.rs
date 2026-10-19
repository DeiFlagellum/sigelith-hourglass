//! SHA-256 (FIPS 180-4) - wlasna implementacja, bez zewnetrznych bibliotek (HOURGLASS.md D3).
//!
//! Dwie wersje funkcji kompresji: przenosna (referencja) i z instrukcjami SHA-NI na x86_64.
//! Wybor przez `Backend`; obie musza dawac te same bajty (testy NIST CAVP i roznicowy).

pub const IV: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

pub(crate) const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Backend {
    Portable,
    #[cfg(target_arch = "x86_64")]
    ShaNi,
}

impl Backend {
    /// Najszybsza wersja dostepna na tym procesorze (D3: prover liczy najszybciej, jak umiemy).
    pub fn best() -> Backend {
        #[cfg(target_arch = "x86_64")]
        {
            if x86::available() {
                return Backend::ShaNi;
            }
        }
        Backend::Portable
    }

    pub fn by_name(name: &str) -> Result<Backend, String> {
        match name {
            "portable" => Ok(Backend::Portable),
            #[cfg(target_arch = "x86_64")]
            "shani" => {
                if x86::available() {
                    Ok(Backend::ShaNi)
                } else {
                    Err("ten procesor nie ma instrukcji SHA-NI".into())
                }
            }
            "best" => Ok(Backend::best()),
            other => Err(format!("nieznana wersja SHA-256: {other}")),
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Backend::Portable => "portable",
            #[cfg(target_arch = "x86_64")]
            Backend::ShaNi => "shani",
        }
    }

    /// Wszystkie wersje dostepne na tym procesorze (do testow zgodnosci).
    pub fn available_all() -> Vec<Backend> {
        let mut out = vec![Backend::Portable];
        #[cfg(target_arch = "x86_64")]
        {
            if x86::available() {
                out.push(Backend::ShaNi);
            }
        }
        out
    }
}

/// Kompresja kolejnych blokow 64-bajtowych (dlugosc `blocks` musi byc wielokrotnoscia 64).
#[inline]
pub fn compress_blocks(backend: Backend, state: &mut [u32; 8], blocks: &[u8]) {
    assert!(blocks.len() % 64 == 0, "dlugosc nie jest wielokrotnoscia 64");
    match backend {
        Backend::Portable => {
            for block in blocks.chunks_exact(64) {
                compress_portable(state, block);
            }
        }
        #[cfg(target_arch = "x86_64")]
        // Bezpieczne: Backend::ShaNi powstaje tylko po sprawdzeniu instrukcji procesora.
        Backend::ShaNi => unsafe { x86::compress_blocks(state, blocks) },
    }
}

fn compress_portable(state: &mut [u32; 8], block: &[u8]) {
    let mut w = [0u32; 64];
    for (i, word) in w.iter_mut().take(16).enumerate() {
        *word = u32::from_be_bytes([block[4 * i], block[4 * i + 1], block[4 * i + 2], block[4 * i + 3]]);
    }
    for i in 16..64 {
        let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
        let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16].wrapping_add(s0).wrapping_add(w[i - 7]).wrapping_add(s1);
    }
    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *state;
    for i in 0..64 {
        let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
        let ch = (e & f) ^ (!e & g);
        let t1 = h.wrapping_add(s1).wrapping_add(ch).wrapping_add(K[i]).wrapping_add(w[i]);
        let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let t2 = s0.wrapping_add(maj);
        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(t1);
        d = c;
        c = b;
        b = a;
        a = t1.wrapping_add(t2);
    }
    for (s, v) in state.iter_mut().zip([a, b, c, d, e, f, g, h]) {
        *s = s.wrapping_add(v);
    }
}

pub fn state_bytes(state: &[u32; 8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, word) in state.iter().enumerate() {
        out[4 * i..4 * i + 4].copy_from_slice(&word.to_be_bytes());
    }
    out
}

/// Pelny SHA-256 dowolnych danych (z dopelnieniem z FIPS 180-4).
pub fn digest(backend: Backend, data: &[u8]) -> [u8; 32] {
    let mut state = IV;
    let full = data.len() / 64 * 64;
    compress_blocks(backend, &mut state, &data[..full]);
    let rest = &data[full..];
    let mut tail = [0u8; 128];
    tail[..rest.len()].copy_from_slice(rest);
    tail[rest.len()] = 0x80;
    let tail_len = if rest.len() < 56 { 64 } else { 128 };
    let bits = (data.len() as u64).wrapping_mul(8);
    tail[tail_len - 8..tail_len].copy_from_slice(&bits.to_be_bytes());
    compress_blocks(backend, &mut state, &tail[..tail_len]);
    state_bytes(&state)
}

#[cfg(target_arch = "x86_64")]
mod x86 {
    use super::K;
    use core::arch::x86_64::*;

    pub fn available() -> bool {
        is_x86_feature_detected!("sha")
            && is_x86_feature_detected!("sse2")
            && is_x86_feature_detected!("ssse3")
            && is_x86_feature_detected!("sse4.1")
    }

    /// Kompresja z instrukcjami SHA-NI. Stan miedzy blokami trzymany w ukladzie ABEF/CDGH,
    /// jak wymagaja instrukcje sha256rnds2; plan wiadomosci: sha256msg1/msg2.
    #[target_feature(enable = "sha,sse2,ssse3,sse4.1")]
    pub unsafe fn compress_blocks(state: &mut [u32; 8], blocks: &[u8]) {
        let mask = _mm_set_epi64x(0x0c0d0e0f08090a0bu64 as i64, 0x0405060700010203u64 as i64);
        let mut tmp = _mm_loadu_si128(state.as_ptr() as *const __m128i);
        let mut state1 = _mm_loadu_si128(state.as_ptr().add(4) as *const __m128i);
        tmp = _mm_shuffle_epi32(tmp, 0xB1); // CDAB
        state1 = _mm_shuffle_epi32(state1, 0x1B); // EFGH
        let mut state0 = _mm_alignr_epi8(tmp, state1, 8); // ABEF
        state1 = _mm_blend_epi16(state1, tmp, 0xF0); // CDGH

        for block in blocks.chunks_exact(64) {
            let abef = state0;
            let cdgh = state1;
            let p = block.as_ptr() as *const __m128i;
            // r[x & 3] trzyma W_x; plan wiadomosci liczony z wyprzedzeniem, w kolejnosci
            // znanej z implementacji referencyjnych SHA-NI (msg1 trzy grupy, msg2 jedna
            // grupe przed uzyciem) - lancuch sha256rnds2 nie czeka na plan.
            let mut r = [_mm_setzero_si128(); 4];
            for g in 0..16usize {
                if g < 4 {
                    r[g] = _mm_shuffle_epi8(_mm_loadu_si128(p.add(g)), mask);
                }
                let k = _mm_loadu_si128(K.as_ptr().add(4 * g) as *const __m128i);
                let msg = _mm_add_epi32(r[g & 3], k);
                state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
                if (3..=14).contains(&g) {
                    // W_{g+1} = msg2(msg1(W_{g-3}, W_{g-2}) + alignr(W_g, W_{g-1}, 4), W_g)
                    let t = _mm_alignr_epi8(r[g & 3], r[(g + 3) & 3], 4);
                    let nx = (g + 1) & 3;
                    r[nx] = _mm_sha256msg2_epu32(_mm_add_epi32(r[nx], t), r[g & 3]);
                }
                state0 = _mm_sha256rnds2_epu32(state0, state1, _mm_shuffle_epi32(msg, 0x0E));
                if (1..=12).contains(&g) {
                    // czesc planu dla W_{g+3}: msg1(W_{g-1}, W_g)
                    let pv = (g + 3) & 3;
                    r[pv] = _mm_sha256msg1_epu32(r[pv], r[g & 3]);
                }
            }
            state0 = _mm_add_epi32(state0, abef);
            state1 = _mm_add_epi32(state1, cdgh);
        }

        tmp = _mm_shuffle_epi32(state0, 0x1B); // FEBA
        state1 = _mm_shuffle_epi32(state1, 0xB1); // DCHG
        state0 = _mm_blend_epi16(tmp, state1, 0xF0); // DCBA
        state1 = _mm_alignr_epi8(state1, tmp, 8); // HGFE
        _mm_storeu_si128(state.as_mut_ptr() as *mut __m128i, state0);
        _mm_storeu_si128(state.as_mut_ptr().add(4) as *mut __m128i, state1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    #[test]
    fn fips_examples() {
        let cases: [(&[u8], &str); 4] = [
            (b"", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
            (b"abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
            (
                b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
                "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
            ),
            (
                b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
                "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1",
            ),
        ];
        let million = vec![b'a'; 1_000_000];
        for backend in Backend::available_all() {
            for (msg, want) in cases {
                assert_eq!(hex(&digest(backend, msg)), want, "{}", backend.name());
            }
            assert_eq!(
                hex(&digest(backend, &million)),
                "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
            );
        }
    }

    #[test]
    fn backends_agree_on_every_length() {
        let data: Vec<u8> = (0..4096u32).map(|i| (i.wrapping_mul(2654435761) >> 13) as u8).collect();
        let all = Backend::available_all();
        for len in 0..=data.len() {
            let want = digest(Backend::Portable, &data[..len]);
            for b in &all {
                assert_eq!(digest(*b, &data[..len]), want, "len {len} {}", b.name());
            }
        }
    }
}
