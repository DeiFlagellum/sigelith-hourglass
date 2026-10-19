//! Zapis szesnastkowy (male litery).

pub fn encode(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(DIGITS[(b >> 4) as usize] as char);
        s.push(DIGITS[(b & 15) as usize] as char);
    }
    s
}

pub fn decode(s: &str) -> Result<Vec<u8>, String> {
    let s = s.trim();
    if s.len() % 2 != 0 {
        return Err("nieparzysta liczba znakow hex".into());
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|_| format!("zly znak hex w {s}")))
        .collect()
}

pub fn decode32(s: &str) -> Result<[u8; 32], String> {
    let v = decode(s)?;
    v.try_into().map_err(|_| "oczekiwane 32 bajty (64 znaki hex)".to_string())
}
