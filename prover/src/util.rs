//! Czas (canonical_utc), zapis atomowy, pliki klucz=wartosc.

use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

pub fn now_micros() -> i64 {
    let d = SystemTime::now().duration_since(UNIX_EPOCH).expect("zegar systemowy przed 1970");
    d.as_secs() as i64 * 1_000_000 + i64::from(d.subsec_micros())
}

fn civil_from_days(z: i64) -> (i64, i64, i64) {
    // H. Hinnant, „chrono-Compatible Low-Level Date Algorithms”
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    (y, m, d)
}

fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// `YYYY-MM-DDTHH:MM:SS.ffffffZ` - ten sam zapis co canonical_utc w logu.
pub fn utc_string(micros: i64) -> String {
    let secs = micros.div_euclid(1_000_000);
    let us = micros.rem_euclid(1_000_000);
    let (y, m, d) = civil_from_days(secs.div_euclid(86_400));
    let sod = secs.rem_euclid(86_400);
    format!("{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}.{us:06}Z", sod / 3600, (sod / 60) % 60, sod % 60)
}

pub fn parse_utc(s: &str) -> Result<i64, String> {
    let b = s.as_bytes();
    let ok = b.len() == 27
        && b[4] == b'-' && b[7] == b'-' && b[10] == b'T' && b[13] == b':' && b[16] == b':'
        && b[19] == b'.' && b[26] == b'Z';
    if !ok {
        return Err(format!("zly czas {s}"));
    }
    let num = |a: usize, z: usize| -> Result<i64, String> {
        s[a..z].parse::<i64>().map_err(|_| format!("zly czas {s}"))
    };
    let (y, mo, d) = (num(0, 4)?, num(5, 7)?, num(8, 10)?);
    let (h, mi, se, us) = (num(11, 13)?, num(14, 16)?, num(17, 19)?, num(20, 26)?);
    let secs = days_from_civil(y, mo, d) * 86_400 + h * 3600 + mi * 60 + se;
    let back = utc_string(secs * 1_000_000 + us);
    if back != s {
        return Err(format!("zly czas {s}"));
    }
    Ok(secs * 1_000_000 + us)
}

/// Zapis atomowy: plik tymczasowy, fsync, rename (i fsync katalogu na Linuksie) - HOURGLASS.md D7.
pub fn write_atomic(path: &Path, data: &[u8]) -> Result<(), String> {
    let mut tmp = PathBuf::from(path);
    let name = format!("{}.tmp", path.file_name().and_then(|n| n.to_str()).unwrap_or("plik"));
    tmp.set_file_name(name);
    {
        let mut f = File::create(&tmp).map_err(|e| format!("{}: {e}", tmp.display()))?;
        f.write_all(data).map_err(|e| format!("{}: {e}", tmp.display()))?;
        f.sync_all().map_err(|e| format!("{}: {e}", tmp.display()))?;
    }
    // Windows odmawia podmiany pliku, ktory ktos akurat czyta - krotkie ponowienia (Linux: od razu).
    let mut attempt = 0;
    loop {
        match fs::rename(&tmp, path) {
            Ok(()) => break,
            Err(_) if attempt < 100 => {
                attempt += 1;
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
            Err(e) => return Err(format!("{}: {e}", path.display())),
        }
    }
    #[cfg(unix)]
    {
        if let Some(dir) = path.parent() {
            if let Ok(d) = File::open(dir) {
                let _ = d.sync_all();
            }
        }
    }
    Ok(())
}

pub fn read_kv(path: &Path) -> Result<BTreeMap<String, String>, String> {
    let text = fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let mut out = BTreeMap::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (k, v) = line.split_once('=').ok_or_else(|| format!("{}: zla linia {line}", path.display()))?;
        out.insert(k.trim().to_string(), v.trim().to_string());
    }
    Ok(out)
}

pub fn write_kv(path: &Path, map: &BTreeMap<String, String>) -> Result<(), String> {
    let mut text = String::new();
    for (k, v) in map {
        text.push_str(k);
        text.push('=');
        text.push_str(v);
        text.push('\n');
    }
    write_atomic(path, text.as_bytes())
}

pub fn get<'a>(map: &'a BTreeMap<String, String>, key: &str) -> Result<&'a str, String> {
    map.get(key).map(String::as_str).ok_or_else(|| format!("brak pola {key}"))
}

pub fn get_num<T: std::str::FromStr>(map: &BTreeMap<String, String>, key: &str) -> Result<T, String> {
    get(map, key)?.parse().map_err(|_| format!("pole {key}: zla liczba"))
}

pub fn is_hex64(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn utc_round_trip() {
        for (us, s) in [
            (0i64, "1970-01-01T00:00:00.000000Z"),
            (1_760_832_000_123_456, "2025-10-19T00:00:00.123456Z"),
            (951_782_400_000_000, "2000-02-29T00:00:00.000000Z"),
        ] {
            assert_eq!(utc_string(us), s);
            assert_eq!(parse_utc(s).unwrap(), us);
        }
        assert!(parse_utc("2026-02-30T00:00:00.000000Z").is_err());
        assert!(parse_utc("2026-10-19T00:00:00Z").is_err());
    }
}
