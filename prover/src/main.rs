//! Sigelith Hourglass (Klepsydra) - prover produkcyjny (M1, w budowie).
//!
//! Dowod pracy sekwencyjnej Cohena-Pietrzaka na SHA-256 wedlug SPEC.md.
//! Musi dawac te same bajty co reference/hourglass_ref.py (wektory w
//! vectors/vectors.json). Bez zewnetrznych bibliotek (HOURGLASS.md D3, D6).

mod chain;
mod hex;
mod json;
mod node;
mod run;
mod sha256;
mod tree;
mod util;

use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::process::ExitCode;
use std::time::Instant;

use sha256::Backend;

const USAGE: &str = "uzycie:
  hourglass genesis --dir D --n N --t T --lambda L --k K [--tag p0] [--bench-seconds 20] [--backend B]
  hourglass run --dir D [--save-every-ms 5000] [--top D_TOP] [--max-segments M] [--backend B]
  hourglass selftest                         SHA-256 (FIPS), zgodnosc wersji, male drzewa
  hourglass cavp <katalog>                   wektory NIST CAVP (ShortMsg, LongMsg, Monte)
  hourglass bench [--n 20] [--backend B]     predkosc: wezly/s i kompresje/s
  hourglass root --n N --chi HEX [--tag p0] [--backend B]
  hourglass proof --n N --t T --chi HEX [--tag p0] [--top D] [--backend B] [--hex]
  hourglass sha256-diff --count C [--seed S] [--backend B]
B: portable | shani | best (domyslnie best)";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match dispatch(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("hourglass: {e}");
            ExitCode::from(1)
        }
    }
}

struct Args {
    cmd: String,
    opts: HashMap<String, String>,
    flags: Vec<String>,
    pos: Vec<String>,
}

impl Args {
    fn parse(args: &[String]) -> Result<Args, String> {
        let cmd = args.first().cloned().ok_or_else(|| USAGE.to_string())?;
        let (mut opts, mut flags, mut pos) = (HashMap::new(), Vec::new(), Vec::new());
        let mut i = 1;
        while i < args.len() {
            if let Some(key) = args[i].strip_prefix("--") {
                if key == "hex" {
                    flags.push(key.to_string());
                    i += 1;
                    continue;
                }
                let value = args.get(i + 1).ok_or_else(|| format!("--{key} wymaga wartosci"))?;
                opts.insert(key.to_string(), value.clone());
                i += 2;
            } else {
                pos.push(args[i].clone());
                i += 1;
            }
        }
        Ok(Args { cmd, opts, flags, pos })
    }

    fn get(&self, key: &str) -> Option<&str> {
        self.opts.get(key).map(String::as_str)
    }

    fn num<T: std::str::FromStr>(&self, key: &str, default: Option<T>) -> Result<T, String> {
        match self.get(key) {
            Some(v) => v.parse().map_err(|_| format!("--{key}: zla liczba {v}")),
            None => default.ok_or_else(|| format!("brak --{key}")),
        }
    }

    fn backend(&self) -> Result<Backend, String> {
        Backend::by_name(self.get("backend").unwrap_or("best"))
    }

    fn tag(&self) -> Result<String, String> {
        let tag = self.get("tag").unwrap_or("p0").to_string();
        node::tag_prefix(&tag)?;
        Ok(tag)
    }
}

fn dispatch(args: &[String]) -> Result<(), String> {
    let a = Args::parse(args)?;
    match a.cmd.as_str() {
        "genesis" => run::genesis(
            Path::new(a.get("dir").ok_or("brak --dir")?),
            &run::GenesisOpts {
                tag: a.tag()?,
                n: a.num("n", None)?,
                t: a.num("t", None)?,
                lambda: a.num("lambda", None)?,
                k: a.num("k", None)?,
                bench_seconds: a.num("bench-seconds", Some(20.0))?,
                backend: a.backend()?,
            },
        ),
        "run" => run::run(
            Path::new(a.get("dir").ok_or("brak --dir")?),
            &run::RunOpts {
                save_every_ms: a.num("save-every-ms", Some(5000))?,
                top: a.get("top").map(|v| v.parse().map_err(|_| "--top: zla liczba".to_string())).transpose()?,
                max_segments: a.get("max-segments").map(|v| v.parse().map_err(|_| "--max-segments: zla liczba".to_string())).transpose()?,
                backend: a.backend()?,
            },
        ),
        "selftest" => selftest(),
        "cavp" => cavp(a.pos.first().ok_or("cavp: podaj katalog z plikami .rsp")?),
        "bench" => bench(&a),
        "root" => cmd_root(&a),
        "proof" => cmd_proof(&a),
        "sha256-diff" => sha256_diff(&a),
        "bench-sha" => bench_sha(&a),
        "help" | "--help" | "-h" => {
            println!("{USAGE}");
            Ok(())
        }
        other => Err(format!("nieznane polecenie {other}\n{USAGE}")),
    }
}

fn selftest() -> Result<(), String> {
    let fips: [(&[u8], &str); 3] = [
        (b"", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
        (b"abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
        (
            b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
        ),
    ];
    let all = Backend::available_all();
    for b in &all {
        for (msg, want) in fips {
            if hex::encode(&sha256::digest(*b, msg)) != want {
                return Err(format!("SHA-256 {}: zly wynik dla przykladu FIPS", b.name()));
            }
        }
    }
    let data: Vec<u8> = (0..2048u32).map(|i| (i.wrapping_mul(2654435761) >> 11) as u8).collect();
    for len in 0..=data.len() {
        let want = sha256::digest(Backend::Portable, &data[..len]);
        for b in &all {
            if sha256::digest(*b, &data[..len]) != want {
                return Err(format!("SHA-256 {}: rozbieznosc przy dlugosci {len}", b.name()));
            }
        }
    }
    let chi = sha256::digest(Backend::Portable, b"selftest");
    let mut roots = Vec::new();
    for b in &all {
        for midstate in [false, true] {
            let mut h = node::NodeHasher::new(*b, "p0", 10, &chi, midstate)?;
            roots.push(tree::root(&mut h, 10, None));
        }
    }
    if roots.iter().any(|r| *r != roots[0]) {
        return Err("drzewo n = 10: wersje SHA-256 daja rozne korzenie".into());
    }
    let names: Vec<&str> = all.iter().map(|b| b.name()).collect();
    println!("OK: SHA-256 FIPS i dlugosci 0..2048, drzewo n = 10 zgodne ({}); najlepsza: {}",
             names.join(", "), Backend::best().name());
    Ok(())
}

fn cavp(dir: &str) -> Result<(), String> {
    let read = |name: &str| fs::read_to_string(Path::new(dir).join(name)).map_err(|e| format!("{name}: {e}"));
    let mut msgs: Vec<(Vec<u8>, String)> = Vec::new();
    for name in ["SHA256ShortMsg.rsp", "SHA256LongMsg.rsp"] {
        let text = read(name)?;
        let mut len_bits: Option<usize> = None;
        let mut msg: Option<Vec<u8>> = None;
        for line in text.lines() {
            let line = line.trim();
            if let Some(v) = line.strip_prefix("Len = ") {
                len_bits = Some(v.parse().map_err(|_| "zly Len".to_string())?);
            } else if let Some(v) = line.strip_prefix("Msg = ") {
                let bytes = hex::decode(v)?;
                let len = len_bits.ok_or("Msg przed Len")? / 8;
                msg = Some(bytes[..len].to_vec());
            } else if let Some(v) = line.strip_prefix("MD = ") {
                msgs.push((msg.take().ok_or("MD przed Msg")?, v.to_string()));
            }
        }
    }
    let monte = read("SHA256Monte.rsp")?;
    let mut seed: Option<[u8; 32]> = None;
    let mut expected: Vec<String> = Vec::new();
    for line in monte.lines() {
        let line = line.trim();
        if let Some(v) = line.strip_prefix("Seed = ") {
            seed = Some(hex::decode32(v)?);
        } else if let Some(v) = line.strip_prefix("MD = ") {
            expected.push(v.to_string());
        }
    }
    let seed = seed.ok_or("Monte: brak Seed")?;
    for b in Backend::available_all() {
        for (i, (msg, want)) in msgs.iter().enumerate() {
            if hex::encode(&sha256::digest(b, msg)) != *want {
                return Err(format!("CAVP {}: wektor {i} (dlugosc {}) nie zgadza sie", b.name(), msg.len()));
            }
        }
        let mut s = seed;
        for (j, want) in expected.iter().enumerate() {
            let (mut m0, mut m1, mut m2) = (s, s, s);
            for _ in 3..1003 {
                let mut buf = [0u8; 96];
                buf[..32].copy_from_slice(&m0);
                buf[32..64].copy_from_slice(&m1);
                buf[64..].copy_from_slice(&m2);
                let next = sha256::digest(b, &buf);
                m0 = m1;
                m1 = m2;
                m2 = next;
            }
            s = m2;
            if hex::encode(&s) != *want {
                return Err(format!("CAVP {}: Monte Carlo, krok {j} nie zgadza sie", b.name()));
            }
        }
        println!("OK: CAVP {}: {} wiadomosci (ShortMsg + LongMsg), Monte Carlo {} krokow", b.name(), msgs.len(), expected.len());
    }
    Ok(())
}

fn bench(a: &Args) -> Result<(), String> {
    let n: u32 = a.num("n", Some(20))?;
    let backends = match a.get("backend") {
        Some(name) => vec![Backend::by_name(name)?],
        None => Backend::available_all(),
    };
    let chi = sha256::digest(Backend::Portable, b"bench");
    for b in backends {
        let mut h = node::NodeHasher::new(b, "p0", n, &chi, true)?;
        let start = Instant::now();
        let r = tree::root(&mut h, n, None);
        let secs = start.elapsed().as_secs_f64();
        let nodes = h.calls as f64;
        let per_s = nodes / secs;
        let comp = h.compressions_per_label();
        println!("{}: n = {n}, {} wezlow w {:.2} s = {:.0} wezlow/s ({:.0} kompresji/s, {comp} na wezel), korzen {}",
                 b.name(), h.calls, secs, per_s, per_s * comp as f64, &hex::encode(&r)[..16]);
        let compressions_per_s = per_s * comp as f64;
        for big in [30u32, 31, 32, 34, 35, 36] {
            // kompresje na wezel przy duzym n (dla n > 32 bez midstate - jedna wiecej)
            let blocks = (node::input_length("p0", big)? + 9).div_ceil(64) - usize::from(big <= 32);
            let est = ((1u64 << (big + 1)) - 1) as f64 * blocks as f64 / compressions_per_s;
            println!("    szacunek n = {big}: {blocks} kompresji na wezel, {:.1} h na odcinek", est / 3600.0);
        }
    }
    Ok(())
}

/// Surowa przepustowosc SHA-256 jednego strumienia (porownanie z OpenSSL/hashlib).
fn bench_sha(a: &Args) -> Result<(), String> {
    let mb: usize = a.num("mb", Some(256))?;
    let data = vec![0x5au8; mb << 20];
    for b in Backend::available_all() {
        let start = Instant::now();
        let d = sha256::digest(b, &data);
        let secs = start.elapsed().as_secs_f64();
        let blocks = (data.len() / 64) as f64;
        println!("{}: {mb} MB w {:.3} s = {:.0} MB/s, {:.1} ns na kompresje ({})",
                 b.name(), secs, mb as f64 / secs, secs * 1e9 / blocks, &hex::encode(&d)[..16]);
    }
    Ok(())
}

fn cmd_root(a: &Args) -> Result<(), String> {
    let (tag, n, b) = (a.tag()?, a.num::<u32>("n", None)?, a.backend()?);
    let chi = hex::decode32(a.get("chi").ok_or("brak --chi")?)?;
    let mut h = node::NodeHasher::new(b, &tag, n, &chi, true)?;
    println!("{}", hex::encode(&tree::root(&mut h, n, None)));
    Ok(())
}

fn cmd_proof(a: &Args) -> Result<(), String> {
    let (tag, n, b) = (a.tag()?, a.num::<u32>("n", None)?, a.backend()?);
    let t: u32 = a.num("t", None)?;
    let dt: u32 = a.num("top", Some(n))?;
    if dt > n || !(1..=1024).contains(&t) {
        return Err("--top musi byc <= n, a --t w 1..1024".into());
    }
    let chi = hex::decode32(a.get("chi").ok_or("brak --chi")?)?;
    let mut h = node::NodeHasher::new(b, &tag, n, &chi, true)?;
    let mut top = tree::Top::new(dt);
    let r = tree::root(&mut h, n, Some(&mut top));
    let chals = tree::challenges(b, &tag, n, &chi, &r, t)?;
    let proof = tree::make_proof(&mut h, n, &top, &chals);
    println!("{}", hex::encode(&r));
    println!("{}", hex::encode(&sha256::digest(b, &proof)));
    if a.flags.iter().any(|f| f == "hex") {
        println!("{}", hex::encode(&proof));
    }
    Ok(())
}

/// Ten sam generator co w tests/test_prover.py (splitmix64).
fn splitmix(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut z = *state;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

/// Test roznicowy (D3): dlugosci 0..2048, potem `count` losowych wejsc 0..2048 bajtow.
/// Wypisuje liczbe wejsc, XOR wszystkich skrotow i sume ich pierwszych 8 bajtow mod 2^64.
fn sha256_diff(a: &Args) -> Result<(), String> {
    let count: u64 = a.num("count", None)?;
    let mut state: u64 = a.num("seed", Some(1))?;
    let b = a.backend()?;
    const BUF: usize = (1 << 20) + 2048;
    let mut buf = vec![0u8; BUF];
    for chunk in buf.chunks_mut(8) {
        let v = splitmix(&mut state).to_le_bytes();
        chunk.copy_from_slice(&v[..chunk.len()]);
    }
    let mut acc_xor = [0u8; 32];
    let mut acc_sum: u64 = 0;
    let mut total = 0u64;
    let mut feed = |data: &[u8]| {
        let d = sha256::digest(b, data);
        for (x, y) in acc_xor.iter_mut().zip(d.iter()) {
            *x ^= *y;
        }
        acc_sum = acc_sum.wrapping_add(u64::from_be_bytes(d[..8].try_into().unwrap()));
        total += 1;
    };
    for len in 0..=2048usize {
        feed(&buf[..len]);
    }
    for _ in 0..count {
        let len = (splitmix(&mut state) % 2049) as usize;
        let off = (splitmix(&mut state) % (BUF - 2048) as u64) as usize;
        feed(&buf[off..off + len]);
    }
    println!("{total} {} {acc_sum:016x}", hex::encode(&acc_xor));
    Ok(())
}
