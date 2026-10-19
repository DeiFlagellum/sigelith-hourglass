//! Genesis i petla pracy provera: odcinki, trwaly stan, wznawianie, odpowiedzi na kontrole,
//! metryki fazy 0 (HOURGLASS.md D7, D13, D16; SPEC.md §7-8).
//!
//! Katalog danych:
//!   genesis.json            - publiczny genesis (kanoniczny JSON)
//!   genesis.txt             - te same parametry dla provera (klucz=wartosc) i phi_0
//!   inputs.txt              - blok Bitcoin, checkpoint, offset PTB (pisze hourglass_sync.py)
//!   state.txt               - stan provera, zapis atomowy
//!   work/top-<j>.bin        - etykiety gornych poziomow odcinka j (tylko dopisywanie)
//!   work/samples-<j>.txt    - predkosci z kolejnych odstepow odcinka j
//!   work/pending-<j>.txt    - odcinek policzony, czeka na dowod
//!   segments/<j>.json|.proof - rekord i dowod (publiczne)
//!   metrics/metrics-<data>.csv - pomiary co minute (faza 0)

use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant};

use crate::chain::{self, Btc, Checkpoint, Gap, Genesis, Inputs, Record};
use crate::hex;
use crate::node::{NodeHasher, LABEL, MAX_N};
use crate::sha256::{self, Backend};
use crate::tree::{self, Progress, Top};
use crate::util;

#[derive(Clone)]
struct Paths {
    dir: PathBuf,
}

impl Paths {
    fn genesis_json(&self) -> PathBuf {
        self.dir.join("genesis.json")
    }
    fn genesis_kv(&self) -> PathBuf {
        self.dir.join("genesis.txt")
    }
    fn inputs(&self) -> PathBuf {
        self.dir.join("inputs.txt")
    }
    fn state(&self) -> PathBuf {
        self.dir.join("state.txt")
    }
    fn work(&self) -> PathBuf {
        self.dir.join("work")
    }
    fn segments(&self) -> PathBuf {
        self.dir.join("segments")
    }
    fn metrics(&self) -> PathBuf {
        self.dir.join("metrics")
    }
    fn top_file(&self, j: u64) -> PathBuf {
        self.work().join(format!("top-{j:06}.bin"))
    }
    fn samples_file(&self, j: u64) -> PathBuf {
        self.work().join(format!("samples-{j:06}.txt"))
    }
    fn pending_file(&self, j: u64) -> PathBuf {
        self.work().join(format!("pending-{j:06}.txt"))
    }
}

fn io<T>(r: std::io::Result<T>, what: &Path) -> Result<T, String> {
    r.map_err(|e| format!("{}: {e}", what.display()))
}

/// Wezly policzone przed lisciem u w porzadku post-order: 2u - popcount(u).
fn nodes_before(u: u64) -> u64 {
    2 * u - u64::from(u.count_ones())
}

fn default_top(n: u32) -> u32 {
    n.saturating_sub(12).min(20)
}

fn read_inputs_file(p: &Paths) -> Result<(Btc, Checkpoint, Option<i64>), String> {
    let kv = util::read_kv(&p.inputs())?;
    let btc = Btc::new(util::get_num(&kv, "btc_height")?, util::get(&kv, "btc_hash")?)?;
    let cp = Checkpoint::new(util::get_num(&kv, "checkpoint_n")?, util::get(&kv, "checkpoint_sha256")?)?;
    let ptb = kv.get("ptb_offset_us").and_then(|v| v.parse::<i64>().ok());
    Ok((btc, cp, ptb))
}

pub struct GenesisOpts {
    pub tag: String,
    pub n: u32,
    pub t: u32,
    pub lambda: u32,
    pub k: u64,
    pub bench_seconds: f64,
    pub backend: Backend,
}

pub fn genesis(dir: &Path, o: &GenesisOpts) -> Result<(), String> {
    let p = Paths { dir: dir.to_path_buf() };
    if p.genesis_json().exists() || p.genesis_kv().exists() || p.state().exists() {
        return Err("genesis juz istnieje - Klepsydra nigdy nie startuje od zera (HOURGLASS.md D7)".into());
    }
    if !(1..=MAX_N).contains(&o.n) || !(1..=1024).contains(&o.t) || !(1..=256).contains(&o.lambda) || o.k < 1 {
        return Err("parametry poza zakresem (n 1..48, t 1..1024, lambda 1..256, k >= 1)".into());
    }
    let (btc, checkpoint, _) = read_inputs_file(&p)?;
    // pomiar rozruchowy: ta sama glebokosc i ta sama wersja SHA-256 co odcinki
    let chi = sha256::digest(o.backend, b"sigelith-hourglass genesis bench");
    let mut h = NodeHasher::new(o.backend, &o.tag, o.n, &chi, true)?;
    let mut prog = Progress::new();
    let start = Instant::now();
    let _ = tree::advance(&mut h, o.n, &mut prog, None, |_| start.elapsed().as_secs_f64() < o.bench_seconds);
    let s_self = (h.calls as f64 / start.elapsed().as_secs_f64().max(1e-6)) as u64;
    let g = Genesis {
        tag: o.tag.clone(),
        n: o.n,
        t: o.t,
        lambda: o.lambda,
        checkpoint,
        btc,
        utc: util::utc_string(util::now_micros()),
        k_assumed: o.k,
        s_self: s_self.max(1),
    };
    let root = g.root(o.backend)?;
    io(fs::create_dir_all(dir), dir)?;
    util::write_atomic(&p.genesis_json(), g.json()?.canonical().as_bytes())?;
    let mut kv = BTreeMap::new();
    for (k, v) in [
        ("tag", g.tag.clone()),
        ("n", g.n.to_string()),
        ("t", g.t.to_string()),
        ("lambda", g.lambda.to_string()),
        ("k_assumed", g.k_assumed.to_string()),
        ("s_self_nodes_per_s", g.s_self.to_string()),
        ("utc", g.utc.clone()),
        ("root", hex::encode(&root)),
    ] {
        kv.insert(k.to_string(), v);
    }
    util::write_kv(&p.genesis_kv(), &kv)?;
    println!("genesis: {} | n = {}, t = {}, lambda = {}, k = {}, s_self = {} wezlow/s",
             p.genesis_json().display(), g.n, g.t, g.lambda, g.k_assumed, g.s_self);
    println!("phi_0 = {}", hex::encode(&root));
    Ok(())
}

/// Stan provera (state.txt).
struct State {
    j: u64,
    prev_root: [u8; 32],
    prev_end_us: i64,
    active: bool,
    seed: [u8; 32],
    inputs: Option<Inputs>,
    next_leaf: u64,
    stack: Vec<(u32, u64, [u8; LABEL])>,
    gaps: Vec<Gap>,
    last_save_us: i64,
}

fn put(kv: &mut BTreeMap<String, String>, k: &str, v: String) {
    kv.insert(k.to_string(), v);
}

fn clean_reason(s: &str) -> String {
    s.chars().filter(|c| c.is_ascii_graphic() || *c == ' ').filter(|c| !"|;=".contains(*c)).collect()
}

fn gaps_to_text(gaps: &[Gap]) -> String {
    gaps.iter()
        .map(|g| format!("{}|{}|{}|{}", g.from_node, g.utc_stop, g.utc_resume, clean_reason(&g.reason)))
        .collect::<Vec<_>>()
        .join(";")
}

fn gaps_from_text(s: &str) -> Result<Vec<Gap>, String> {
    if s.is_empty() {
        return Ok(Vec::new());
    }
    s.split(';')
        .map(|item| {
            let f: Vec<&str> = item.split('|').collect();
            if f.len() != 4 {
                return Err("zla przerwa w stanie".to_string());
            }
            Ok(Gap {
                from_node: f[0].parse().map_err(|_| "zla przerwa".to_string())?,
                utc_stop: f[1].to_string(),
                utc_resume: f[2].to_string(),
                reason: f[3].to_string(),
            })
        })
        .collect()
}

fn inputs_to_kv(kv: &mut BTreeMap<String, String>, prefix: &str, inp: &Inputs) {
    put(kv, &format!("{prefix}btc_height"), inp.btc.height.to_string());
    put(kv, &format!("{prefix}btc_hash"), inp.btc.hash.clone());
    put(kv, &format!("{prefix}checkpoint_n"), inp.checkpoint.n.to_string());
    put(kv, &format!("{prefix}checkpoint_sha256"), inp.checkpoint.sha256.clone());
    put(kv, &format!("{prefix}utc"), inp.utc.clone());
}

fn inputs_from_kv(kv: &BTreeMap<String, String>, prefix: &str) -> Result<Inputs, String> {
    let g = |k: &str| util::get(kv, &format!("{prefix}{k}")).map(str::to_string);
    let btc = Btc::new(g("btc_height")?.parse().map_err(|_| "zla wysokosc")?, &g("btc_hash")?)?;
    let cp = Checkpoint::new(g("checkpoint_n")?.parse().map_err(|_| "zly numer checkpointu")?, &g("checkpoint_sha256")?)?;
    let utc = g("utc")?;
    util::parse_utc(&utc)?;
    Ok(Inputs { btc, checkpoint: cp, utc })
}

impl State {
    fn save(&mut self, p: &Paths) -> Result<(), String> {
        self.last_save_us = util::now_micros();
        let mut kv = BTreeMap::new();
        put(&mut kv, "format", "sigelith-hourglass-state-1".into());
        put(&mut kv, "j", self.j.to_string());
        put(&mut kv, "prev_root", hex::encode(&self.prev_root));
        put(&mut kv, "prev_end_utc", util::utc_string(self.prev_end_us));
        put(&mut kv, "active", u8::from(self.active).to_string());
        put(&mut kv, "last_save_utc", util::utc_string(self.last_save_us));
        if self.active {
            put(&mut kv, "seed", hex::encode(&self.seed));
            if let Some(inp) = &self.inputs {
                inputs_to_kv(&mut kv, "inputs_", inp);
            }
            put(&mut kv, "next_leaf", self.next_leaf.to_string());
            let stack: Vec<String> = self.stack.iter().map(|(d, b, l)| format!("{d}.{b}.{}", hex::encode(l))).collect();
            put(&mut kv, "stack", stack.join(";"));
            put(&mut kv, "gaps", gaps_to_text(&self.gaps));
        }
        util::write_kv(&p.state(), &kv)
    }

    fn load(p: &Paths) -> Result<Option<State>, String> {
        if !p.state().exists() {
            return Ok(None);
        }
        let kv = util::read_kv(&p.state())?;
        if util::get(&kv, "format")? != "sigelith-hourglass-state-1" {
            return Err("state.txt: nieznany format".into());
        }
        let active = util::get(&kv, "active")? == "1";
        let mut st = State {
            j: util::get_num(&kv, "j")?,
            prev_root: hex::decode32(util::get(&kv, "prev_root")?)?,
            prev_end_us: util::parse_utc(util::get(&kv, "prev_end_utc")?)?,
            active,
            seed: [0u8; 32],
            inputs: None,
            next_leaf: 0,
            stack: Vec::new(),
            gaps: Vec::new(),
            last_save_us: util::parse_utc(util::get(&kv, "last_save_utc")?)?,
        };
        if active {
            st.seed = hex::decode32(util::get(&kv, "seed")?)?;
            st.inputs = Some(inputs_from_kv(&kv, "inputs_")?);
            st.next_leaf = util::get_num(&kv, "next_leaf")?;
            let stack = util::get(&kv, "stack")?;
            if !stack.is_empty() {
                for item in stack.split(';') {
                    let f: Vec<&str> = item.split('.').collect();
                    if f.len() != 3 {
                        return Err("state.txt: zly stos".into());
                    }
                    st.stack.push((
                        f[0].parse().map_err(|_| "zly stos")?,
                        f[1].parse().map_err(|_| "zly stos")?,
                        hex::decode32(f[2])?,
                    ));
                }
            }
            st.gaps = gaps_from_text(util::get(&kv, "gaps")?)?;
        }
        Ok(Some(st))
    }
}

fn load_top_file(path: &Path, top: &mut Top) -> Result<(), String> {
    if !path.exists() {
        return Ok(());
    }
    let mut data = Vec::new();
    io(io(File::open(path), path)?.read_to_end(&mut data), path)?;
    // wpis: 1 bajt glebokosci, 8 bajtow bitow, 32 bajty etykiety; niepelny ogon (przerwa w zapisie) pomijamy
    for rec in data.chunks_exact(41) {
        let bits = u64::from_be_bytes(rec[1..9].try_into().unwrap());
        top.restore(u32::from(rec[0]), bits, rec[9..41].try_into().unwrap())?;
    }
    Ok(())
}

struct Metrics {
    p: Paths,
    /// chwila poprzedniego wpisu (None = jeszcze nie bylo)
    last: Option<Instant>,
    /// (wszystkie, skradzione) takty CPU z /proc/stat przy poprzednim wpisie
    cpu: Option<(u64, u64)>,
}

/// Suma taktow CPU i takty "steal" (czas zabrany maszynie wirtualnej przez hiperwizor).
fn cpu_ticks() -> Option<(u64, u64)> {
    let stat = fs::read_to_string("/proc/stat").ok()?;
    let v: Vec<u64> = stat.lines().next()?.split_whitespace().skip(1).filter_map(|x| x.parse().ok()).collect();
    // user nice system idle iowait irq softirq steal; guest i guest_nice sa juz w user i nice
    (v.len() >= 8).then(|| (v[..8].iter().sum(), v[7]))
}

impl Metrics {
    fn maybe_write(&mut self, j: u64, next_leaf: u64, nodes_per_s: u64, force: bool) {
        if !force && self.last.is_some_and(|t| t.elapsed() < Duration::from_secs(60)) {
            return;
        }
        self.last = Some(Instant::now());
        let now = util::now_micros();
        let day = &util::utc_string(now)[..10];
        let path = self.p.metrics().join(format!("metrics-{day}.csv"));
        let new = !path.exists();
        let load = fs::read_to_string("/proc/loadavg").ok().and_then(|s| s.split_whitespace().next().map(str::to_string));
        let cpu = cpu_ticks();
        let steal = match (self.cpu, cpu) {
            (Some((t0, s0)), Some((t1, s1))) if t1 > t0 => (s1.saturating_sub(s0) * 1000 / (t1 - t0)).to_string(),
            _ => String::new(),
        };
        self.cpu = cpu;
        let ptb = read_inputs_file(&self.p).ok().and_then(|x| x.2).map(|v| v.to_string()).unwrap_or_default();
        if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(&path) {
            if new {
                let _ = writeln!(f, "utc,j,next_leaf,nodes_per_s,loadavg1,steal_permille,ptb_offset_us");
            }
            let _ = writeln!(f, "{},{j},{next_leaf},{nodes_per_s},{},{steal},{ptb}", util::utc_string(now), load.unwrap_or_default());
        }
    }
}

pub struct RunOpts {
    pub save_every_ms: u64,
    pub top: Option<u32>,
    pub max_segments: Option<u64>,
    pub backend: Backend,
}

struct Params {
    tag: String,
    n: u32,
    t: u32,
    lambda: u32,
    k: u64,
    top: u32,
}

pub fn run(dir: &Path, o: &RunOpts) -> Result<(), String> {
    let p = Paths { dir: dir.to_path_buf() };
    let g = util::read_kv(&p.genesis_kv())?;
    let n: u32 = util::get_num(&g, "n")?;
    let prm = Params {
        tag: util::get(&g, "tag")?.to_string(),
        n,
        t: util::get_num(&g, "t")?,
        lambda: util::get_num(&g, "lambda")?,
        k: util::get_num(&g, "k_assumed")?,
        top: o.top.unwrap_or_else(|| default_top(n)),
    };
    if prm.top > prm.n {
        return Err("--top nie moze byc wieksze niz n".into());
    }
    let backend = o.backend;
    for d in [p.work(), p.segments(), p.metrics()] {
        io(fs::create_dir_all(&d), &d)?;
    }
    let mut st = match State::load(&p)? {
        Some(st) => st,
        None => State {
            j: 1,
            prev_root: hex::decode32(util::get(&g, "root")?)?,
            prev_end_us: util::parse_utc(util::get(&g, "utc")?)?,
            active: false,
            seed: [0u8; 32],
            inputs: None,
            next_leaf: 0,
            stack: Vec::new(),
            gaps: Vec::new(),
            last_save_us: util::now_micros(),
        },
    };
    let mut workers: Vec<thread::JoinHandle<Result<(), String>>> = Vec::new();
    // zalegle dowody odcinkow ukonczonych przed przerwa; pending biezacego odcinka jest nieaktualny
    let mut pendings: Vec<u64> = io(fs::read_dir(p.work()), &p.work())?
        .filter_map(|e| e.ok())
        .filter_map(|e| {
            let name = e.file_name().to_string_lossy().to_string();
            name.strip_prefix("pending-").and_then(|r| r.strip_suffix(".txt")).and_then(|r| r.parse().ok())
        })
        .collect();
    pendings.sort_unstable();
    for j in pendings {
        if j >= st.j {
            let _ = fs::remove_file(p.pending_file(j));
        } else {
            let (pp, prm2) = (p.clone(), Params { tag: prm.tag.clone(), ..prm });
            workers.push(thread::spawn(move || openings(&pp, j, None, &prm2, backend)));
        }
    }
    let mut metrics = Metrics { p: p.clone(), last: None, cpu: cpu_ticks() };
    let save_every = Duration::from_millis(o.save_every_ms.max(10));
    let mut last_inputs: Option<(Btc, Checkpoint)> = st.inputs.as_ref().map(|i| (i.btc.clone(), i.checkpoint.clone()));

    loop {
        if let Some(max) = o.max_segments {
            if st.j > max && !st.active {
                break;
            }
        }
        if !st.active {
            let (btc, cp) = match read_inputs_file(&p) {
                Ok((b, c, _)) => (b, c),
                Err(e) => match &last_inputs {
                    Some((b, c)) => {
                        eprintln!("hourglass: brak swiezych wejsc ({e}) - biore ostatnie znane");
                        (b.clone(), c.clone())
                    }
                    None => return Err(format!("brak wejsc do ziarna: {e}")),
                },
            };
            let mut now = util::now_micros();
            while now <= st.prev_end_us {
                // zegar cofnal sie albo stoi - utc ziarna musi byc pozniejsze niz koniec poprzedniego odcinka
                thread::sleep(Duration::from_millis(((st.prev_end_us - now) / 1000 + 1) as u64));
                now = util::now_micros();
            }
            let inputs = Inputs { btc: btc.clone(), checkpoint: cp.clone(), utc: util::utc_string(now) };
            st.seed = chain::seed(backend, &prm.tag, st.j, &st.prev_root, &inputs)?;
            st.inputs = Some(inputs);
            st.active = true;
            st.next_leaf = 0;
            st.stack.clear();
            st.gaps.clear();
            last_inputs = Some((btc, cp));
            io(File::create(p.top_file(st.j)), &p.top_file(st.j))?;
            io(File::create(p.samples_file(st.j)), &p.samples_file(st.j))?;
            st.save(&p)?; // ziarno trwale ZANIM ruszy liczenie (D16)
        } else {
            let now = util::now_micros();
            st.gaps.push(Gap {
                from_node: nodes_before(st.next_leaf),
                utc_stop: util::utc_string(st.last_save_us),
                utc_resume: util::utc_string(now),
                reason: "restart".into(),
            });
        }

        let j = st.j;
        let mut h = NodeHasher::new(backend, &prm.tag, prm.n, &st.seed, true)?;
        let mut top = Top::new(prm.top);
        load_top_file(&p.top_file(j), &mut top)?;
        let top_path = p.top_file(j);
        let mut top_out = BufWriter::new(io(OpenOptions::new().create(true).append(true).open(&top_path), &top_path)?);
        let samples_path = p.samples_file(j);
        let mut prog = Progress {
            next_leaf: st.next_leaf,
            meta: st.stack.iter().map(|&(d, b, _)| (d, b)).collect(),
            labels: st.stack.iter().map(|&(_, _, l)| l).collect(),
        };
        let mut last_save = Instant::now();
        let mut nodes_at_save = h.calls;
        let mut last_speed = 0u64;
        // predkosc z okien >= 1 s, niezaleznie od tego, jak czesto zapisujemy stan
        let (mut win_nodes, mut win_secs) = (0u64, 0f64);
        loop {
            let res = tree::advance(&mut h, prm.n, &mut prog, Some(&mut top), |_| last_save.elapsed() < save_every);
            // dziennik gornych poziomow i predkosc z odstepu - przed zapisem stanu
            for (d, b, l) in top.take_journal() {
                let mut rec = [0u8; 41];
                rec[0] = d as u8;
                rec[1..9].copy_from_slice(&b.to_be_bytes());
                rec[9..].copy_from_slice(&l);
                io(top_out.write_all(&rec), &top_path)?;
            }
            io(top_out.flush(), &top_path)?;
            io(top_out.get_ref().sync_all(), &top_path)?;
            win_nodes += h.calls - nodes_at_save;
            win_secs += last_save.elapsed().as_secs_f64();
            if win_secs >= 1.0 {
                last_speed = (win_nodes as f64 / win_secs) as u64;
                let mut f = io(OpenOptions::new().create(true).append(true).open(&samples_path), &samples_path)?;
                io(writeln!(f, "{last_speed}"), &samples_path)?;
                io(f.sync_all(), &samples_path)?;
                (win_nodes, win_secs) = (0, 0.0);
            }
            st.next_leaf = prog.next_leaf;
            st.stack = prog.meta.iter().zip(prog.labels.iter()).map(|(&(d, b), &l)| (d, b, l)).collect();
            let Some(root) = res else {
                st.save(&p)?;
                metrics.maybe_write(j, st.next_leaf, last_speed, false);
                last_save = Instant::now();
                nodes_at_save = h.calls;
                continue;
            };
            // koniec odcinka j
            let end_us = util::now_micros();
            let mut speeds: Vec<u64> = fs::read_to_string(&samples_path)
                .unwrap_or_default()
                .lines()
                .filter_map(|l| l.trim().parse().ok())
                .collect();
            if speeds.is_empty() {
                let start_us = util::parse_utc(&st.inputs.as_ref().unwrap().utc)?;
                speeds.push((chain::node_count(prm.n) as f64 * 1e6 / (end_us - start_us).max(1) as f64) as u64);
            }
            speeds.sort_unstable();
            let ptb = read_inputs_file(&p).ok().and_then(|x| x.2);
            let mut kv = BTreeMap::new();
            put(&mut kv, "j", j.to_string());
            put(&mut kv, "prev_root", hex::encode(&st.prev_root));
            put(&mut kv, "seed", hex::encode(&st.seed));
            put(&mut kv, "root", hex::encode(&root));
            inputs_to_kv(&mut kv, "inputs_", st.inputs.as_ref().unwrap());
            put(&mut kv, "utc_end", util::utc_string(end_us));
            put(&mut kv, "gaps", gaps_to_text(&st.gaps));
            put(&mut kv, "speed_min", speeds[0].max(1).to_string());
            put(&mut kv, "speed_median", speeds[speeds.len() / 2].max(1).to_string());
            put(&mut kv, "speed_max", speeds[speeds.len() - 1].max(1).to_string());
            put(&mut kv, "ptb_offset_us", ptb.map(|v| v.to_string()).unwrap_or_default());
            util::write_kv(&p.pending_file(j), &kv)?;
            metrics.maybe_write(j, 1u64 << prm.n, last_speed, true);
            // ziarno odcinka j+1 zalezy tylko od korzenia - liczenie rusza od razu
            st.prev_root = root;
            st.prev_end_us = end_us;
            st.j += 1;
            st.active = false;
            st.inputs = None;
            st.stack.clear();
            st.next_leaf = 0;
            st.gaps.clear();
            st.save(&p)?;
            let (pp, prm2) = (p.clone(), Params { tag: prm.tag.clone(), ..prm });
            workers.push(thread::spawn(move || openings(&pp, j, Some(top), &prm2, backend)));
            break;
        }
        // sprzatanie ukonczonych watkow i zgloszenie bledow
        let mut still = Vec::new();
        for w in workers {
            if w.is_finished() {
                w.join().map_err(|_| "watek dowodu przerwany".to_string())??;
            } else {
                still.push(w);
            }
        }
        workers = still;
    }
    for w in workers {
        w.join().map_err(|_| "watek dowodu przerwany".to_string())??;
    }
    Ok(())
}

/// Odpowiedzi na kontrole dla odcinka j, zapis dowodu i rekordu (najpierw dowod, potem rekord).
fn openings(p: &Paths, j: u64, top: Option<Top>, prm: &Params, backend: Backend) -> Result<(), String> {
    let kv = util::read_kv(&p.pending_file(j))?;
    let seed = hex::decode32(util::get(&kv, "seed")?)?;
    let root = hex::decode32(util::get(&kv, "root")?)?;
    let top = match top {
        Some(t) => t,
        None => {
            let mut t = Top::new(prm.top);
            load_top_file(&p.top_file(j), &mut t)?;
            t
        }
    };
    let mut h = NodeHasher::new(backend, &prm.tag, prm.n, &seed, true)?;
    let chals = tree::challenges(backend, &prm.tag, prm.n, &seed, &root, prm.t)?;
    let proof = tree::make_proof(&mut h, prm.n, &top, &chals);
    if !tree::verify(&mut h, backend, &prm.tag, prm.n, prm.t, &seed, &root, &proof)? {
        return Err(format!("odcinek {j}: wlasny dowod nie przechodzi kontroli - nie publikuje"));
    }
    let ptb = util::get(&kv, "ptb_offset_us")?;
    let rec = Record {
        tag: prm.tag.clone(),
        j,
        n: prm.n,
        t: prm.t,
        lambda: prm.lambda,
        prev_root: hex::decode32(util::get(&kv, "prev_root")?)?,
        inputs: inputs_from_kv(&kv, "inputs_")?,
        seed,
        root,
        proof_sha256: sha256::digest(backend, &proof),
        utc_end: util::get(&kv, "utc_end")?.to_string(),
        gaps: gaps_from_text(util::get(&kv, "gaps")?)?,
        speed_min: util::get_num(&kv, "speed_min")?,
        speed_median: util::get_num(&kv, "speed_median")?,
        speed_max: util::get_num(&kv, "speed_max")?,
        ptb_offset_us: if ptb.is_empty() { None } else { Some(ptb.parse().map_err(|_| "zly ptb_offset_us")?) },
        k_assumed: prm.k,
    };
    util::write_atomic(&p.segments().join(chain::proof_file_name(j)), &proof)?;
    util::write_atomic(&p.segments().join(chain::record_file_name(j)), rec.json()?.canonical().as_bytes())?;
    for f in [p.pending_file(j), p.top_file(j), p.samples_file(j)] {
        let _ = fs::remove_file(f);
    }
    Ok(())
}
