# -*- coding: utf-8 -*-
"""Sigelith Hourglass (Klepsydra) - implementacja referencyjna, faza 0 (szkic M0).

Wylacznie biblioteka standardowa Pythona. Kazda funkcja odpowiada punktowi
specyfikacji SPEC.md (numery paragrafow w komentarzach).
Prover w tym pliku jest dla malych n (wektory, testy, demonstracje); prover
produkcyjny powstaje w M1 i musi dawac te same bajty co ten plik
(vectors/vectors.json).

Klepsydra to dowod pracy sekwencyjnej (PoSW) Cohena-Pietrzaka, nie VDF.

Uzycie z wiersza polecen (weryfikacja opublikowanego ciagu odcinkow):

    python -I hourglass_ref.py verify <katalog>

gdzie <katalog> zawiera genesis.json oraz segments/<j>.json i segments/<j>.proof.
"""
import datetime
import hashlib
import json
import os
import re
import sys

LABEL = 32                 # bajty etykiety (SHA-256)
MAX_N = 48                 # glebokosc drzewa odcinka
MAX_T = 1024               # liczba kontroli
MAX_LAMBDA = 256           # poziom bezpieczenstwa w bitach
_MAX_INT = 2 ** 53
_UTC = re.compile(r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$')
_HEX64 = re.compile(r'^[0-9a-f]{64}$')
_PROOF_FILE = re.compile(r'^\d{6,}\.proof$')

# §1 Tagi wersji i identyfikatory formatow (HOURGLASS.md D9).
TAGS = {'p0': 'sigelith-hourglass-p0', 'v1': 'sigelith-hourglass-v1'}
FORMATS = {
    'p0': {'genesis': 'sigelith-hourglass-p0-genesis', 'segment': 'sigelith-hourglass-p0-segment'},
    'v1': {'genesis': 'sigelith-hourglass-genesis-v1', 'segment': 'sigelith-hourglass-segment-v1'},
}


class HourglassError(ValueError):
    """Dane niezgodne ze specyfikacja."""


class ForkError(HourglassError):
    """Dwa rozne korzenie albo ziarna dla tego samego odcinka - incydent (§9)."""


def _require(cond: bool, message: str) -> None:
    if not cond:
        raise HourglassError(message)


def _sep(tag: str, kind: str) -> bytes:
    """§1 Separator domeny, np. b'sigelith-hourglass-p0|node|'."""
    _require(tag in TAGS, f'nieznany tag {tag!r}')
    return f'{TAGS[tag]}|{kind}|'.encode('ascii')


def _sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def check_params(n: int, t: int = 1, lam: int = 1) -> None:
    for name, value, lo, hi in (('n', n, 1, MAX_N), ('t', t, 1, MAX_T), ('lambda', lam, 1, MAX_LAMBDA)):
        _require(isinstance(value, int) and not isinstance(value, bool) and lo <= value <= hi,
                 f'{name} poza zakresem {lo}..{hi}')


def _check_label(value: bytes, name: str) -> None:
    _require(isinstance(value, bytes) and len(value) == LABEL, f'{name}: oczekiwane {LABEL} bajtow')


# §7 Kanoniczny JSON - ten sam podzbior JCS co checkpointy (checkpointy dziennika Sigelith).

def _check_json(value, path: str = '$') -> None:
    if value is None or isinstance(value, bool):
        return
    if isinstance(value, int):
        _require(abs(value) < _MAX_INT, f'{path}: liczba poza zakresem 2**53')
        return
    if isinstance(value, float):
        raise HourglassError(f'{path}: liczby zmiennoprzecinkowe sa zakazane')
    if isinstance(value, str):
        _require(all(ord(c) >= 0x20 for c in value), f'{path}: znak sterujacy w napisie')
        return
    if isinstance(value, list):
        for i, item in enumerate(value):
            _check_json(item, f'{path}[{i}]')
        return
    if isinstance(value, dict):
        for key, item in value.items():
            _require(isinstance(key, str) and key.isascii(), f'{path}: klucz musi byc napisem ASCII')
            _check_json(key, f'{path}.{key}')
            _check_json(item, f'{path}.{key}')
        return
    raise HourglassError(f'{path}: niedozwolony typ {type(value).__name__}')


def canonical_json(obj) -> bytes:
    """Bajty JCS (RFC 8785) dla dozwolonego podzbioru JSON."""
    _check_json(obj)
    return json.dumps(obj, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode('utf-8')


# §2-3 Graf odcinka i etykieta wezla.

def node_count(n: int) -> int:
    """N = 2^(n+1) - 1 wezlow - tyle sekwencyjnych wywolan SHA-256 robi uczciwy prover."""
    return (1 << (n + 1)) - 1


def max_parents(n: int) -> int:
    return max(2, n)


def input_length(tag: str, n: int) -> int:
    """§3 Stala dlugosc wejscia SHA-256 dla kazdego wezla odcinka o glebokosci n."""
    return len(_sep(tag, 'node')) + LABEL + 9 + LABEL * max_parents(n)


def enc_node(depth: int, bits: int) -> bytes:
    """§3 Wezel = 1 bajt glebokosci + 8 bajtow wartosci jego bitow (big-endian)."""
    return bytes([depth]) + bits.to_bytes(8, 'big')


def leaf_parents(n: int, u: int) -> list:
    """§2 Rodzice liscia u: lewe rodzenstwo na sciezce od korzenia do u, od korzenia w dol."""
    out = []
    for i in range(1, n + 1):
        prefix = u >> (n - i)
        if prefix & 1:
            out.append((i, prefix - 1))
    return out


def label(tag: str, n: int, chi: bytes, depth: int, bits: int, parents: list) -> bytes:
    """§3 Etykieta wezla: SHA-256(sep|node| || chi || enc(v) || etykiety rodzicow || zera).

    Zera dopelniaja wejscie NA KONCU do jednej dlugosci dla wszystkich wezlow:
    kazde wywolanie kosztuje tyle samo kompresji, a staly poczatek nie daje sie
    policzyc raz dla wielu wezlow."""
    _require(len(parents) <= max_parents(n), 'za duzo rodzicow')
    data = b''.join((_sep(tag, 'node'), chi, enc_node(depth, bits), *parents,
                     bytes(LABEL * (max_parents(n) - len(parents)))))
    return _sha256(data)


# §4 Kolejnosc liczenia: post-order ze stosem.

def compute(tag: str, n: int, chi: bytes, keep: bool = False):
    """Liczy odcinek w porzadku post-order. Zwraca (korzen, slownik etykiet albo None).

    Przed kazdym lisciem stos zawiera DOKLADNIE jego rodzicow (lewe rodzenstwo na
    sciezce, od korzenia w dol). Kazdy kolejny wezel zalezy od poprzedniego, wiec
    to jedna sekwencyjna sciezka przez wszystkie N wezlow; pamiec: O(n) etykiet."""
    check_params(n)
    _check_label(chi, 'chi')
    stack = []                    # [(glebokosc, bity, etykieta)]
    store = {} if keep else None
    for u in range(1 << n):
        lab = label(tag, n, chi, n, u, [entry[2] for entry in stack])
        if keep:
            store[(n, u)] = lab
        stack.append((n, u, lab))
        while len(stack) >= 2 and stack[-1][0] == stack[-2][0]:
            depth, _, right = stack.pop()
            _, left_bits, left = stack.pop()
            parent = (depth - 1, left_bits >> 1)
            plab = label(tag, n, chi, parent[0], parent[1], [left, right])
            if keep:
                store[parent] = plab
            stack.append((parent[0], parent[1], plab))
    _require(len(stack) == 1 and stack[0][0] == 0, 'blad wewnetrzny: stos po odcinku')
    return stack[0][2], store


def compute_recursive(tag: str, n: int, chi: bytes) -> dict:
    """Niezalezne liczenie wprost z definicji grafu (§2-3) - tylko do sprawdzania compute()."""
    check_params(n)
    memo = {}

    def lab(depth: int, bits: int) -> bytes:
        key = (depth, bits)
        if key not in memo:
            if depth == n:
                parents = [lab(d, b) for d, b in leaf_parents(n, bits)]
            else:
                parents = [lab(depth + 1, 2 * bits), lab(depth + 1, 2 * bits + 1)]
            memo[key] = label(tag, n, chi, depth, bits, parents)
        return memo[key]

    lab(0, 0)
    return memo


def subtree(tag: str, n: int, chi: bytes, depth: int, bits: int, left_siblings: list) -> dict:
    """Etykiety poddrzewa wezla (depth, bits), gdy znane sa etykiety lewego rodzenstwa na
    sciezce od korzenia do tego wezla (od korzenia w dol). Tak prover produkcyjny odpowiada
    na kontrole, trzymajac tylko gorne poziomy drzewa (§4, uwaga)."""
    check_params(n)
    _require(0 <= depth <= n and 0 <= bits < (1 << depth), 'zly wezel')
    expected = [(i, (bits >> (depth - i)) - 1) for i in range(1, depth + 1) if (bits >> (depth - i)) & 1]
    _require(len(left_siblings) == len(expected), 'zla liczba etykiet lewego rodzenstwa')
    stack = [(d, b, lab) for (d, b), lab in zip(expected, left_siblings)]
    base = len(stack)
    store = {}
    for u in range(bits << (n - depth), (bits + 1) << (n - depth)):
        lab = label(tag, n, chi, n, u, [entry[2] for entry in stack])
        store[(n, u)] = lab
        stack.append((n, u, lab))
        while len(stack) - base >= 2 and stack[-1][0] == stack[-2][0]:
            d, _, right = stack.pop()
            _, left_bits, left = stack.pop()
            parent = (d - 1, left_bits >> 1)
            plab = label(tag, n, chi, parent[0], parent[1], [left, right])
            store[parent] = plab
            stack.append((parent[0], parent[1], plab))
    return store


# §5 Kontrole z Fiata-Shamira, dowod i jego sprawdzenie.

def challenges(tag: str, n: int, chi: bytes, root: bytes, t: int) -> list:
    """gamma_i = pierwsze n bitow SHA-256(sep|challenge| || chi || phi || BE32(i)), i = 1..t.
    gamma_i nie zalezy od t, wiec dowod dla t jest przedrostkiem dowodu dla wiekszego t."""
    check_params(n, t)
    _check_label(chi, 'chi')
    _check_label(root, 'root')
    out = []
    for i in range(1, t + 1):
        h = _sha256(_sep(tag, 'challenge') + chi + root + i.to_bytes(4, 'big'))
        out.append(int.from_bytes(h[:8], 'big') >> (64 - n))
    return out


def make_proof(n: int, store: dict, chals: list) -> bytes:
    """Dla kazdej kontroli: etykiety rodzenstwa wezlow na sciezce od liscia do korzenia
    (glebokosc n, n-1, ..., 1). Etykiety liscia nie ma - weryfikator liczy ja z rodzicow."""
    parts = []
    for u in chals:
        for d in range(n, 0, -1):
            parts.append(store[(d, (u >> (n - d)) ^ 1)])
    return b''.join(parts)


def verify_segment(tag: str, n: int, t: int, chi: bytes, root: bytes, proof: bytes) -> bool:
    """Sprawdza dowod odcinka: t * (n + 1) wywolan SHA-256."""
    check_params(n, t)
    _check_label(chi, 'chi')
    _check_label(root, 'root')
    if not isinstance(proof, bytes) or len(proof) != t * n * LABEL:
        return False
    for idx, u in enumerate(challenges(tag, n, chi, root, t)):
        base = idx * n * LABEL
        sibs = [proof[base + LABEL * k: base + LABEL * (k + 1)] for k in range(n)]
        # sibs[k] = rodzenstwo na glebokosci n - k
        parents = [sibs[n - i] for i, _ in leaf_parents(n, u)]
        cur = label(tag, n, chi, n, u, parents)
        for d in range(n, 0, -1):
            prefix = u >> (n - d)
            sib = sibs[n - d]
            pair = [sib, cur] if prefix & 1 else [cur, sib]
            cur = label(tag, n, chi, d - 1, prefix >> 1, pair)
        if cur != root:
            return False
    return True


# §6 Czesc krokow gwarantowana przez kontrole.

def claim_permille(t: int, lam: int) -> int:
    """Najwieksze p (promile), dla ktorego (p/1000)^t <= 2^-lambda - w liczbach calkowitych."""
    check_params(1, t, lam)
    limit = 1000 ** t
    lo, hi = 0, 1000
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if (mid ** t) << lam <= limit:
            lo = mid
        else:
            hi = mid - 1
    return lo


# §7 Genesis, wejscia i ziarno.

GENESIS_KEYS = frozenset({'v', 'hash', 'n', 't', 'lambda', 'checkpoint', 'btc', 'utc',
                          'k_assumed', 's_self_nodes_per_s'})
INPUT_KEYS = frozenset({'btc', 'checkpoint', 'utc'})


def _check_utc(value, name: str) -> None:
    _require(isinstance(value, str) and bool(_UTC.match(value)), f'{name}: oczekiwane YYYY-MM-DDTHH:MM:SS.ffffffZ')


def _check_hex64(value, name: str) -> None:
    _require(isinstance(value, str) and bool(_HEX64.match(value)), f'{name}: oczekiwane 64 znaki hex (male litery)')


def _check_int(value, name: str, lo: int = 0) -> None:
    _require(isinstance(value, int) and not isinstance(value, bool) and lo <= value < _MAX_INT,
             f'{name}: oczekiwana liczba calkowita >= {lo}')


def _check_btc(btc) -> None:
    _require(isinstance(btc, dict) and set(btc) == {'height', 'hash'}, 'btc: pola height i hash')
    _check_int(btc['height'], 'btc.height')
    _check_hex64(btc['hash'], 'btc.hash')


def _check_checkpoint(cp) -> None:
    _require(isinstance(cp, dict) and set(cp) == {'n', 'sha256'}, 'checkpoint: pola n i sha256')
    _check_int(cp['n'], 'checkpoint.n', 1)
    _check_hex64(cp['sha256'], 'checkpoint.sha256')


def check_genesis(tag: str, st: dict) -> None:
    _require(isinstance(st, dict) and set(st) == GENESIS_KEYS, 'genesis: zly zestaw pol')
    _require(st['v'] == FORMATS[tag]['genesis'], f"genesis: v musi byc {FORMATS[tag]['genesis']}")
    _require(st['hash'] == 'sha-256', 'genesis: hash musi byc sha-256')
    check_params(st['n'], st['t'], st['lambda'])
    _check_checkpoint(st['checkpoint'])
    _check_btc(st['btc'])
    _check_utc(st['utc'], 'genesis.utc')
    _check_int(st['k_assumed'], 'k_assumed', 1)
    _check_int(st['s_self_nodes_per_s'], 's_self_nodes_per_s', 1)
    canonical_json(st)


def genesis_root(tag: str, st: dict) -> bytes:
    """phi_0 = SHA-256(sep|genesis| || JCS(genesis))."""
    check_genesis(tag, st)
    return _sha256(_sep(tag, 'genesis') + canonical_json(st))


def check_inputs(inputs: dict) -> None:
    _require(isinstance(inputs, dict) and set(inputs) == INPUT_KEYS, 'inputs: pola btc, checkpoint, utc')
    _check_btc(inputs['btc'])
    _check_checkpoint(inputs['checkpoint'])
    _check_utc(inputs['utc'], 'inputs.utc')


def inputs_digest(inputs: dict) -> bytes:
    """x_j = SHA-256(JCS(inputs))."""
    check_inputs(inputs)
    return _sha256(canonical_json(inputs))


def seed(tag: str, j: int, prev_root: bytes, inputs: dict) -> bytes:
    """chi_j = SHA-256(sep|seed| || BE64(j) || phi_{j-1} || x_j)."""
    _check_int(j, 'j', 1)
    _check_label(prev_root, 'prev_root')
    return _sha256(_sep(tag, 'seed') + j.to_bytes(8, 'big') + prev_root + inputs_digest(inputs))


# §8 Rekord odcinka.

SEGMENT_KEYS = frozenset({'v', 'j', 'n', 't', 'lambda', 'prev_root', 'inputs', 'seed', 'root', 'proof',
                          'utc_end', 'gaps', 'speed', 'ptb_offset_us', 'k_assumed', 'claim_permille',
                          'coverage_permille'})


def utc_micros(value: str) -> int:
    _check_utc(value, 'utc')
    dt = datetime.datetime.strptime(value, '%Y-%m-%dT%H:%M:%S.%fZ').replace(tzinfo=datetime.timezone.utc)
    epoch = datetime.datetime(1970, 1, 1, tzinfo=datetime.timezone.utc)
    delta = dt - epoch
    return (delta.days * 86400 + delta.seconds) * 1_000_000 + delta.microseconds


def coverage_permille(n: int, nodes_per_s_max: int, utc_start: str, utc_end: str) -> int:
    """Pokrycie N / (najwyzsza predkosc odcinka * czas zegarowy), w promilach - informacja,
    nie czesc dowodu (HOURGLASS.md D16)."""
    wall = utc_micros(utc_end) - utc_micros(utc_start)
    _require(wall > 0 and nodes_per_s_max > 0, 'pokrycie: zly czas albo predkosc')
    return (1000 * node_count(n) * 1_000_000) // (nodes_per_s_max * wall)


def check_segment(tag: str, rec: dict, proof: bytes, prev_root: bytes, prev_utc: str) -> None:
    """Sprawdza jeden rekord odcinka wzgledem poprzedniego korzenia i czasu (§8)."""
    _require(isinstance(rec, dict) and set(rec) == SEGMENT_KEYS, 'rekord: zly zestaw pol')
    _require(rec['v'] == FORMATS[tag]['segment'], f"rekord: v musi byc {FORMATS[tag]['segment']}")
    _check_int(rec['j'], 'j', 1)
    check_params(rec['n'], rec['t'], rec['lambda'])
    canonical_json(rec)
    _check_hex64(rec['prev_root'], 'prev_root')
    _require(bytes.fromhex(rec['prev_root']) == prev_root, f"odcinek {rec['j']}: prev_root nie pasuje do poprzedniego korzenia")
    check_inputs(rec['inputs'])
    _require(rec['inputs']['utc'] >= prev_utc, f"odcinek {rec['j']}: inputs.utc wczesniejsze niz koniec poprzedniego")
    _check_utc(rec['utc_end'], 'utc_end')
    _require(rec['utc_end'] > rec['inputs']['utc'], f"odcinek {rec['j']}: utc_end nie po starcie")
    chi = seed(tag, rec['j'], prev_root, rec['inputs'])
    _check_hex64(rec['seed'], 'seed')
    _require(bytes.fromhex(rec['seed']) == chi, f"odcinek {rec['j']}: ziarno nie wynika z prev_root i inputs")
    _check_hex64(rec['root'], 'root')
    pf = rec['proof']
    _require(isinstance(pf, dict) and set(pf) == {'file', 'sha256'}, 'proof: pola file i sha256')
    _require(isinstance(pf['file'], str) and bool(_PROOF_FILE.match(pf['file'])), 'proof.file: <j>.proof')
    _check_hex64(pf['sha256'], 'proof.sha256')
    _require(hashlib.sha256(proof).hexdigest() == pf['sha256'], f"odcinek {rec['j']}: skrot pliku dowodu nie pasuje")
    _require(verify_segment(tag, rec['n'], rec['t'], chi, bytes.fromhex(rec['root']), proof),
             f"odcinek {rec['j']}: dowod NIE przechodzi kontroli")
    _require(isinstance(rec['gaps'], list), 'gaps: lista')
    for gap in rec['gaps']:
        _require(isinstance(gap, dict) and set(gap) == {'from_node', 'utc_stop', 'utc_resume', 'reason'}, 'gaps: zle pola')
        _check_int(gap['from_node'], 'gaps.from_node')
        _check_utc(gap['utc_stop'], 'gaps.utc_stop')
        _check_utc(gap['utc_resume'], 'gaps.utc_resume')
        _require(isinstance(gap['reason'], str), 'gaps.reason: napis')
    sp = rec['speed']
    _require(isinstance(sp, dict) and set(sp) == {'nodes_per_s_min', 'nodes_per_s_median', 'nodes_per_s_max'}, 'speed: zle pola')
    for key in sp:
        _check_int(sp[key], f'speed.{key}', 1)
    _require(sp['nodes_per_s_min'] <= sp['nodes_per_s_median'] <= sp['nodes_per_s_max'], 'speed: min <= mediana <= max')
    _require(rec['ptb_offset_us'] is None or isinstance(rec['ptb_offset_us'], int), 'ptb_offset_us: liczba albo null')
    _check_int(rec['k_assumed'], 'k_assumed', 1)
    _require(rec['claim_permille'] == claim_permille(rec['t'], rec['lambda']), 'claim_permille nie wynika z t i lambda')
    _require(rec['coverage_permille'] == coverage_permille(rec['n'], sp['nodes_per_s_max'], rec['inputs']['utc'],
                                                           rec['utc_end']), 'coverage_permille nie wynika z danych')


# §9 Ciag odcinkow i rozwidlenia.

def verify_chain(tag: str, genesis: dict, records: list, proofs: list) -> bytes:
    """Sprawdza genesis i odcinki 1..m po kolei. Zwraca korzen ostatniego odcinka."""
    _require(len(records) == len(proofs), 'tyle samo rekordow co dowodow')
    phi = genesis_root(tag, genesis)
    prev_utc = genesis['utc']
    for expected_j, (rec, proof) in enumerate(zip(records, proofs), 1):
        _require(isinstance(rec, dict) and rec.get('j') == expected_j, f'brak ciaglosci numeracji przy odcinku {expected_j}')
        check_segment(tag, rec, proof, phi, prev_utc)
        phi = bytes.fromhex(rec['root'])
        prev_utc = rec['utc_end']
    return phi


def find_forks(*sources: list) -> None:
    """Porownuje rekordy z kilku zrodel (np. nasza publikacja i kopia archiwalna).
    Rozne korzenie albo ziarna dla tego samego j - ForkError."""
    seen = {}
    for records in sources:
        for rec in records:
            key = rec['j']
            value = (rec['seed'], rec['root'])
            if key in seen and seen[key] != value:
                raise ForkError(f'rozwidlenie: odcinek {key} ma dwa rozne korzenie albo ziarna')
            seen[key] = value


# §10 Odstep i wiek minimalny (liczby calkowite).

def min_elapsed_seconds(records: list, k: int, s_max: int) -> int:
    """Dolne ograniczenie czasu w pelnych sekundach dla pelnych odcinkow `records`:
    floor(sum(claim_permille * N) / (1000 * k * s_max)). Wiek minimalny wpisu = ta sama
    suma po odcinkach od tego, ktory wchlonal wpis, do najnowszego (HOURGLASS.md §3.6)."""
    _check_int(k, 'k', 1)
    _check_int(s_max, 's_max', 1)
    total = sum(rec['claim_permille'] * node_count(rec['n']) for rec in records)
    return total // (1000 * k * s_max)


def absorbing_segment(records: list, checkpoint_sha256: str) -> int:
    """Numer pierwszego odcinka, ktorego ziarno wchlonelo dany checkpoint (albo 0)."""
    for rec in records:
        if rec['inputs']['checkpoint']['sha256'] == checkpoint_sha256:
            return rec['j']
    return 0


# Wiersz polecen.

def _load_dir(path: str):
    with open(os.path.join(path, 'genesis.json'), encoding='utf-8') as fh:
        genesis = json.load(fh)
    seg_dir = os.path.join(path, 'segments')
    # tylko rekordy <j>.json - obok leza dowody i kwity stempli (<j>.receipt.json)
    names = sorted((f for f in os.listdir(seg_dir) if re.fullmatch(r'\d+\.json', f)), key=lambda f: int(f[:-5]))
    records, proofs = [], []
    for name in names:
        with open(os.path.join(seg_dir, name), encoding='utf-8') as fh:
            rec = json.load(fh)
        with open(os.path.join(seg_dir, rec['proof']['file']), 'rb') as fh:
            proofs.append(fh.read())
        records.append(rec)
    return genesis, records, proofs


def main(argv: list) -> int:
    if len(argv) != 3 or argv[1] != 'verify':
        print('usage: python -I hourglass_ref.py verify <directory>', file=sys.stderr)
        return 2
    genesis, records, proofs = _load_dir(argv[2])
    tag = next((t for t, f in FORMATS.items() if f['genesis'] == genesis.get('v')), None)
    if tag is None:
        print('unknown genesis format', file=sys.stderr)
        return 1
    try:
        last = verify_chain(tag, genesis, records, proofs)
    except HourglassError as exc:
        print(f'REJECTED: {exc}')
        return 1
    k = genesis['k_assumed']
    s_max = max([genesis['s_self_nodes_per_s']] + [r['speed']['nodes_per_s_max'] for r in records])
    seconds = min_elapsed_seconds(records, k, s_max)
    print(f'OK: genesis + {len(records)} segment(s) verified ({tag}); last root {last.hex()}')
    print(f'At least {seconds} s of sequential SHA-256 work elapsed from the start of segment 1 to the '
          f'end of segment {len(records)} - under the published assumption k = {k} '
          f'(no one computes this more than {k}x faster than s_max = {s_max} nodes/s), counting '
          f'only the share of work the checks guarantee (claim_permille per segment).')
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
