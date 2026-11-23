# -*- coding: utf-8 -*-
"""Sigelith Hourglass (Klepsydra) - implementacja referencyjna, v1 i faza 0 (p0).

Wylacznie biblioteka standardowa Pythona. Kazda funkcja odpowiada punktowi
specyfikacji SPEC.md (numery paragrafow w komentarzach).
Prover w tym pliku jest dla malych n (wektory, testy, demonstracje); prover
produkcyjny (prover/, Rust) musi dawac te same bajty co ten plik
(vectors/vectors.json).

Klepsydra to dowod pracy sekwencyjnej (PoSW) Cohena-Pietrzaka, nie VDF.

Uzycie z wiersza polecen:

    python -I hourglass_ref.py verify <katalog> [--key <base64>]...
    python -I hourglass_ref.py age <katalog> [--key <base64>]...

verify: <katalog> zawiera genesis.json oraz segments/<j>.json i segments/<j>.proof - caly
ciag od genesis. age: <katalog> zawiera segments/ z odcinkami i ... j bez genesis (dowod wieku
wpisu wchlonietego w odcinek i); dowody moga byc przedrostkami (SPEC.md §10.1).
--key: klucz publiczny operatora z jego historii kluczy (v1, SPEC.md §8); bez --key podpisy
nie sa sprawdzane - dolne ograniczenie czasu od nich nie zalezy.
"""
import base64
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
_OPERATOR = re.compile(r'^[a-z0-9](?:[a-z0-9.-]{0,62}[a-z0-9])?$')

# §1 Tagi wersji i identyfikatory formatow (HOURGLASS.md D9).
TAGS = {'p0': 'sigelith-hourglass-p0', 'v1': 'sigelith-hourglass-v1'}
FORMATS = {
    'p0': {'genesis': 'sigelith-hourglass-p0-genesis', 'segment': 'sigelith-hourglass-p0-segment'},
    'v1': {'genesis': 'sigelith-hourglass-genesis-v1', 'segment': 'sigelith-hourglass-segment-v1'},
}
# §1, §8 Domena podpisu rekordu v1 (HOURGLASS.md D5) - jak kwit `sigelith-receipt-v1|`.
SIG_DOMAIN = 'sigelith-hourglass-segment-v1|'


class HourglassError(ValueError):
    """Dane niezgodne ze specyfikacja."""


class ForkError(HourglassError):
    """Dwa rozne korzenie albo ziarna dla tego samego odcinka - incydent (§9)."""


def _require(cond: bool, message: str) -> None:
    if not cond:
        raise HourglassError(message)


def _sep(tag: str, kind: str) -> bytes:
    """§1 Separator domeny, np. b'sigelith-hourglass-v1|node|'."""
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
    """Sprawdza dowod odcinka: t * (n + 1) wywolan SHA-256. Dla przedrostka dowodu
    (pierwsze t' kontroli, §10.1) wystarczy podac t' zamiast t."""
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

GENESIS_KEYS = {
    'p0': frozenset({'v', 'hash', 'n', 't', 'lambda', 'checkpoint', 'btc', 'utc', 'k_assumed',
                     's_self_nodes_per_s'}),
    'v1': frozenset({'v', 'hash', 'operator', 'n', 't', 'lambda', 'checkpoint', 'btc', 'utc', 'k_assumed',
                     's_ref_nodes_per_s'}),
}
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


def check_operator(value) -> None:
    """§7 v1: identyfikator operatora zegara - 1 do 64 znakow a-z, 0-9, '.', '-', na poczatku
    i na koncu litera albo cyfra (zwyczajowo domena operatora)."""
    _require(isinstance(value, str) and bool(_OPERATOR.match(value)), 'operator: 1-64 znakow a-z 0-9 . -')


def check_genesis(tag: str, st: dict) -> None:
    _require(tag in FORMATS, f'nieznany tag {tag!r}')
    _require(isinstance(st, dict) and set(st) == GENESIS_KEYS[tag], 'genesis: zly zestaw pol')
    _require(st['v'] == FORMATS[tag]['genesis'], f"genesis: v musi byc {FORMATS[tag]['genesis']}")
    _require(st['hash'] == 'sha-256', 'genesis: hash musi byc sha-256')
    check_params(st['n'], st['t'], st['lambda'])
    _check_checkpoint(st['checkpoint'])
    _check_btc(st['btc'])
    _check_utc(st['utc'], 'genesis.utc')
    _check_int(st['k_assumed'], 'k_assumed', 1)
    if tag == 'p0':
        _check_int(st['s_self_nodes_per_s'], 's_self_nodes_per_s', 1)
    else:
        check_operator(st['operator'])
        _check_int(st['s_ref_nodes_per_s'], 's_ref_nodes_per_s', 1)
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


# §8 Podpis rekordu v1: Ed25519 (RFC 8032), wzorowane na kodzie z rozdzialu 6 RFC.
# Weryfikacja bez bibliotek spoza stdlib (HOURGLASS.md D4). Podpisywanie (_ed25519_sign) jest
# TYLKO dla wektorow i testow: nie dziala w stalym czasie - nigdy z prawdziwym kluczem.
# Prawdziwy rekord podpisuje publikujacy operator, nigdy prover (HOURGLASS.md D16).

_ED_P = 2 ** 255 - 19
_ED_L = 2 ** 252 + 27742317777372353535851937790883648493
_ED_D = -121665 * pow(121666, _ED_P - 2, _ED_P) % _ED_P
_ED_SQRT_M1 = pow(2, (_ED_P - 1) // 4, _ED_P)


def _ed_recover_x(y: int, sign: int):
    if y >= _ED_P:
        return None
    x2 = (y * y - 1) * pow(_ED_D * y * y + 1, _ED_P - 2, _ED_P) % _ED_P
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (_ED_P + 3) // 8, _ED_P)
    if (x * x - x2) % _ED_P:
        x = x * _ED_SQRT_M1 % _ED_P
    if (x * x - x2) % _ED_P:
        return None
    if (x & 1) != sign:
        x = _ED_P - x
    return x


_ED_GY = 4 * pow(5, _ED_P - 2, _ED_P) % _ED_P
_ED_GX = _ed_recover_x(_ED_GY, 0)
_ED_G = (_ED_GX, _ED_GY, 1, _ED_GX * _ED_GY % _ED_P)


def _ed_add(p, q):
    a = (p[1] - p[0]) * (q[1] - q[0]) % _ED_P
    b = (p[1] + p[0]) * (q[1] + q[0]) % _ED_P
    c = 2 * p[3] * q[3] * _ED_D % _ED_P
    d = 2 * p[2] * q[2] % _ED_P
    e, f, g, h = b - a, d - c, d + c, b + a
    return (e * f % _ED_P, g * h % _ED_P, f * g % _ED_P, e * h % _ED_P)


def _ed_mul(s: int, p):
    q = (0, 1, 1, 0)
    while s > 0:
        if s & 1:
            q = _ed_add(q, p)
        p = _ed_add(p, p)
        s >>= 1
    return q


def _ed_equal(p, q) -> bool:
    return (p[0] * q[2] - q[0] * p[2]) % _ED_P == 0 and (p[1] * q[2] - q[1] * p[2]) % _ED_P == 0


def _ed_compress(p) -> bytes:
    zinv = pow(p[2], _ED_P - 2, _ED_P)
    x, y = p[0] * zinv % _ED_P, p[1] * zinv % _ED_P
    return (y | ((x & 1) << 255)).to_bytes(32, 'little')


def _ed_decompress(s: bytes):
    y = int.from_bytes(s, 'little')
    sign = y >> 255
    y &= (1 << 255) - 1
    x = _ed_recover_x(y, sign)
    return None if x is None else (x, y, 1, x * y % _ED_P)


def _ed_hash(data: bytes) -> int:
    return int.from_bytes(hashlib.sha512(data).digest(), 'little') % _ED_L


def ed25519_verify(public: bytes, message: bytes, signature: bytes) -> bool:
    """RFC 8032 §5.1.7: [S]B = R + [k]A (rownanie bez kofaktora, jak kod z rozdzialu 6 RFC);
    odrzuca S >= L i niepoprawne kodowanie punktow."""
    if not (isinstance(public, bytes) and isinstance(signature, bytes) and isinstance(message, bytes)):
        return False
    if len(public) != 32 or len(signature) != 64:
        return False
    a = _ed_decompress(public)
    r = _ed_decompress(signature[:32])
    if a is None or r is None:
        return False
    s = int.from_bytes(signature[32:], 'little')
    if s >= _ED_L:
        return False
    k = _ed_hash(signature[:32] + public + message)
    return _ed_equal(_ed_mul(s, _ED_G), _ed_add(r, _ed_mul(k, a)))


def _ed25519_expand(secret: bytes):
    _require(isinstance(secret, bytes) and len(secret) == 32, 'sekret Ed25519: 32 bajty')
    h = hashlib.sha512(secret).digest()
    a = int.from_bytes(h[:32], 'little')
    a &= (1 << 254) - 8
    a |= 1 << 254
    return a, h[32:]


def ed25519_public_key(secret: bytes) -> bytes:
    """Klucz publiczny z 32-bajtowego sekretu (wektory i testy)."""
    return _ed_compress(_ed_mul(_ed25519_expand(secret)[0], _ED_G))


def _ed25519_sign(secret: bytes, message: bytes) -> bytes:
    """Podpis RFC 8032 - WYLACZNIE wektory i testy (nie w stalym czasie)."""
    a, prefix = _ed25519_expand(secret)
    public = _ed_compress(_ed_mul(a, _ED_G))
    r = _ed_hash(prefix + message)
    r_enc = _ed_compress(_ed_mul(r, _ED_G))
    s = (r + _ed_hash(r_enc + public + message) * a) % _ED_L
    return r_enc + s.to_bytes(32, 'little')


def b64_field(value, size: int, name: str) -> bytes:
    """Kanoniczne base64 (RFC 4648, z dopelnieniem) dokladnie `size` bajtow."""
    _require(isinstance(value, str), f'{name}: oczekiwane base64')
    try:
        raw = base64.b64decode(value, validate=True)
    except ValueError:
        raise HourglassError(f'{name}: niepoprawne base64') from None
    _require(len(raw) == size and base64.b64encode(raw).decode('ascii') == value,
             f'{name}: oczekiwane kanoniczne base64 {size} bajtow')
    return raw


def signing_message(rec: dict) -> bytes:
    """§8 Bajty podpisu rekordu v1: `sigelith-hourglass-segment-v1|` + JCS(rekord bez `sig`)."""
    return SIG_DOMAIN.encode('ascii') + canonical_json({k: v for k, v in rec.items() if k != 'sig'})


def sign_record_for_tests(rec: dict, secret: bytes) -> dict:
    """Rekord v1 z polami key i sig dla wektorow i testow (klucz testowy)."""
    body = {k: v for k, v in rec.items() if k not in ('key', 'sig')}
    body['key'] = base64.b64encode(ed25519_public_key(secret)).decode('ascii')
    return dict(body, sig=base64.b64encode(_ed25519_sign(secret, signing_message(body))).decode('ascii'))


# §8 Rekord odcinka.

_P0_SEGMENT_KEYS = frozenset({'v', 'j', 'n', 't', 'lambda', 'prev_root', 'inputs', 'seed', 'root', 'proof',
                              'utc_end', 'gaps', 'speed', 'ptb_offset_us', 'k_assumed', 'claim_permille',
                              'coverage_permille'})
SEGMENT_KEYS = {
    'p0': _P0_SEGMENT_KEYS,
    'v1': _P0_SEGMENT_KEYS | {'s_ref_nodes_per_s', 'key', 'sig'},
}
# v1 prosto z provera, przed podpisem: bez key i sig (prover nigdy nie ma klucza, D16)
UNSIGNED_KEYS_V1 = _P0_SEGMENT_KEYS | {'s_ref_nodes_per_s'}


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


def check_segment(tag: str, rec: dict, proof: bytes, prev_root: bytes, prev_utc: str, keys=None,
                  signed: bool = True, allow_prefix: bool = False) -> int:
    """Sprawdza jeden rekord odcinka wzgledem poprzedniego korzenia i czasu (§8-9).

    keys: historia kluczy operatora (napisy base64) - podpis v1 sprawdzany tylko, gdy podana.
    signed=False: rekord v1 prosto z provera, przed podpisem (sprawdza publikujacy, §8).
    allow_prefix: dowod moze byc przedrostkiem z t' < t kontroli (dowod wieku, §10.1).
    Zwraca liczbe sprawdzonych kontroli t' (= t dla pelnego dowodu)."""
    _require(tag in FORMATS, f'nieznany tag {tag!r}')
    fields = SEGMENT_KEYS[tag] if signed or tag == 'p0' else UNSIGNED_KEYS_V1
    _require(isinstance(rec, dict) and set(rec) == fields, 'rekord: zly zestaw pol')
    _require(rec['v'] == FORMATS[tag]['segment'], f"rekord: v musi byc {FORMATS[tag]['segment']}")
    _check_int(rec['j'], 'j', 1)
    j = rec['j']
    check_params(rec['n'], rec['t'], rec['lambda'])
    canonical_json(rec)
    _check_hex64(rec['prev_root'], 'prev_root')
    _require(bytes.fromhex(rec['prev_root']) == prev_root, f'odcinek {j}: prev_root nie pasuje do poprzedniego korzenia')
    check_inputs(rec['inputs'])
    _require(rec['inputs']['utc'] >= prev_utc, f'odcinek {j}: inputs.utc wczesniejsze niz koniec poprzedniego')
    _check_utc(rec['utc_end'], 'utc_end')
    _require(rec['utc_end'] > rec['inputs']['utc'], f'odcinek {j}: utc_end nie po starcie')
    chi = seed(tag, j, prev_root, rec['inputs'])
    _check_hex64(rec['seed'], 'seed')
    _require(bytes.fromhex(rec['seed']) == chi, f'odcinek {j}: ziarno nie wynika z prev_root i inputs')
    _check_hex64(rec['root'], 'root')
    pf = rec['proof']
    _require(isinstance(pf, dict) and set(pf) == {'file', 'sha256'}, 'proof: pola file i sha256')
    _require(isinstance(pf['file'], str) and bool(_PROOF_FILE.match(pf['file'])), 'proof.file: <j>.proof')
    _check_hex64(pf['sha256'], 'proof.sha256')
    _require(isinstance(proof, bytes), f'odcinek {j}: dowod to bajty')
    one = rec['n'] * LABEL
    if len(proof) == rec['t'] * one:
        _require(hashlib.sha256(proof).hexdigest() == pf['sha256'], f'odcinek {j}: skrot pliku dowodu nie pasuje')
        checked = rec['t']
    else:
        _require(allow_prefix, f"odcinek {j}: dowod ma {len(proof)} bajtow zamiast {rec['t'] * one}")
        # przedrostek: skrotu calego pliku nie da sie porownac - kontrole wprost wobec ziarna i korzenia
        _require(len(proof) % one == 0 and 1 <= len(proof) // one < rec['t'],
                 f'odcinek {j}: przedrostek dowodu musi miec od 1 do t - 1 pelnych kontroli')
        checked = len(proof) // one
    _require(verify_segment(tag, rec['n'], checked, chi, bytes.fromhex(rec['root']), proof),
             f'odcinek {j}: dowod NIE przechodzi kontroli')
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
    if tag == 'v1':
        _check_int(rec['s_ref_nodes_per_s'], 's_ref_nodes_per_s', 1)
        if signed:
            public = b64_field(rec['key'], 32, 'key')
            sig = b64_field(rec['sig'], 64, 'sig')
            if keys is not None:
                _require(rec['key'] in keys, f'odcinek {j}: klucz {rec["key"]} spoza historii kluczy operatora')
                _require(ed25519_verify(public, signing_message(rec), sig), f'odcinek {j}: podpis NIE pasuje')
    return checked


# §9 Ciag odcinkow i rozwidlenia.

def verify_chain(tag: str, genesis: dict, records: list, proofs: list, keys=None, signed: bool = True) -> bytes:
    """Sprawdza genesis i odcinki 1..m po kolei, z pelnymi dowodami. Zwraca korzen ostatniego."""
    _require(len(records) == len(proofs), 'tyle samo rekordow co dowodow')
    phi = genesis_root(tag, genesis)
    prev_utc = genesis['utc']
    for expected_j, (rec, proof) in enumerate(zip(records, proofs), 1):
        _require(isinstance(rec, dict) and rec.get('j') == expected_j, f'brak ciaglosci numeracji przy odcinku {expected_j}')
        check_segment(tag, rec, proof, phi, prev_utc, keys=keys, signed=signed)
        phi = bytes.fromhex(rec['root'])
        prev_utc = rec['utc_end']
    return phi


def verify_range(tag: str, records: list, proofs: list, keys=None) -> list:
    """§10.1 Odcinki i ... j bez genesis (dowod wieku wpisu wchlonietego w odcinek i).

    Numeracja ciagla, prev_root kazdego odcinka = root poprzedniego; dowod kazdego odcinka
    pelny albo przedrostek z co najmniej jedna kontrola - bez niej korzen nie musialby
    powstac po ziarnie i odcinki przed nim i po nim moglyby byc liczone rownolegle.
    Zwraca liczbe sprawdzonych kontroli t' dla kolejnych odcinkow."""
    _require(records and len(records) == len(proofs), 'tyle samo rekordow co dowodow, co najmniej jeden')
    first = records[0]
    _require(isinstance(first, dict), 'rekord: obiekt JSON')
    _check_int(first.get('j'), 'j', 1)
    _check_hex64(first.get('prev_root'), 'prev_root')
    phi = bytes.fromhex(first['prev_root'])
    prev_utc = ''
    checked = []
    for expected_j, (rec, proof) in enumerate(zip(records, proofs), first['j']):
        _require(isinstance(rec, dict) and rec.get('j') == expected_j, f'brak ciaglosci numeracji przy odcinku {expected_j}')
        checked.append(check_segment(tag, rec, proof, phi, prev_utc, keys=keys, allow_prefix=True))
        phi = bytes.fromhex(rec['root'])
        prev_utc = rec['utc_end']
    return checked


def find_forks(*sources: list) -> None:
    """Porownuje rekordy z kilku zrodel (np. nasza publikacja i kopia archiwalna) jednego zegara.
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

def segment_work_ms(rec: dict, t_checked: int = None) -> int:
    """§10 v1: milisekundy pracy sekwencyjnej gwarantowane przez jeden odcinek:
    floor(claim * N / (k * s_eff)), s_eff = max(s_ref, najwyzsza predkosc odcinka).
    k i s_ref z rekordu (obowiazuja w chwili liczenia). Przedrostek z t' kontroli liczy sie
    z claim_permille(t', lambda) - przy lambda = 100 zero dla t' <= 10 (§10.1)."""
    t_c = rec['t'] if t_checked is None else t_checked
    s_eff = max(rec['s_ref_nodes_per_s'], rec['speed']['nodes_per_s_max'])
    return claim_permille(t_c, rec['lambda']) * node_count(rec['n']) // (rec['k_assumed'] * s_eff)


def min_elapsed_seconds_v1(records: list, checked: list = None) -> int:
    """§10 v1: floor(suma milisekund odcinkow / 1000) - kazdy odcinek ze swoim k, s_ref i s_eff."""
    checked = checked if checked is not None else [None] * len(records)
    _require(len(checked) == len(records), 'tyle samo wartosci t\' co rekordow')
    return sum(segment_work_ms(rec, c) for rec, c in zip(records, checked)) // 1000


def min_elapsed_seconds(records: list, k: int, s_max: int) -> int:
    """Faza 0 (p0): floor(sum(claim_permille * N) / (1000 * k * s_max)) dla pelnych odcinkow
    `records`, s_max = najwyzsza zmierzona predkosc z calego okresu (HOURGLASS.md §3.6)."""
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

def _load_segments(seg_dir: str):
    # tylko rekordy <j>.json - obok leza dowody i kwity stempli (<j>.receipt.json)
    names = sorted((f for f in os.listdir(seg_dir) if re.fullmatch(r'\d+\.json', f)), key=lambda f: int(f[:-5]))
    records, proofs = [], []
    for name in names:
        with open(os.path.join(seg_dir, name), encoding='utf-8') as fh:
            rec = json.load(fh)
        pf = rec.get('proof') if isinstance(rec, dict) else None
        file_name = pf.get('file') if isinstance(pf, dict) else None
        # nazwa pliku dowodu z rekordu - tylko <j>.proof w tym samym katalogu
        _require(isinstance(file_name, str) and bool(_PROOF_FILE.match(file_name)), f'{name}: proof.file musi byc <j>.proof')
        with open(os.path.join(seg_dir, file_name), 'rb') as fh:
            proofs.append(fh.read())
        records.append(rec)
    return records, proofs


def _span(values: list) -> str:
    lo, hi = min(values), max(values)
    return f'{lo}' if lo == hi else f'{lo}..{hi}'


def _print_v1_bound(records: list, seconds: int, what: str) -> None:
    k = _span([r['k_assumed'] for r in records])
    s_ref = _span([r['s_ref_nodes_per_s'] for r in records])
    faster = sum(1 for r in records if r['speed']['nodes_per_s_max'] > r['s_ref_nodes_per_s'])
    print(f'At least {seconds} s of sequential SHA-256 work elapsed {what} - under the published '
          f'assumption k = {k} (no one computes this more than k times faster than the reference speed '
          f's_ref = {s_ref} nodes/s; {faster} segment(s) faster than s_ref counted with their own highest '
          f'speed), counting only the share of work the checks guarantee (claim_permille per segment).')


def main(argv: list) -> int:
    usage = 'usage: python -I hourglass_ref.py verify|age <directory> [--key <base64>]...'
    if len(argv) < 3 or argv[1] not in ('verify', 'age'):
        print(usage, file=sys.stderr)
        return 2
    keys, rest = [], argv[3:]
    while rest:
        if rest[0] != '--key' or len(rest) < 2:
            print(usage, file=sys.stderr)
            return 2
        keys.append(rest[1])
        rest = rest[2:]
    mode, path = argv[1], argv[2]
    try:
        records, proofs = _load_segments(os.path.join(path, 'segments'))
        if mode == 'verify':
            with open(os.path.join(path, 'genesis.json'), encoding='utf-8') as fh:
                genesis = json.load(fh)
            tag = next((t for t, f in FORMATS.items() if f['genesis'] == genesis.get('v')), None)
            _require(tag is not None, 'unknown genesis format')
            last = verify_chain(tag, genesis, records, proofs, keys=(keys or None) if tag == 'v1' else None)
        else:
            _require(bool(records), 'no segment records')
            tag = next((t for t, f in FORMATS.items() if f['segment'] == records[0].get('v')), None)
            _require(tag is not None, 'unknown segment format')
            checked = verify_range(tag, records, proofs, keys=(keys or None) if tag == 'v1' else None)
    except (HourglassError, OSError, ValueError) as exc:
        print(f'REJECTED: {exc}')
        return 1
    if mode == 'verify' and tag == 'p0':
        k = genesis['k_assumed']
        s_max = max([genesis['s_self_nodes_per_s']] + [r['speed']['nodes_per_s_max'] for r in records])
        seconds = min_elapsed_seconds(records, k, s_max)
        print(f'OK: genesis + {len(records)} segment(s) verified ({tag}); last root {last.hex()}')
        print(f'At least {seconds} s of sequential SHA-256 work elapsed from the start of segment 1 to the '
              f'end of segment {len(records)} - under the published assumption k = {k} '
              f'(no one computes this more than {k}x faster than s_max = {s_max} nodes/s), counting '
              f'only the share of work the checks guarantee (claim_permille per segment).')
        return 0
    if tag == 'v1':
        signatures = (f'{len(records)} record signature(s) verified against the given key history'
                      if keys else 'signatures NOT checked (no --key given); the bound below does not depend on them')
    if mode == 'verify':
        print(f'OK: genesis + {len(records)} segment(s) verified ({tag}, operator {genesis["operator"]}); '
              f'last root {last.hex()}')
        print(f'Signatures: {signatures}.')
        _print_v1_bound(records, min_elapsed_seconds_v1(records),
                        f'from the start of segment 1 to the end of segment {len(records)}')
        return 0
    i, j = records[0]['j'], records[-1]['j']
    full = sum(1 for rec, c in zip(records, checked) if c == rec['t'])
    print(f'OK: segments {i}..{j} verified ({tag}): {full} with the full proof, {len(records) - full} with a '
          f'proof prefix (at least one check each, so the order of all segments holds)')
    cp, btc = records[0]['inputs']['checkpoint'], records[0]['inputs']['btc']
    print(f'The inputs of segment {i} existed before it started: Sigelith checkpoint {cp["n"]} '
          f'(sha256 {cp["sha256"]}) and Bitcoin block {btc["height"]} ({btc["hash"]}).')
    if tag == 'p0':
        print('Phase 0 records: use verify with the whole chain for the phase 0 bound.')
        return 0
    print(f'Signatures: {signatures}.')
    _print_v1_bound(records, min_elapsed_seconds_v1(records, checked),
                    f'from the start of segment {i} to the end of segment {j}, so everything that checkpoint '
                    f'covers is at least that old now')
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
