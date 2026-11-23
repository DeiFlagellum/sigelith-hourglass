# -*- coding: utf-8 -*-
"""Generuje vectors/vectors.json z implementacji referencyjnej (spec §11).

    python -I reference/gen_vectors.py

Plik wektorow jest wynikiem, nie zrodlem: test tests/test_reference.py
liczy wszystko od nowa (takze niezalezna metoda rekurencyjna) i porownuje z plikiem.
Wartosci btc, checkpoint i czasy w lancuchach testowych sa wymyslone, nie produkcyjne.
Klucz testowy v1 jest jawny z zalozenia - nigdy nie podpisuje niczego poza testami.
"""
import base64
import hashlib
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import hourglass_ref as hg  # noqa: E402

OUT = os.path.join(os.path.dirname(HERE), 'vectors', 'vectors.json')
TAG = 'p0'
CHI = hashlib.sha256(b'sigelith-hourglass test vector').digest()
TEST_SECRET = hashlib.sha256(b'sigelith-hourglass test key').digest()


def tree_vector(n: int, all_labels: bool, tag: str = TAG) -> dict:
    root, store = hg.compute(tag, n, CHI, keep=all_labels)
    item = {'n': n, 'node_count': hg.node_count(n), 'input_length': hg.input_length(tag, n), 'root': root.hex()}
    if all_labels:
        item['labels'] = [[d, b, store[(d, b)].hex()] for d, b in sorted(store)]
    return item


def proof_vector(n: int, t: int, tag: str = TAG) -> dict:
    root, store = hg.compute(tag, n, CHI, keep=True)
    chals = hg.challenges(tag, n, CHI, root, t)
    proof = hg.make_proof(n, store, chals)
    return {'n': n, 't': t, 'root': root.hex(), 'challenges': chals,
            'proof_sha256': hashlib.sha256(proof).hexdigest(), 'proof': proof.hex()}


def _example_inputs(j: int, start: str) -> dict:
    return {
        'btc': {'height': 970000 + j, 'hash': hashlib.sha256(f'example block {970000 + j}'.encode()).hexdigest()},
        'checkpoint': {'n': 25 + j, 'sha256': hashlib.sha256(f'example checkpoint {25 + j}'.encode()).hexdigest()},
        'utc': start,
    }


def example_chain() -> dict:
    """Genesis i dwa odcinki n = 4, t = 8, lambda = 4 (parametry TESTOWE, nie produkcyjne)."""
    n, t, lam, speed = 4, 8, 4, 1000
    genesis = {
        'v': hg.FORMATS[TAG]['genesis'], 'hash': 'sha-256', 'n': n, 't': t, 'lambda': lam,
        'checkpoint': {'n': 25, 'sha256': hashlib.sha256(b'example checkpoint 25').hexdigest()},
        'btc': {'height': 970000, 'hash': hashlib.sha256(b'example block 970000').hexdigest()},
        'utc': '2026-10-19T00:00:00.000000Z', 'k_assumed': 20, 's_self_nodes_per_s': speed,
    }
    phi = hg.genesis_root(TAG, genesis)
    records, proofs = [], []
    starts = ['2026-10-19T00:00:01.000000Z', '2026-10-19T00:00:02.000000Z']
    ends = ['2026-10-19T00:00:01.031000Z', '2026-10-19T00:00:02.062000Z']
    for j, (start, end) in enumerate(zip(starts, ends), 1):
        inputs = _example_inputs(j, start)
        chi = hg.seed(TAG, j, phi, inputs)
        root, store = hg.compute(TAG, n, chi, keep=True)
        proof = hg.make_proof(n, store, hg.challenges(TAG, n, chi, root, t))
        gaps = [] if j == 1 else [{'from_node': 15, 'utc_stop': '2026-10-19T00:00:02.015000Z',
                                   'utc_resume': '2026-10-19T00:00:02.046000Z', 'reason': 'test: restart procesu'}]
        rec = {
            'v': hg.FORMATS[TAG]['segment'], 'j': j, 'n': n, 't': t, 'lambda': lam,
            'prev_root': phi.hex(), 'inputs': inputs, 'seed': chi.hex(), 'root': root.hex(),
            'proof': {'file': f'{j:06d}.proof', 'sha256': hashlib.sha256(proof).hexdigest()},
            'utc_end': end, 'gaps': gaps,
            'speed': {'nodes_per_s_min': speed, 'nodes_per_s_median': speed, 'nodes_per_s_max': speed},
            'ptb_offset_us': 412, 'k_assumed': 20, 'claim_permille': hg.claim_permille(t, lam),
            'coverage_permille': hg.coverage_permille(n, speed, start, end),
        }
        records.append(rec)
        proofs.append(proof)
        phi = root
    hg.verify_chain(TAG, genesis, records, proofs)
    return {
        'genesis': genesis,
        'genesis_root': hg.genesis_root(TAG, genesis).hex(),
        'inputs_digest_1': hg.inputs_digest(records[0]['inputs']).hex(),
        'segments': records,
        'proofs': [p.hex() for p in proofs],
        'min_elapsed': {'k': 20, 's_max': speed,
                        'seconds_both': hg.min_elapsed_seconds(records, 20, speed),
                        'note': 'k = 20, s_max = 1000 wezlow/s: (707 * 31 * 2) // (1000 * 20 * 1000) = 0 s - '
                                'male drzewa testowe; liczba pokazuje tylko arytmetyke calkowita'},
    }


def example_chain_v1() -> dict:
    """Genesis v1 i dwa podpisane odcinki: n = 4, t = 8, lambda = 4, k = 1, s_ref = 10 wezlow/s
    (parametry TESTOWE - dobrane tak, zeby arytmetyka §10 dala niezerowe liczby)."""
    tag = 'v1'
    n, t, lam, k, s_ref = 4, 8, 4, 1, 10
    genesis = {
        'v': hg.FORMATS[tag]['genesis'], 'hash': 'sha-256', 'operator': 'example.org', 'n': n, 't': t,
        'lambda': lam,
        'checkpoint': {'n': 25, 'sha256': hashlib.sha256(b'example checkpoint 25').hexdigest()},
        'btc': {'height': 970000, 'hash': hashlib.sha256(b'example block 970000').hexdigest()},
        'utc': '2026-11-23T00:00:00.000000Z', 'k_assumed': k, 's_ref_nodes_per_s': s_ref,
    }
    phi = hg.genesis_root(tag, genesis)
    prev_utc = genesis['utc']
    # odcinek 1 wolniejszy niz s_ref (liczy sie s_ref), odcinek 2 szybszy (liczy sie jego predkosc)
    plan = [
        ('2026-11-23T00:00:01.000000Z', '2026-11-23T00:00:05.000000Z', (7, 8, 8), []),
        ('2026-11-23T00:00:06.000000Z', '2026-11-23T00:00:09.000000Z', (9, 11, 12),
         [{'from_node': 15, 'utc_stop': '2026-11-23T00:00:07.000000Z',
           'utc_resume': '2026-11-23T00:00:07.500000Z', 'reason': 'restart'}]),
    ]
    unsigned, records, proofs = [], [], []
    for j, (start, end, (lo, mid, hi), gaps) in enumerate(plan, 1):
        inputs = _example_inputs(j, start)
        chi = hg.seed(tag, j, phi, inputs)
        root, store = hg.compute(tag, n, chi, keep=True)
        proof = hg.make_proof(n, store, hg.challenges(tag, n, chi, root, t))
        rec = {
            'v': hg.FORMATS[tag]['segment'], 'j': j, 'n': n, 't': t, 'lambda': lam,
            'prev_root': phi.hex(), 'inputs': inputs, 'seed': chi.hex(), 'root': root.hex(),
            'proof': {'file': f'{j:06d}.proof', 'sha256': hashlib.sha256(proof).hexdigest()},
            'utc_end': end, 'gaps': gaps,
            'speed': {'nodes_per_s_min': lo, 'nodes_per_s_median': mid, 'nodes_per_s_max': hi},
            'ptb_offset_us': None, 'k_assumed': k, 's_ref_nodes_per_s': s_ref,
            'claim_permille': hg.claim_permille(t, lam),
            'coverage_permille': hg.coverage_permille(n, hi, start, end),
        }
        hg.check_segment(tag, rec, proof, phi, prev_utc, signed=False)   # tak sprawdza publikujacy przed podpisem
        unsigned.append(rec)
        records.append(hg.sign_record_for_tests(rec, TEST_SECRET))
        proofs.append(proof)
        phi, prev_utc = root, end
    key = base64.b64encode(hg.ed25519_public_key(TEST_SECRET)).decode('ascii')
    hg.verify_chain(tag, genesis, records, proofs, keys=[key])
    prefix = [proofs[0], proofs[1][:n * hg.LABEL]]       # odcinek 2 tylko z jedna kontrola (§10.1)
    checked = hg.verify_range(tag, records, prefix, keys=[key])
    return {
        'genesis': genesis,
        'genesis_root': hg.genesis_root(tag, genesis).hex(),
        'test_key': {'secret': TEST_SECRET.hex(), 'public': key,
                     'note': 'klucz TESTOWY = SHA-256("sigelith-hourglass test key"), jawny z zalozenia'},
        'signing_message_1': hg.signing_message(records[0]).decode('ascii'),
        'segments': records,
        'proofs': [p.hex() for p in proofs],
        'elapsed': {
            'work_ms': [hg.segment_work_ms(r) for r in records],
            'seconds': hg.min_elapsed_seconds_v1(records),
            'note': 'w_s = claim * N // (k * max(s_ref, nodes_per_s_max)): 707 * 31 // (1 * 10) = 2191 ms, '
                    '707 * 31 // (1 * 12) = 1826 ms; (2191 + 1826) // 1000 = 4 s',
        },
        'age_prefix': {
            'checked': checked,
            'work_ms': [hg.segment_work_ms(r, c) for r, c in zip(records, checked)],
            'seconds': hg.min_elapsed_seconds_v1(records, checked),
            'note': 'odcinek 2 z przedrostkiem jednej kontroli: claim_permille(1, 4) = 62, 62 * 31 // 12 = 160 ms',
        },
        'unsigned_1': unsigned[0],
    }


def build() -> dict:
    return {
        'format': 'sigelith-hourglass-vectors-v1',
        'note': 'Wygenerowane przez reference/gen_vectors.py - nie edytowac recznie. '
                'trees, proofs i chain: tag p0 (faza 0); v1: te same wielkosci z tagiem v1 i podpisany ciag.',
        'tag': TAG,
        'chi': CHI.hex(),
        'trees': [tree_vector(n, n <= 3) for n in (1, 2, 3, 4, 8, 12)],
        'proofs': [proof_vector(4, 8), proof_vector(8, 16)],
        'claim_permille': [[t, lam, hg.claim_permille(t, lam)]
                           for t, lam in ((1, 4), (8, 4), (64, 40), (128, 40), (128, 100), (256, 100))],
        'chain': example_chain(),
        'v1': {
            'trees': [tree_vector(n, n <= 2, 'v1') for n in (1, 2, 3, 4, 8, 12)],
            'proofs': [proof_vector(4, 8, 'v1'), proof_vector(8, 16, 'v1')],
            'chain': example_chain_v1(),
        },
    }


def main() -> None:
    data = build()
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, 'w', encoding='utf-8', newline='\n') as fh:
        json.dump(data, fh, ensure_ascii=False, indent=1, sort_keys=True)
        fh.write('\n')
    print('zapisano', os.path.relpath(OUT))


if __name__ == '__main__':
    main()
