# -*- coding: utf-8 -*-
"""Generuje vectors/vectors.json z implementacji referencyjnej (spec §11).

    python -I reference/gen_vectors.py

Plik wektorow jest wynikiem, nie zrodlem: test tests/test_reference.py
liczy wszystko od nowa (takze niezalezna metoda rekurencyjna) i porownuje z plikiem.
Wartosci btc, checkpoint i czasy w lancuchu testowym sa wymyslone, nie produkcyjne.
"""
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


def tree_vector(n: int, all_labels: bool) -> dict:
    root, store = hg.compute(TAG, n, CHI, keep=all_labels)
    item = {'n': n, 'node_count': hg.node_count(n), 'input_length': hg.input_length(TAG, n), 'root': root.hex()}
    if all_labels:
        item['labels'] = [[d, b, store[(d, b)].hex()] for d, b in sorted(store)]
    return item


def proof_vector(n: int, t: int) -> dict:
    root, store = hg.compute(TAG, n, CHI, keep=True)
    chals = hg.challenges(TAG, n, CHI, root, t)
    proof = hg.make_proof(n, store, chals)
    return {'n': n, 't': t, 'root': root.hex(), 'challenges': chals,
            'proof_sha256': hashlib.sha256(proof).hexdigest(), 'proof': proof.hex()}


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
        inputs = {
            'btc': {'height': 970000 + j, 'hash': hashlib.sha256(f'example block {970000 + j}'.encode()).hexdigest()},
            'checkpoint': {'n': 25 + j, 'sha256': hashlib.sha256(f'example checkpoint {25 + j}'.encode()).hexdigest()},
            'utc': start,
        }
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


def build() -> dict:
    return {
        'format': 'sigelith-hourglass-vectors-p0',
        'note': 'Wygenerowane przez reference/gen_vectors.py - nie edytowac recznie.',
        'tag': TAG,
        'chi': CHI.hex(),
        'trees': [tree_vector(n, n <= 3) for n in (1, 2, 3, 4, 8, 12)],
        'proofs': [proof_vector(4, 8), proof_vector(8, 16)],
        'claim_permille': [[t, lam, hg.claim_permille(t, lam)]
                           for t, lam in ((8, 4), (64, 40), (128, 40), (128, 100), (256, 100))],
        'chain': example_chain(),
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
