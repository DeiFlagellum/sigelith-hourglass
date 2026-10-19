# -*- coding: utf-8 -*-
"""Prover produkcyjny (prover, Rust) kontra wektory i implementacja referencyjna.

    cargo build --release --manifest-path prover/Cargo.toml
    python -I -m unittest discover -s tests -v

Test roznicowy SHA-256 z hashlib (HOURGLASS.md D3): domyslnie 200 000 losowych wejsc;
pelny przebieg 10 000 000 - zmienna srodowiskowa HOURGLASS_DIFF_COUNT=10000000.
"""
import hashlib
import json
import os
import subprocess
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BIN = os.environ.get('HOURGLASS_BIN') or os.path.join(
    ROOT, 'prover', 'target', 'release', 'hourglass' + ('.exe' if os.name == 'nt' else ''))
VECTORS = os.path.join(ROOT, 'vectors', 'vectors.json')
sys.path.insert(0, os.path.join(ROOT, 'reference'))

import hourglass_ref as hg  # noqa: E402

MASK = (1 << 64) - 1
BUF = (1 << 20) + 2048


def run(*args) -> list:
    out = subprocess.run([BIN, *map(str, args)], capture_output=True, text=True)
    if out.returncode != 0:
        raise AssertionError(f'hourglass {" ".join(map(str, args))}: {out.stderr.strip()}')
    return out.stdout.split()


def backends() -> list:
    found = ['portable']
    probe = subprocess.run([BIN, 'root', '--n', '1', '--chi', '00' * 32, '--backend', 'shani'], capture_output=True)
    if probe.returncode == 0:
        found.append('shani')
    return found


def splitmix(state: int):
    """Ten sam generator co `sha256-diff` w proverze (splitmix64)."""
    state = (state + 0x9E3779B97F4A7C15) & MASK
    z = state
    z = ((z ^ (z >> 30)) * 0xBF58476D1CE4E5B9) & MASK
    z = ((z ^ (z >> 27)) * 0x94D049BB133111EB) & MASK
    return state, z ^ (z >> 31)


def reference_diff(count: int, seed: int) -> str:
    state = seed
    parts = []
    for _ in range(BUF // 8):
        state, value = splitmix(state)
        parts.append(value.to_bytes(8, 'little'))
    buf = b''.join(parts)
    acc_xor, acc_sum, total = 0, 0, 0

    def feed(data: bytes) -> None:
        nonlocal acc_xor, acc_sum, total
        d = hashlib.sha256(data).digest()
        acc_xor ^= int.from_bytes(d, 'big')
        acc_sum = (acc_sum + int.from_bytes(d[:8], 'big')) & MASK
        total += 1

    for length in range(2049):
        feed(buf[:length])
    for _ in range(count):
        state, r1 = splitmix(state)
        state, r2 = splitmix(state)
        length = r1 % 2049
        off = r2 % (BUF - 2048)
        feed(buf[off:off + length])
    return f'{total} {acc_xor.to_bytes(32, "big").hex()} {acc_sum:016x}'


@unittest.skipUnless(os.path.exists(BIN), 'brak provera - zbuduj: cargo build --release w prover/')
class ProverTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with open(VECTORS, encoding='utf-8') as fh:
            cls.vectors = json.load(fh)
        cls.backends = backends()

    def test_selftest_and_cavp(self):
        self.assertTrue(' '.join(run('selftest')).startswith('OK'))
        out = ' '.join(run('cavp', os.path.join(ROOT, 'prover', 'cavp')))
        for b in self.backends:
            self.assertIn(f'CAVP {b}: 129', out)

    def test_roots_match_vectors(self):
        chi = self.vectors['chi']
        for tree in self.vectors['trees']:
            for b in self.backends:
                with self.subTest(n=tree['n'], backend=b):
                    self.assertEqual(run('root', '--n', tree['n'], '--chi', chi, '--backend', b), [tree['root']])

    def test_proofs_match_vectors_with_any_stored_depth(self):
        chi = self.vectors['chi']
        for pv in self.vectors['proofs']:
            n, t = pv['n'], pv['t']
            for top in sorted({n, n // 2, 0}):
                for b in self.backends:
                    with self.subTest(n=n, t=t, top=top, backend=b):
                        out = run('proof', '--n', n, '--t', t, '--chi', chi, '--top', top, '--backend', b, '--hex')
                        self.assertEqual(out, [pv['root'], pv['proof_sha256'], pv['proof']])

    def test_chain_segments_match_vectors(self):
        chain = self.vectors['chain']
        for rec, proof in zip(chain['segments'], chain['proofs']):
            out = run('proof', '--n', rec['n'], '--t', rec['t'], '--chi', rec['seed'], '--hex')
            self.assertEqual(out, [rec['root'], rec['proof']['sha256'], proof])

    def test_random_seeds_match_reference(self):
        for i in range(4):
            chi = hashlib.sha256(f'prover random {i}'.encode()).digest()
            n = 6 + i
            root, store = hg.compute('p0', n, chi, keep=True)
            proof = hg.make_proof(n, store, hg.challenges('p0', n, chi, root, 16))
            for tag in ('p0', 'v1'):
                want_root = root if tag == 'p0' else hg.compute('v1', n, chi)[0]
                self.assertEqual(run('root', '--tag', tag, '--n', n, '--chi', chi.hex()), [want_root.hex()])
            out = run('proof', '--n', n, '--t', 16, '--chi', chi.hex(), '--top', n // 3, '--hex')
            self.assertEqual(out, [root.hex(), hashlib.sha256(proof).hexdigest(), proof.hex()])

    def test_sha256_differential_against_hashlib(self):
        count = int(os.environ.get('HOURGLASS_DIFF_COUNT', '200000'))
        want = reference_diff(count, 1)
        for b in self.backends:
            with self.subTest(backend=b):
                self.assertEqual(' '.join(run('sha256-diff', '--count', count, '--seed', 1, '--backend', b)), want)


if __name__ == '__main__':
    unittest.main()
