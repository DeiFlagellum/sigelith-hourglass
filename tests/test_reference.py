# -*- coding: utf-8 -*-
"""Testy implementacji referencyjnej Klepsydry (M0).

    python -I -m unittest discover -s tests -v
"""
import copy
import hashlib
import json
import os
import random
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, 'reference'))

import gen_vectors  # noqa: E402
import hourglass_ref as hg  # noqa: E402

TAG = 'p0'


def chi_for(i: int) -> bytes:
    return hashlib.sha256(f'test chi {i}'.encode()).digest()


class GraphTests(unittest.TestCase):
    def test_stack_order_equals_definition(self):
        # post-order ze stosem (§4) = etykiety wprost z definicji grafu (§2-3)
        for n in range(1, 11):
            with self.subTest(n=n):
                root, store = hg.compute(TAG, n, chi_for(n), keep=True)
                memo = hg.compute_recursive(TAG, n, chi_for(n))
                self.assertEqual(store, memo)
                self.assertEqual(root, memo[(0, 0)])
                self.assertEqual(len(store), hg.node_count(n))

    def test_every_node_has_the_same_input_length(self):
        # §3: dopelnienie do stalej dlugosci - kazde wywolanie kosztuje tyle samo
        for n in (1, 2, 5, 32):
            sizes = set()
            orig = hg._sha256
            try:
                hg._sha256 = lambda data: (sizes.add(len(data)), orig(data))[1]
                if n <= 5:
                    hg.compute(TAG, n, chi_for(0))
                else:
                    hg.label(TAG, n, chi_for(0), n, (1 << n) - 1, [b'\0' * 32] * n)
                    hg.label(TAG, n, chi_for(0), 0, 0, [b'\0' * 32] * 2)
            finally:
                hg._sha256 = orig
            self.assertEqual(sizes, {hg.input_length(TAG, n)}, n)

    def test_subtree_recompute_matches_full_tree(self):
        # tak prover produkcyjny odpowiada na kontrole, trzymajac tylko gorne poziomy
        n = 9
        _, store = hg.compute(TAG, n, chi_for(9), keep=True)
        rnd = random.Random(1)
        for _ in range(25):
            depth = rnd.randint(0, n)
            bits = rnd.randrange(1 << depth)
            siblings = [store[(i, (bits >> (depth - i)) - 1)]
                        for i in range(1, depth + 1) if (bits >> (depth - i)) & 1]
            sub = hg.subtree(TAG, n, chi_for(9), depth, bits, siblings)
            for key, value in sub.items():
                self.assertEqual(store[key], value)
            self.assertEqual(sub[(depth, bits)], store[(depth, bits)])

    def test_tags_separate_domains(self):
        self.assertNotEqual(hg.compute('p0', 4, chi_for(4))[0], hg.compute('v1', 4, chi_for(4))[0])


class ProofTests(unittest.TestCase):
    def _proof(self, n, t, chi):
        root, store = hg.compute(TAG, n, chi, keep=True)
        return root, hg.make_proof(n, store, hg.challenges(TAG, n, chi, root, t))

    def test_honest_proofs_verify(self):
        for n in range(1, 10):
            for t in (1, 8, 32):
                with self.subTest(n=n, t=t):
                    root, proof = self._proof(n, t, chi_for(n))
                    self.assertEqual(len(proof), t * n * 32)
                    self.assertTrue(hg.verify_segment(TAG, n, t, chi_for(n), root, proof))

    def test_proof_for_t_is_prefix_of_proof_for_larger_t(self):
        root, small = self._proof(7, 16, chi_for(7))
        _, big = self._proof(7, 64, chi_for(7))
        self.assertEqual(big[:len(small)], small)
        self.assertTrue(hg.verify_segment(TAG, 7, 16, chi_for(7), root, big[:len(small)]))

    def test_tampering_is_rejected(self):
        n, t = 6, 8
        chi = chi_for(6)
        root, proof = self._proof(n, t, chi)
        rnd = random.Random(2)
        for _ in range(40):
            pos = rnd.randrange(len(proof))
            bad = bytearray(proof)
            bad[pos] ^= 1 << rnd.randrange(8)
            self.assertFalse(hg.verify_segment(TAG, n, t, chi, root, bytes(bad)))
        self.assertFalse(hg.verify_segment(TAG, n, t, chi_for(99), root, proof))       # inne ziarno
        self.assertFalse(hg.verify_segment(TAG, n, t, chi, hashlib.sha256(b'x').digest(), proof))
        self.assertFalse(hg.verify_segment(TAG, n, t, chi, root, proof[:-32]))       # za krotki
        self.assertFalse(hg.verify_segment('v1', n, t, chi, root, proof))             # inna domena
        swapped = proof[n * 32:2 * n * 32] + proof[:n * 32] + proof[2 * n * 32:]
        if swapped != proof:
            self.assertFalse(hg.verify_segment(TAG, n, t, chi, root, swapped))      # zla kolejnosc kontroli


class SoundnessDemoTests(unittest.TestCase):
    """Demonstracje do notatki nr 1: czesciowa praca przechodzi z prawdopodobienstwem
    ok. (1 - alfa)^t, a losowanie korzenia jest tanie - stad lambda z zapasem (spec §6)."""

    @staticmethod
    def _cheat(n, chi, honest_leaves, salt=b''):
        # uczciwe liscie 0..honest_leaves-1, reszta to smieci; wezly wewnetrzne spojne
        store = {}
        stack = []
        for u in range(1 << n):
            if u < honest_leaves:
                lab = hg.label(TAG, n, chi, n, u, [e[2] for e in stack])
            else:
                lab = hashlib.sha256(b'junk' + salt + u.to_bytes(8, 'big')).digest()
            store[(n, u)] = lab
            stack.append((n, u, lab))
            while len(stack) >= 2 and stack[-1][0] == stack[-2][0]:
                d, _, right = stack.pop()
                _, lb, left = stack.pop()
                plab = hg.label(TAG, n, chi, d - 1, lb >> 1, [left, right])
                store[(d - 1, lb >> 1)] = plab
                stack.append((d - 1, lb >> 1, plab))
        return stack[0][2], store

    def test_half_the_work_passes_about_2_to_minus_t(self):
        n, t, trials = 8, 3, 256
        accepted = 0
        for i in range(trials):
            chi = chi_for(1000 + i)
            root, store = self._cheat(n, chi, 1 << (n - 1))
            proof = hg.make_proof(n, store, hg.challenges(TAG, n, chi, root, t))
            accepted += hg.verify_segment(TAG, n, t, chi, root, proof)
        # oczekiwane 256 / 8 = 32; szerokie granice, wynik i tak jest deterministyczny
        self.assertTrue(12 <= accepted <= 60, accepted)

    def test_grinding_the_root_is_cheap(self):
        # 3/4 uczciwej pracy, t = 4: jedna proba przechodzi z p = 0,316. Nowa proba to
        # tylko inne smieci; prawdziwy oszust zmienilby jeden lisc na koncu i przeliczyl
        # sama sciezke (~n haszy), rownolegle - po kilku probach sukces (spec §6)
        n, t = 8, 4
        chi = chi_for(5)
        for attempt in range(60):
            root, store = self._cheat(n, chi, 3 << (n - 2), salt=attempt.to_bytes(4, 'big'))
            proof = hg.make_proof(n, store, hg.challenges(TAG, n, chi, root, t))
            if hg.verify_segment(TAG, n, t, chi, root, proof):
                break
        else:
            self.fail('brak sukcesu w 60 probach - demonstracja nie dziala')
        self.assertLess(attempt, 60)


class ParameterTests(unittest.TestCase):
    def test_claim_permille_is_exact(self):
        for t, lam in ((1, 1), (8, 4), (64, 40), (128, 40), (128, 100), (256, 100), (1024, 256)):
            p = hg.claim_permille(t, lam)
            self.assertLessEqual((p ** t) << lam, 1000 ** t)
            if p < 1000:
                self.assertGreater(((p + 1) ** t) << lam, 1000 ** t)
        self.assertEqual(hg.claim_permille(64, 40), 648)
        self.assertEqual(hg.claim_permille(256, 100), 762)

    def test_min_elapsed_integer_math(self):
        recs = [{'claim_permille': 762, 'n': 32}] * 24       # doba odcinkow n = 32
        s = hg.min_elapsed_seconds(recs, 20, 2_000_000)
        self.assertEqual(s, (762 * ((1 << 33) - 1) * 24) // (1000 * 20 * 2_000_000))

    def test_canonical_json_rules(self):
        self.assertEqual(hg.canonical_json({'b': 1, 'a': [True, None, 'x']}), b'{"a":[true,null,"x"],"b":1}')
        for bad in ({'a': 1.5}, {'a': 2 ** 53}, {'a': 'x\ny'}, {'ą': 1}):
            with self.assertRaises(hg.HourglassError):
                hg.canonical_json(bad)


class ChainTests(unittest.TestCase):
    def setUp(self):
        self.chain = gen_vectors.example_chain()
        self.proofs = [bytes.fromhex(p) for p in self.chain['proofs']]

    def test_example_chain_verifies(self):
        last = hg.verify_chain(TAG, self.chain['genesis'], self.chain['segments'], self.proofs)
        self.assertEqual(last.hex(), self.chain['segments'][-1]['root'])

    def test_changed_inputs_utc_breaks_the_seed(self):
        recs = copy.deepcopy(self.chain['segments'])
        recs[0]['inputs']['utc'] = '2026-10-19T00:00:00.500000Z'
        with self.assertRaisesRegex(hg.HourglassError, 'ziarno'):
            hg.verify_chain(TAG, self.chain['genesis'], recs, self.proofs)

    def test_rejects_broken_continuity_and_bad_fields(self):
        recs = copy.deepcopy(self.chain['segments'])
        recs[1]['prev_root'] = '00' * 32
        with self.assertRaises(hg.HourglassError):
            hg.verify_chain(TAG, self.chain['genesis'], recs, self.proofs)
        recs = copy.deepcopy(self.chain['segments'])
        recs[0]['claim_permille'] = 999
        with self.assertRaisesRegex(hg.HourglassError, 'claim_permille'):
            hg.verify_chain(TAG, self.chain['genesis'], recs, self.proofs)
        recs = copy.deepcopy(self.chain['segments'])
        recs[1]['coverage_permille'] = 1000
        with self.assertRaisesRegex(hg.HourglassError, 'coverage'):
            hg.verify_chain(TAG, self.chain['genesis'], recs, self.proofs)
        with self.assertRaises(hg.HourglassError):
            hg.verify_chain(TAG, self.chain['genesis'], list(reversed(self.chain['segments'])), self.proofs)

    def test_fork_is_detected(self):
        recs = self.chain['segments']
        other = copy.deepcopy(recs)
        other[1]['root'] = 'ab' * 32
        hg.find_forks(recs, copy.deepcopy(recs))
        with self.assertRaises(hg.ForkError):
            hg.find_forks(recs, other)

    def test_absorbing_segment(self):
        recs = self.chain['segments']
        cp = recs[1]['inputs']['checkpoint']['sha256']
        self.assertEqual(hg.absorbing_segment(recs, cp), 2)
        self.assertEqual(hg.absorbing_segment(recs, '00' * 32), 0)

    def test_cli_verifies_a_published_directory(self):
        import contextlib
        import io
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            os.makedirs(os.path.join(tmp, 'segments'))
            with open(os.path.join(tmp, 'genesis.json'), 'w', encoding='utf-8') as fh:
                json.dump(self.chain['genesis'], fh)
            for rec, proof in zip(self.chain['segments'], self.proofs):
                with open(os.path.join(tmp, 'segments', f"{rec['j']:06d}.json"), 'w', encoding='utf-8') as fh:
                    json.dump(rec, fh)
                with open(os.path.join(tmp, 'segments', rec['proof']['file']), 'wb') as fh:
                    fh.write(proof)
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                code = hg.main(['hourglass_ref.py', 'verify', tmp])
        self.assertEqual(code, 0, out.getvalue())
        self.assertIn('OK: genesis + 2 segment(s) verified', out.getvalue())


class VectorFileTests(unittest.TestCase):
    def test_vectors_file_matches_reference(self):
        with open(gen_vectors.OUT, encoding='utf-8') as fh:
            stored = json.load(fh)
        self.assertEqual(stored, json.loads(json.dumps(gen_vectors.build())))


if __name__ == '__main__':
    unittest.main()
