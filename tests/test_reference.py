# -*- coding: utf-8 -*-
"""Testy implementacji referencyjnej Klepsydry (M0).

    python -I -m unittest discover -s tests -v
"""
import copy
import hashlib
import importlib.util
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


class Ed25519Tests(unittest.TestCase):
    """Weryfikacja podpisow v1 bez bibliotek spoza stdlib (§8): wektory z RFC 8032, rozdzial 7.1."""
    RFC8032 = (
        ('9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60',
         'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a', '',
         'e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd2'
         '5bf5f0595bbe24655141438e7a100b'),
        ('4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb',
         '3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c', '72',
         '92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c'
         '387b2eaeb4302aeeb00d291612bb0c00'),
        ('c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7',
         'fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025', 'af82',
         '6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc659'
         '4a7c15e9716ed28dc027beceea1ec40a'),
    )

    def test_rfc8032_vectors(self):
        for secret, public, msg, sig in self.RFC8032:
            secret, public, msg, sig = map(bytes.fromhex, (secret, public, msg, sig))
            self.assertEqual(hg.ed25519_public_key(secret), public)
            self.assertEqual(hg._ed25519_sign(secret, msg), sig)
            self.assertTrue(hg.ed25519_verify(public, msg, sig))
            self.assertFalse(hg.ed25519_verify(public, msg + b'!', sig))

    def test_rejects_malformed_signatures(self):
        secret, public, msg, sig = map(bytes.fromhex, self.RFC8032[1])
        s = int.from_bytes(sig[32:], 'little') + hg._ED_L          # S + L: ta sama reszta, ale S >= L
        self.assertFalse(hg.ed25519_verify(public, msg, sig[:32] + s.to_bytes(32, 'little')))
        self.assertFalse(hg.ed25519_verify(public, msg, sig[:-1]))
        self.assertFalse(hg.ed25519_verify(public[:-1], msg, sig))
        self.assertFalse(hg.ed25519_verify(b'\xff' * 32, msg, sig))      # y >= p: niepoprawny punkt
        bad = bytearray(sig)
        bad[0] ^= 1
        self.assertFalse(hg.ed25519_verify(public, msg, bytes(bad)))

    @unittest.skipUnless(importlib.util.find_spec('cryptography'), 'brak pakietu cryptography')
    def test_agrees_with_an_independent_library(self):
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        rnd = random.Random(8)
        for _ in range(12):
            secret, msg = rnd.randbytes(32), rnd.randbytes(rnd.randrange(300))
            lib = Ed25519PrivateKey.from_private_bytes(secret)
            public = lib.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
            self.assertEqual(hg.ed25519_public_key(secret), public)
            self.assertTrue(hg.ed25519_verify(public, msg, lib.sign(msg)))


class V1Tests(unittest.TestCase):
    """v1 (§7-10): operator w genesis, predkosc odniesienia, podpis rekordu, przedrostki dowodu."""

    def setUp(self):
        self.chain = gen_vectors.example_chain_v1()
        self.proofs = [bytes.fromhex(p) for p in self.chain['proofs']]
        self.key = self.chain['test_key']['public']

    def verify(self, records=None, proofs=None, keys=None, genesis=None):
        return hg.verify_chain('v1', genesis or self.chain['genesis'], records or self.chain['segments'],
                               proofs or self.proofs, keys=keys)

    def test_signed_chain_verifies_with_the_key_history(self):
        self.assertEqual(self.verify(keys=[self.key]).hex(), self.chain['segments'][-1]['root'])
        self.assertEqual(hg.min_elapsed_seconds_v1(self.chain['segments']), 4)

    def test_signature_errors(self):
        with self.assertRaisesRegex(hg.HourglassError, 'spoza historii'):
            self.verify(keys=['AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA='])
        recs = copy.deepcopy(self.chain['segments'])
        recs[0]['k_assumed'] = 2                       # zmiana po podpisie
        with self.assertRaisesRegex(hg.HourglassError, 'podpis NIE pasuje'):
            self.verify(recs, keys=[self.key])
        recs = copy.deepcopy(self.chain['segments'])
        recs[1]['sig'] = recs[0]['sig']                # podpis innego rekordu
        with self.assertRaisesRegex(hg.HourglassError, 'podpis NIE pasuje'):
            self.verify(recs, keys=[self.key])
        recs = copy.deepcopy(self.chain['segments'])
        recs[0]['key'] = recs[0]['key'].rstrip('=')    # base64 niekanoniczne
        with self.assertRaisesRegex(hg.HourglassError, 'key'):
            self.verify(recs)

    def test_prover_output_is_unsigned_and_checked_before_signing(self):
        rec = self.chain['unsigned_1']
        self.assertNotIn('sig', rec)
        phi0 = bytes.fromhex(self.chain['genesis_root'])
        self.assertEqual(hg.check_segment('v1', rec, self.proofs[0], phi0, self.chain['genesis']['utc'], signed=False), 8)
        with self.assertRaisesRegex(hg.HourglassError, 'zestaw pol'):
            hg.check_segment('v1', rec, self.proofs[0], phi0, self.chain['genesis']['utc'])
        signed = hg.sign_record_for_tests(rec, bytes.fromhex(self.chain['test_key']['secret']))
        self.assertEqual(signed, self.chain['segments'][0])
        self.assertTrue(hg.signing_message(signed).startswith(b'sigelith-hourglass-segment-v1|{"claim_permille"'))

    def test_signature_domain_is_disjoint_from_other_sigelith_domains(self):
        others = ('sigelith-receipt-v1|', 'beattime-proof-v1|', 'beattime-checkpoint-v1|', 'sigelith-cosign-v1|',
                  'sigelith-hourglass-v1|', 'sigelith-hourglass-p0|')
        for other in others:
            self.assertFalse(hg.SIG_DOMAIN.startswith(other) or other.startswith(hg.SIG_DOMAIN), other)

    def test_genesis_operator(self):
        g = self.chain['genesis']
        other = dict(g, operator='operator-b.example')
        self.assertNotEqual(hg.genesis_root('v1', g), hg.genesis_root('v1', other))   # dwa zegary, dwa poczatki
        for bad in ('Example.org', '-example.org', 'example.org.', 'a' * 65, '', 'przykład.pl'):
            with self.subTest(operator=bad), self.assertRaisesRegex(hg.HourglassError, 'operator'):
                hg.genesis_root('v1', dict(g, operator=bad))
        with self.assertRaisesRegex(hg.HourglassError, 'zestaw pol'):
            hg.genesis_root('v1', {k: v for k, v in g.items() if k != 'operator'})
        with self.assertRaisesRegex(hg.HourglassError, 'zestaw pol'):
            hg.genesis_root('p0', g)

    def test_reference_speed_and_own_speed(self):
        rec = self.chain['segments'][0]                # nodes_per_s_max 8 < s_ref 10
        self.assertEqual(hg.segment_work_ms(rec), 707 * 31 // 10)
        faster = dict(rec, speed=dict(rec['speed'], nodes_per_s_max=25))
        self.assertEqual(hg.segment_work_ms(faster), 707 * 31 // 25)
        self.assertEqual(self.chain['elapsed']['work_ms'], [2191, 1826])
        # v1 przy parametrach produkcyjnych: odcinek n = 32 przy s_ref = 1 308 141 i k = 20
        prod = {'n': 32, 't': 256, 'lambda': 100, 'k_assumed': 20, 's_ref_nodes_per_s': 1_308_141,
                'speed': {'nodes_per_s_max': 1_250_000}}
        self.assertEqual(hg.segment_work_ms(prod), 762 * ((1 << 33) - 1) // (20 * 1_308_141))
        self.assertEqual(hg.segment_work_ms(prod) // 1000, 250)

    def test_one_check_prefix_keeps_the_order_and_counts_its_own_claim(self):
        prefix = [self.proofs[0], self.proofs[1][:4 * 32]]
        checked = hg.verify_range('v1', self.chain['segments'], prefix, keys=[self.key])
        self.assertEqual(checked, [8, 1])
        self.assertEqual(hg.min_elapsed_seconds_v1(self.chain['segments'], checked), 2)
        # przy lambda = 100 kontrole 1..10 nie gwarantuja zadnej czesci pracy, 11 juz tak
        self.assertEqual([hg.claim_permille(t, 100) for t in (1, 10, 11)][:2], [0, 0])
        self.assertGreater(hg.claim_permille(11, 100), 0)
        # odcinek bez zadnej kontroli zrywa ciag - odrzucony
        with self.assertRaisesRegex(hg.HourglassError, 'od 1 do t - 1'):
            hg.verify_range('v1', self.chain['segments'], [self.proofs[0], b''])
        with self.assertRaisesRegex(hg.HourglassError, 'od 1 do t - 1'):
            hg.verify_range('v1', self.chain['segments'], [self.proofs[0], self.proofs[1][:100]])
        bad = bytearray(prefix[1])
        bad[5] ^= 1
        with self.assertRaisesRegex(hg.HourglassError, 'NIE przechodzi'):
            hg.verify_range('v1', self.chain['segments'], [self.proofs[0], bytes(bad)])
        # pelny ciag od genesis przyjmuje tylko pelne dowody
        with self.assertRaisesRegex(hg.HourglassError, 'bajtow zamiast'):
            self.verify(proofs=prefix)

    def test_range_needs_continuous_links(self):
        recs = copy.deepcopy(self.chain['segments'])
        recs[1]['prev_root'] = '00' * 32
        with self.assertRaises(hg.HourglassError):
            hg.verify_range('v1', recs, self.proofs)
        with self.assertRaisesRegex(hg.HourglassError, 'ciaglosci'):
            hg.verify_range('v1', list(reversed(self.chain['segments'])), list(reversed(self.proofs)))
        self.assertEqual(hg.verify_range('v1', self.chain['segments'][1:], self.proofs[1:]), [8])  # od odcinka i = 2

    def _write(self, tmp, genesis=True, proofs=None):
        os.makedirs(os.path.join(tmp, 'segments'))
        if genesis:
            with open(os.path.join(tmp, 'genesis.json'), 'wb') as fh:
                fh.write(hg.canonical_json(self.chain['genesis']))
        for rec, proof in zip(self.chain['segments'], proofs or self.proofs):
            with open(os.path.join(tmp, 'segments', f"{rec['j']:06d}.json"), 'wb') as fh:
                fh.write(hg.canonical_json(rec))
            with open(os.path.join(tmp, 'segments', rec['proof']['file']), 'wb') as fh:
                fh.write(proof)

    def _cli(self, *args):
        import contextlib
        import io
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = hg.main(['hourglass_ref.py', *args])
        return code, out.getvalue()

    def test_cli_verify_and_age(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            self._write(tmp)
            code, out = self._cli('verify', tmp, '--key', self.key)
            self.assertEqual(code, 0, out)
            self.assertIn('OK: genesis + 2 segment(s) verified (v1, operator example.org)', out)
            self.assertIn('2 record signature(s) verified', out)
            self.assertIn('At least 4 s', out)
            self.assertIn('1 segment(s) faster than s_ref', out)
            code, out = self._cli('verify', tmp)
            self.assertEqual(code, 0, out)
            self.assertIn('signatures NOT checked', out)
            code, out = self._cli('verify', tmp, '--key', 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=')
            self.assertEqual(code, 1, out)
            self.assertIn('REJECTED', out)
        with tempfile.TemporaryDirectory() as tmp:
            self._write(tmp, genesis=False, proofs=[self.proofs[0], self.proofs[1][:4 * 32]])
            code, out = self._cli('age', tmp, '--key', self.key)
            self.assertEqual(code, 0, out)
            self.assertIn('OK: segments 1..2 verified (v1): 1 with the full proof, 1 with a proof prefix', out)
            self.assertIn('Sigelith checkpoint 26', out)
            self.assertIn('At least 2 s', out)

    def test_cli_refuses_a_proof_file_outside_the_directory(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            self._write(tmp)
            rec = dict(self.chain['segments'][0], proof={'file': '../genesis.json', 'sha256': '00' * 32})
            with open(os.path.join(tmp, 'segments', '000001.json'), 'wb') as fh:
                fh.write(hg.canonical_json(rec))
            code, out = self._cli('verify', tmp)
            self.assertEqual(code, 1, out)
            self.assertIn('proof.file', out)


class VectorFileTests(unittest.TestCase):
    def test_vectors_file_matches_reference(self):
        with open(gen_vectors.OUT, encoding='utf-8') as fh:
            stored = json.load(fh)
        self.assertEqual(stored, json.loads(json.dumps(gen_vectors.build())))


if __name__ == '__main__':
    unittest.main()
