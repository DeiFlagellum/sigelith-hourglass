# -*- coding: utf-8 -*-
"""Prover w petli pracy: genesis, odcinki, twarde przerwanie w polowie odcinka (kill -9),
wznowienie - i caly ciag sprawdzony niezaleznym weryfikatorem wzorcowym (HOURGLASS.md D7, D16).

    cargo build --release --manifest-path prover/Cargo.toml
    python -I -m unittest discover -s tests -k run -v
"""
import contextlib
import hashlib
import io
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BIN = os.environ.get('HOURGLASS_BIN') or os.path.join(
    ROOT, 'prover', 'target', 'release', 'hourglass' + ('.exe' if os.name == 'nt' else ''))
sys.path.insert(0, os.path.join(ROOT, 'reference'))

import hourglass_ref as hg  # noqa: E402

N, T, LAMBDA = 21, 16, 4   # parametry TESTOWE: odcinek ok. 1-2 s


def write_inputs(path, height, checkpoint_n):
    with open(path, 'w', encoding='utf-8') as fh:
        fh.write(f'btc_height={height}\n')
        fh.write(f'btc_hash={hashlib.sha256(f"blok {height}".encode()).hexdigest()}\n')
        fh.write(f'checkpoint_n={checkpoint_n}\n')
        fh.write(f'checkpoint_sha256={hashlib.sha256(f"checkpoint {checkpoint_n}".encode()).hexdigest()}\n')
        fh.write('ptb_offset_us=-217\n')


def state(path):
    out = {}
    try:
        with open(os.path.join(path, 'state.txt'), encoding='utf-8') as fh:
            for line in fh:
                if '=' in line:
                    k, v = line.rstrip('\n').split('=', 1)
                    out[k] = v
    except OSError:
        pass
    return out


@unittest.skipUnless(os.path.exists(BIN), 'brak provera - zbuduj: cargo build --release w prover/')
class RunLoopTests(unittest.TestCase):
    def test_kill_and_resume_then_reference_verifies_the_chain(self):
        with tempfile.TemporaryDirectory() as d:
            write_inputs(os.path.join(d, 'inputs.txt'), 972100, 30)
            subprocess.run([BIN, 'genesis', '--dir', d, '--n', str(N), '--t', str(T), '--lambda', str(LAMBDA),
                            '--k', '20', '--bench-seconds', '0.5'], check=True, capture_output=True)
            # genesis nie da sie nadpisac
            again = subprocess.run([BIN, 'genesis', '--dir', d, '--n', str(N), '--t', str(T), '--lambda', '4',
                                    '--k', '20'], capture_output=True, text=True)
            self.assertNotEqual(again.returncode, 0)
            self.assertIn('nigdy nie startuje od zera', again.stderr)

            run = [BIN, 'run', '--dir', d, '--save-every-ms', '100', '--max-segments', '4']
            proc = subprocess.Popen(run, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
            self.addCleanup(proc.stderr.close)
            # czekamy na srodek odcinka 2, zmieniamy wejscia i zabijamy proces bez ostrzezenia
            # zapas na wolna albo obciazona maszyne (CI, inne procesy): odcinek trwa wtedy dluzej, nie krocej
            deadline = time.time() + 300
            killed_in = None
            while time.time() < deadline:
                if proc.poll() is not None:
                    self.fail(f'prover zakonczyl sie sam: {proc.stderr.read().decode(errors="replace")}')
                st = state(d)
                if st.get('j') == '2' and st.get('active') == '1' and int(st.get('next_leaf', '0')) > 0:
                    write_inputs(os.path.join(d, 'inputs.txt'), 972101, 31)
                    proc.kill()
                    proc.wait()
                    killed_in = st
                    break
                time.sleep(0.02)
            self.assertIsNotNone(killed_in, 'nie zlapalismy srodka odcinka 2')
            # wznowienie: ten sam odcinek, to samo ziarno (wejscia zmienione w miedzyczasie nie wchodza)
            done = subprocess.run(run, capture_output=True, text=True, timeout=600)
            self.assertEqual(done.returncode, 0, done.stderr)

            # kwity stempli leza obok rekordow (hourglass_sync.py) - weryfikator ma je pomijac
            with open(os.path.join(d, 'segments', '000001.receipt.json'), 'w', encoding='utf-8') as fh:
                fh.write('{"digest":"test"}')
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                code = hg.main(['hourglass_ref.py', 'verify', d])
            self.assertEqual(code, 0, out.getvalue())
            self.assertIn('OK: genesis + 4 segment(s) verified', out.getvalue())

            with open(os.path.join(d, 'segments', '000002.json'), encoding='utf-8') as fh:
                seg2 = json.load(fh)
            self.assertEqual(seg2['seed'], killed_in['seed'])
            self.assertEqual(seg2['inputs']['btc']['height'], 972100)        # ziarno sprzed przerwania
            self.assertEqual([g['reason'] for g in seg2['gaps']], ['restart'])
            self.assertLess(seg2['coverage_permille'], 1000, json.dumps(
                {k: seg2[k] for k in ('inputs', 'utc_end', 'gaps', 'speed', 'coverage_permille')}, indent=1))
            with open(os.path.join(d, 'segments', '000003.json'), encoding='utf-8') as fh:
                seg3 = json.load(fh)
            self.assertEqual(seg3['inputs']['btc']['height'], 972101)        # nowe wejscia w nowym odcinku
            self.assertEqual(seg3['gaps'], [])
            self.assertEqual(seg3['ptb_offset_us'], -217)
            # plik rekordu = kanoniczny JSON (to jego skrot trafi do stempla)
            with open(os.path.join(d, 'segments', '000003.json'), 'rb') as fh:
                raw = fh.read()
            self.assertEqual(raw, hg.canonical_json(json.loads(raw)))
            with open(os.path.join(d, 'genesis.json'), 'rb') as fh:
                raw = fh.read()
            self.assertEqual(raw, hg.canonical_json(json.loads(raw)))
            # po skonczeniu nie zostaja pliki robocze
            self.assertEqual(sorted(os.listdir(os.path.join(d, 'work'))), [])
            self.assertTrue(any(f.startswith('metrics-') for f in os.listdir(os.path.join(d, 'metrics'))))

    def test_v1_genesis_and_records_then_signed_chain_verifies(self):
        """v1 (SPEC.md §7-8): genesis z operatorem i predkoscia odniesienia, rekordy bez klucza
        i podpisu (prover nigdy nie ma klucza); po podpisie kluczem testowym ciag przechodzi weryfikator."""
        n = 14
        with tempfile.TemporaryDirectory() as d:
            write_inputs(os.path.join(d, 'inputs.txt'), 972200, 40)
            base = [BIN, 'genesis', '--dir', d, '--n', str(n), '--t', str(T), '--lambda', str(LAMBDA), '--k', '20',
                    '--bench-seconds', '0.2', '--tag', 'v1']
            for extra, why in (([], '--operator'), (['--operator', 'example.org'], '--s-ref'),
                               (['--operator', 'Example.org', '--s-ref', '1000'], 'operator')):
                bad = subprocess.run(base + extra, capture_output=True, text=True)
                self.assertNotEqual(bad.returncode, 0)
                self.assertIn(why, bad.stderr)
                self.assertFalse(os.path.exists(os.path.join(d, 'genesis.json')))
            subprocess.run(base + ['--operator', 'example.org', '--s-ref', '1308141'], check=True, capture_output=True)
            done = subprocess.run([BIN, 'run', '--dir', d, '--max-segments', '2'], capture_output=True, text=True,
                                  timeout=600)
            self.assertEqual(done.returncode, 0, done.stderr)

            with open(os.path.join(d, 'genesis.json'), 'rb') as fh:
                raw = fh.read()
            genesis = json.loads(raw)
            self.assertEqual(raw, hg.canonical_json(genesis))
            self.assertEqual((genesis['v'], genesis['operator'], genesis['s_ref_nodes_per_s']),
                             ('sigelith-hourglass-genesis-v1', 'example.org', 1308141))
            self.assertNotIn('s_self_nodes_per_s', genesis)
            records, proofs = [], []
            for j in (1, 2):
                with open(os.path.join(d, 'segments', f'{j:06d}.json'), 'rb') as fh:
                    raw = fh.read()
                rec = json.loads(raw)
                self.assertEqual(raw, hg.canonical_json(rec))
                self.assertEqual(set(rec), hg.UNSIGNED_KEYS_V1)          # bez key i sig
                self.assertEqual(rec['s_ref_nodes_per_s'], 1308141)
                with open(os.path.join(d, 'segments', rec['proof']['file']), 'rb') as fh:
                    proofs.append(fh.read())
                records.append(rec)
            hg.verify_chain('v1', genesis, records, proofs, signed=False)   # tak sprawdza publikujacy

            secret = hashlib.sha256(b'sigelith-hourglass test key').digest()
            for rec in records:
                with open(os.path.join(d, 'segments', f"{rec['j']:06d}.json"), 'wb') as fh:
                    fh.write(hg.canonical_json(hg.sign_record_for_tests(rec, secret)))
            key = hg.sign_record_for_tests(records[0], secret)['key']
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                code = hg.main(['hourglass_ref.py', 'verify', d, '--key', key])
            self.assertEqual(code, 0, out.getvalue())
            self.assertIn('OK: genesis + 2 segment(s) verified (v1, operator example.org)', out.getvalue())
            self.assertIn('2 record signature(s) verified', out.getvalue())


if __name__ == '__main__':
    unittest.main()
