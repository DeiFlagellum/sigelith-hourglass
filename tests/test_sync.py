# -*- coding: utf-8 -*-
"""hourglass_sync.py - wejscia do ziarna i stemple, z podmieniona siecia."""
import hashlib
import io
import json
import os
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, 'deploy'))

import hourglass_sync as hs  # noqa: E402

H1 = hashlib.sha256(b'blok').hexdigest()
H2 = hashlib.sha256(b'inny blok').hexdigest()
CP = hashlib.sha256(b'checkpoint').hexdigest()


class FakeNet:
    def __init__(self, routes):
        self.routes = routes
        self.posts = []

    def __call__(self, req):
        url = req.full_url
        if req.get_method() == 'POST':
            body = json.loads(req.data)
            self.posts.append(body['digest'])
            return io.BytesIO(json.dumps({'digest': body['digest'], 'seq': len(self.posts),
                                          'receipt': {'v': 'sigelith-receipt-v1'}}).encode())
        value = self.routes.get(url)
        if value is None or isinstance(value, Exception):
            raise value or OSError('brak trasy ' + url)
        return io.BytesIO(value.encode() if isinstance(value, str) else json.dumps(value).encode())


def routes(hash_mempool=H1, hash_blockstream=H1):
    return {
        'https://mempool.space/api/blocks/tip/height': '972100',
        'https://blockstream.info/api/blocks/tip/height': '972099',
        'https://mempool.space/api/block-height/972098': hash_mempool,
        'https://blockstream.info/api/block-height/972098': hash_blockstream,
        'https://sigelith.org/api/proof/checkpoints/latest': {'n': 29, 'hash': CP, 'kind': 'daily'},
    }


class SyncTests(unittest.TestCase):
    def setUp(self):
        self._orig = hs._urlopen
        self._orig_clock = hs.clock_offset_us
        hs.clock_offset_us = lambda: -217

    def tearDown(self):
        hs._urlopen = self._orig
        hs.clock_offset_us = self._orig_clock

    def test_inputs_from_two_agreeing_sources(self):
        hs._urlopen = FakeNet(routes())
        with tempfile.TemporaryDirectory() as d:
            hs.update_inputs(d, 'https://sigelith.org')
            kv = hs.read_kv(os.path.join(d, 'inputs.txt'))
        self.assertEqual(kv, {'btc_hash': H1, 'btc_height': '972098', 'checkpoint_n': '29',
                              'checkpoint_sha256': CP, 'ptb_offset_us': '-217'})

    def test_disagreeing_sources_keep_the_previous_block(self):
        with tempfile.TemporaryDirectory() as d:
            hs._urlopen = FakeNet(routes())
            hs.update_inputs(d, 'https://sigelith.org')
            hs._urlopen = FakeNet(routes(hash_blockstream=H2))
            hs.update_inputs(d, 'https://sigelith.org')
            kv = hs.read_kv(os.path.join(d, 'inputs.txt'))
        self.assertEqual(kv['btc_hash'], H1)

    def test_nothing_is_written_without_a_complete_set(self):
        r = routes()
        r['https://sigelith.org/api/proof/checkpoints/latest'] = OSError('strona lezy')
        hs._urlopen = FakeNet(r)
        with tempfile.TemporaryDirectory() as d:
            hs.update_inputs(d, 'https://sigelith.org')
            self.assertFalse(os.path.exists(os.path.join(d, 'inputs.txt')))

    def test_stamps_genesis_and_new_records_once(self):
        net = FakeNet(routes())
        hs._urlopen = net
        with tempfile.TemporaryDirectory() as d:
            os.makedirs(os.path.join(d, 'segments'))
            for name, body in (('genesis.json', b'{"g":1}'), ('segments/000001.json', b'{"j":1}'),
                               ('segments/000002.json', b'{"j":2}')):
                with open(os.path.join(d, name), 'wb') as fh:
                    fh.write(body)
            done = hs.stamp_new_files(d, 'https://sigelith.org')
            self.assertEqual(done, ['genesis.json', '000001.json', '000002.json'])
            self.assertEqual(net.posts[0], hashlib.sha256(b'{"g":1}').hexdigest())
            self.assertTrue(os.path.exists(os.path.join(d, 'segments', '000002.receipt.json')))
            self.assertEqual(hs.stamp_new_files(d, 'https://sigelith.org'), [])   # drugi raz nic
            self.assertEqual(len(net.posts), 3)


class PtbOffsetTests(unittest.TestCase):
    """ptb_offset_us tylko wtedy, gdy chrony liczy wedlug serwera czasu PTB."""
    DNS = {'ptbtime1.ptb.de': {'192.53.103.108', '2001:638:610:be01::108'},
           'ptbtime4.ptb.de': {'194.94.95.123', '2001:638:610:cecf::7b'}}

    def setUp(self):
        self._orig = (hs._chrony_tracking, hs._resolve)
        hs._resolve = lambda name: self.DNS.get(name, set())

    def tearDown(self):
        hs._chrony_tracking, hs._resolve = self._orig

    @staticmethod
    def tracking(ref, offset):
        # pierwsze pola `chronyc -c tracking`: Ref ID, zrodlo, stratum, czas odniesienia, System time
        return lambda: ['50544231', ref, '1', '1792386000.123456789', offset, '0.000001', '0.000002']

    def test_offset_only_when_the_source_is_ptb(self):
        hs._chrony_tracking = self.tracking('2001:638:610:be01::108', '-0.000017572')   # odczyt z prod 19.10
        self.assertEqual(hs.clock_offset_us(), -18)
        hs._chrony_tracking = self.tracking('194.94.95.123', '0.000250000')
        self.assertEqual(hs.clock_offset_us(), 250)
        hs._chrony_tracking = self.tracking('162.159.200.1', '0.000001000')              # inne zrodlo
        self.assertIsNone(hs.clock_offset_us())
        hs._chrony_tracking = self.tracking('PPS0', '0.000001000')                       # zegar lokalny
        self.assertIsNone(hs.clock_offset_us())
        hs._chrony_tracking = lambda: None                                               # chrony milczy
        self.assertIsNone(hs.clock_offset_us())

    def test_no_dns_means_no_offset(self):
        def no_dns(name):
            raise OSError('dns')
        hs._resolve = no_dns
        hs._chrony_tracking = self.tracking('192.53.103.108', '0.000003000')
        self.assertIsNone(hs.clock_offset_us())


if __name__ == '__main__':
    unittest.main()
