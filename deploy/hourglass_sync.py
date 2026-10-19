#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Sigelith Hourglass (Klepsydra) - wejscia do ziarna i stemple rekordow (faza 0).

Uruchamiane co minute (systemd: hourglass-sync.timer). Wylacznie biblioteka standardowa;
korzysta z Sigelith jak kazdy klient publicznego API (HOURGLASS.md D16 - prover nie zalezy
od strony, bazy ani sieci; ten skrypt zapisuje mu tylko plik).

1. data/inputs.txt (zapis atomowy):
   - checkpoint: numer i SHA-256 pliku ostatniego checkpointu z /api/proof/checkpoints/latest;
   - btc: blok na glebokosci 3, zgodny w DWOCH niezaleznych zrodlach - ta sama zasada co
     checkpointy dziennika Sigelith; niezgodnosc albo awaria = zostaje poprzedni blok;
   - ptb_offset_us: przesuniecie zegara systemowego wedlug chrony (chronyc tracking) - tylko gdy
     chrony liczy akurat wedlug serwera czasu PTB (ptbtime1-4.ptb.de), inaczej puste.
   Brak ktoregos zrodla nigdy nie zatrzymuje provera - zostaja ostatnie znane wartosci.
2. Stemple: genesis.json i kazdy nowy segments/<j>.json -> POST /api/proof/stamp {"digest"};
   odpowiedz (z kwitem sigelith-receipt-v1) zapisana obok jako <plik>.receipt.json.

    python3 -I hourglass_sync.py --dir /srv/hourglass/data [--api https://sigelith.org]
"""
import argparse
import hashlib
import ipaddress
import json
import os
import re
import socket
import subprocess
import sys
import urllib.request

UA = 'Sigelith Hourglass sync (+https://sigelith.org/spec/)'
TIMEOUT = 10
BTC_SOURCES = (
    ('mempool.space', 'https://mempool.space/api'),
    ('blockstream.info', 'https://blockstream.info/api'),
)
BTC_DEPTH = 3
PTB_SERVERS = ('ptbtime1.ptb.de', 'ptbtime2.ptb.de', 'ptbtime3.ptb.de', 'ptbtime4.ptb.de')
MAX_STAMPS_PER_RUN = 5          # limit publicznego API: 20 stempli na minute
_HEX64 = re.compile(r'^[0-9a-f]{64}$')
_HEIGHT = re.compile(r'^\d{1,9}$')


def _urlopen(req):
    """Jedyny punkt wyjscia do sieci (podmieniany w testach)."""
    return urllib.request.urlopen(req, timeout=TIMEOUT)


def _get_text(url: str) -> str:
    req = urllib.request.Request(url, headers={'User-Agent': UA, 'Accept': 'text/plain'})
    with _urlopen(req) as resp:
        return resp.read(1024).decode('ascii').strip()


def _get_json(url: str):
    req = urllib.request.Request(url, headers={'User-Agent': UA, 'Accept': 'application/json'})
    with _urlopen(req) as resp:
        return json.loads(resp.read(256 * 1024))


def _post_json(url: str, payload: dict):
    data = json.dumps(payload).encode('utf-8')
    req = urllib.request.Request(url, data=data, method='POST',
                                 headers={'User-Agent': UA, 'Content-Type': 'application/json',
                                          'Accept': 'application/json'})
    with _urlopen(req) as resp:
        return json.loads(resp.read(256 * 1024))


def btc_block_at_depth():
    """{"height", "hash"} na glebokosci 3, zgodny w obu zrodlach - albo None."""
    try:
        tips = []
        for _, base in BTC_SOURCES:
            tip = _get_text(f'{base}/blocks/tip/height')
            if not _HEIGHT.match(tip):
                return None
            tips.append(int(tip))
        height = max(tips) - (BTC_DEPTH - 1)
        hashes = set()
        for _, base in BTC_SOURCES:
            h = _get_text(f'{base}/block-height/{height}').lower()
            if not _HEX64.match(h):
                return None
            hashes.add(h)
    except Exception as exc:  # siec, HTTP, kodowanie
        print(f'hourglass-sync: btc niedostepny ({type(exc).__name__})', file=sys.stderr)
        return None
    if len(hashes) != 1:
        print(f'hourglass-sync: zrodla nie zgadzaja sie co do bloku {height}', file=sys.stderr)
        return None
    return {'height': height, 'hash': hashes.pop()}


def latest_checkpoint(api: str):
    """{"n", "sha256"} ostatniego checkpointu - albo None."""
    try:
        data = _get_json(f'{api}/api/proof/checkpoints/latest')
        n, digest = data.get('n'), str(data.get('hash', '')).lower()
        if isinstance(n, int) and not isinstance(n, bool) and n >= 1 and _HEX64.match(digest):
            return {'n': n, 'sha256': digest}
    except Exception as exc:
        print(f'hourglass-sync: checkpoint niedostepny ({type(exc).__name__})', file=sys.stderr)
    return None


def _chrony_tracking():
    """Pola `chronyc -c tracking` (CSV) albo None (podmieniane w testach)."""
    out = subprocess.run(['chronyc', '-c', 'tracking'], capture_output=True, text=True, timeout=5)
    return out.stdout.strip().split(',') if out.returncode == 0 else None


def _resolve(name: str) -> set:
    """Adresy IP nazwy wedlug DNS (podmieniane w testach)."""
    return {info[4][0] for info in socket.getaddrinfo(name, 123, proto=socket.IPPROTO_UDP)}


def ptb_addresses() -> set:
    """Adresy serwerow czasu PTB wedlug DNS; przy awarii DNS zbior moze byc pusty."""
    out = set()
    for name in PTB_SERVERS:
        try:
            out |= {ipaddress.ip_address(a.split('%')[0]) for a in _resolve(name)}
        except (OSError, ValueError):
            pass
    return out


def clock_offset_us():
    """Przesuniecie zegara systemowego wzgledem PTB w us wedlug chrony - albo None.

    Pole "System time" z `chronyc -c tracking`: dodatnie = zegar serwera sie spoznia. Tylko gdy
    zrodlem chrony jest serwer czasu PTB (adres zrodla wsrod adresow ptbtime1-4.ptb.de) - pole
    nazywa sie ptb_offset_us, wiec przy innym zrodle zostaje puste.
    """
    try:
        fields = _chrony_tracking()
        if not fields or len(fields) <= 4:
            return None
        if ipaddress.ip_address(fields[1]) not in ptb_addresses():
            return None
        return int(round(float(fields[4]) * 1_000_000))
    except Exception:
        return None


def read_kv(path: str) -> dict:
    out = {}
    try:
        with open(path, encoding='utf-8') as fh:
            for line in fh:
                line = line.strip()
                if line and not line.startswith('#') and '=' in line:
                    k, v = line.split('=', 1)
                    out[k.strip()] = v.strip()
    except OSError:
        pass
    return out


def write_atomic(path: str, data: bytes) -> None:
    tmp = path + '.tmp'
    with open(tmp, 'wb') as fh:
        fh.write(data)
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, path)


def update_inputs(data_dir: str, api: str) -> dict:
    path = os.path.join(data_dir, 'inputs.txt')
    kv = read_kv(path)
    cp = latest_checkpoint(api)
    if cp:
        kv['checkpoint_n'], kv['checkpoint_sha256'] = str(cp['n']), cp['sha256']
    btc = btc_block_at_depth()
    if btc:
        kv['btc_height'], kv['btc_hash'] = str(btc['height']), btc['hash']
    off = clock_offset_us()
    kv['ptb_offset_us'] = '' if off is None else str(off)
    if {'checkpoint_n', 'checkpoint_sha256', 'btc_height', 'btc_hash'} <= set(kv):
        text = ''.join(f'{k}={kv[k]}\n' for k in sorted(kv))
        write_atomic(path, text.encode('utf-8'))
    else:
        print('hourglass-sync: brak kompletu wejsc - inputs.txt jeszcze nie powstal', file=sys.stderr)
    return kv


def stamp_new_files(data_dir: str, api: str, limit: int = MAX_STAMPS_PER_RUN) -> list:
    """Stempluje genesis.json i rekordy odcinkow, ktore nie maja jeszcze kwitu."""
    files = []
    if os.path.exists(os.path.join(data_dir, 'genesis.json')):
        files.append(os.path.join(data_dir, 'genesis.json'))
    seg_dir = os.path.join(data_dir, 'segments')
    if os.path.isdir(seg_dir):
        files += sorted(os.path.join(seg_dir, f) for f in os.listdir(seg_dir) if re.match(r'^\d{6,}\.json$', f))
    done = []
    for path in files:
        receipt = path[:-len('.json')] + '.receipt.json'
        if os.path.exists(receipt):
            continue
        if len(done) >= limit:
            break
        with open(path, 'rb') as fh:
            digest = hashlib.sha256(fh.read()).hexdigest()
        try:
            resp = _post_json(f'{api}/api/proof/stamp', {'digest': digest})
        except Exception as exc:
            print(f'hourglass-sync: stempel {os.path.basename(path)} nieudany ({type(exc).__name__})', file=sys.stderr)
            break
        if resp.get('digest') != digest:
            print(f'hourglass-sync: zla odpowiedz stempla dla {os.path.basename(path)}', file=sys.stderr)
            break
        write_atomic(receipt, json.dumps(resp, sort_keys=True, separators=(',', ':')).encode('utf-8'))
        done.append(os.path.basename(path))
    return done


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description='Sigelith Hourglass - wejscia do ziarna i stemple')
    ap.add_argument('--dir', required=True, help='katalog danych provera (np. /srv/hourglass/data)')
    ap.add_argument('--api', default='https://sigelith.org')
    a = ap.parse_args(argv)
    os.makedirs(a.dir, exist_ok=True)
    kv = update_inputs(a.dir, a.api.rstrip('/'))
    stamped = stamp_new_files(a.dir, a.api.rstrip('/'))
    print(f"hourglass-sync: checkpoint {kv.get('checkpoint_n', '-')}, blok {kv.get('btc_height', '-')}, "
          f"offset {kv.get('ptb_offset_us') or '-'} us, ostemplowane: {', '.join(stamped) or '-'}")
    return 0


if __name__ == '__main__':
    sys.exit(main())
