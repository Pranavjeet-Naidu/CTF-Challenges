"""
Solver for the "Underhanded Stream Challenge" (assumptions explained below)

How this solver works (assumptions):
- The solver assumes the server reuses the same keystream across requests (i.e. the per-request
  nonce is *not* actually changing the keystream, or the server has a fixed nonce). The current
  server implementation we saved earlier **chooses a random nonce per-request**, which makes the
  intended exploit impossible. If you want the solver to work against that server, either make
  the server use a fixed nonce or remove nonce from the seeding.

- Given keystream reuse, the subtle offset bug in the encryption function (for len>32 the server
  advances the keystream by `offset = len(msg) % 16` before XORing) lets us recover long runs
  of the keystream by sending chosen plaintexts of zeros at many lengths. For a zero plaintext of
  length L>32 we observe: ciphertext[i] = ks[offset + i] for i in [0..L-1]. That lets us populate
  ks[offset : offset+L]. Doing this with many L covers a large contiguous prefix of ks.

- After we collect enough keystream bytes, we submit a large chosen payload to `/encrypt_secret`
  so that the server appends the secret (flag) after our payload. We compute the offset for that
  request from the returned ciphertext length, and then recover the secret bytes by XORing the
  ciphertext bytes of the flag with the corresponding recovered keystream bytes.

Usage:
  pip install requests
  python3 underhanded_stream_solver.py --host http://127.0.0.1:5000

If you want, I can also modify the server to use a fixed nonce so this solver works immediately.

"""

import requests
import binascii
import argparse
from collections import defaultdict


def hexpost(session, url, payload_bytes):
    obj = {"data": binascii.hexlify(payload_bytes).decode()}
    r = session.post(url, json=obj)
    r.raise_for_status()
    return r.json()


def collect_keystream(session, base_url, max_len=220):
    """Collect keystream bytes by requesting zero plaintexts of many lengths.
    Returns a dict mapping ks_index -> byte value (int).
    """
    ks = {}
    for L in range(33, max_len+1):
        payload = b"\x00" * L
        resp = hexpost(session, base_url + '/encrypt', payload)
        ct = binascii.unhexlify(resp['ciphertext'])
        # server's encrypt uses offset = L % 16 when L>32
        offset = L % 16
        for i, cbyte in enumerate(ct):
            ks_idx = offset + i
            # prefer earlier writes but it's the same value if ks reused properly
            if ks_idx not in ks:
                ks[ks_idx] = cbyte
    return ks


def recover_flag(session, base_url, ks, payload_len=100):
    # send a chosen payload of 'A's of length payload_len
    payload = b'A' * payload_len
    resp = hexpost(session, base_url + '/encrypt_secret', payload)
    ct = binascii.unhexlify(resp['ciphertext'])
    total_len = len(ct)
    # offset used for this encryption
    offset = total_len % 16
    flag_len = total_len - payload_len
    if flag_len <= 0:
        raise RuntimeError('payload_len too large or server behaved unexpectedly')

    # check if we have enough ks bytes
    needed_indices = [offset + payload_len + i for i in range(flag_len)]
    missing = [i for i in needed_indices if i not in ks]
    if missing:
        raise RuntimeError(f"Missing keystream bytes for indices: {missing[:10]} (need {len(missing)})")

    flag_bytes = bytearray(flag_len)
    for i in range(flag_len):
        pos = payload_len + i
        ks_idx = offset + pos
        flag_bytes[i] = ct[pos] ^ ks[ks_idx]
    return bytes(flag_bytes)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--host', default='http://127.0.0.1:5000')
    parser.add_argument('--collect-max', type=int, default=400)
    parser.add_argument('--payload-len', type=int, default=100)
    args = parser.parse_args()

    s = requests.Session()
    print('Collecting keystream... (this assumes the server reuses the same keystream across requests)')
    ks = collect_keystream(s, args.host, max_len=args.collect_max)
    print(f'Collected {len(ks)} keystream bytes (highest index {max(ks.keys()) if ks else -1})')

    print('Requesting encrypt_secret to leak flag...')
    try:
        flag = recover_flag(s, args.host, ks, payload_len=args.payload_len)
    except Exception as e:
        print('Failed to recover flag:', e)
        return
    print('Recovered flag bytes:')
    try:
        print(flag.decode())
    except Exception:
        print(binascii.hexlify(flag))

if __name__ == '__main__':
    main()
