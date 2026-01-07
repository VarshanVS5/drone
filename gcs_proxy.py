import argparse
import socket
import threading
import time
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

NONCE_LEN = 12
TS_LEN = 8

class SecureProxy:
    def __init__(self, key, plain_listen, enc_remote_addr, enc_remote_port, enc_listen, forward_host, forward_port, ts_skew=3):
        self.key = key
        self.aesgcm = AESGCM(key)
        self.plain_listen = plain_listen
        self.enc_remote = (enc_remote_addr, enc_remote_port)
        self.enc_listen = enc_listen
        self.forward = (forward_host, forward_port)
        self.ts_skew = ts_skew
        self.seen_nonces = set()

    def start(self):
        t1 = threading.Thread(target=self._plain_listener, daemon=True)
        t2 = threading.Thread(target=self._enc_listener, daemon=True)
        t1.start(); t2.start()
        print('GCS proxy running. Plain->Enc port:', self.plain_listen, 'Enc listen:', self.enc_listen)
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print('Shutting down')

    def _plain_listener(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind(('0.0.0.0', self.plain_listen))
        while True:
            data, addr = s.recvfrom(4096)
            ts = int(time.time())
            ts_bytes = ts.to_bytes(TS_LEN, 'big')
            plaintext = ts_bytes + data
            nonce = os.urandom(NONCE_LEN)
            ct = self.aesgcm.encrypt(nonce, plaintext, None)
            packet = nonce + ct
            out = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            out.sendto(packet, self.enc_remote)
            out.close()

    def _enc_listener(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind(('0.0.0.0', self.enc_listen))
        while True:
            packet, addr = s.recvfrom(8192)
            if len(packet) < NONCE_LEN + 16:
                print('[ALERT] Received too-small encrypted packet; dropping')
                continue
            nonce = packet[:NONCE_LEN]
            ct = packet[NONCE_LEN:]
            if nonce in self.seen_nonces:
                print('[ALERT] Nonce reuse detected; dropping')
                continue
            try:
                plaintext = self.aesgcm.decrypt(nonce, ct, None)
            except Exception as e:
                print('[ALERT] Decryption/auth failed:', e)
                continue
            ts = int.from_bytes(plaintext[:TS_LEN], 'big')
            payload = plaintext[TS_LEN:]
            now = int(time.time())
            if abs(now - ts) > self.ts_skew:
                print('[ALERT] Timestamp violation; dropping')
                continue
            self.seen_nonces.add(nonce)
            fwd = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            fwd.sendto(payload, self.forward)
            fwd.close()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='GCS Secure Proxy (encrypting)')
    parser.add_argument('--key-file', default='psk.key')
    parser.add_argument('--plain-listen', type=int, default=14551, help='port where GCS sends MAVLink (plaintext)')
    parser.add_argument('--enc-remote-addr', default='127.0.0.1')
    parser.add_argument('--enc-remote-port', type=int, default=14552, help='drone proxy encrypted port')
    parser.add_argument('--enc-listen', type=int, default=14554, help='port where this proxy receives encrypted telemetry back')
    parser.add_argument('--forward-host', default='127.0.0.1')
    parser.add_argument('--forward-port', type=int, default=14550, help='where to forward decrypted telemetry (GCS listen)')
    args = parser.parse_args()

    with open(args.key_file, 'rb') as f:
        key = f.read()
    proxy = SecureProxy(key, args.plain_listen, args.enc_remote_addr, args.enc_remote_port, args.enc_listen, args.forward_host, args.forward_port)
    proxy.start()
