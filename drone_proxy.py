import argparse
import socket
import threading
import time
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

NONCE_LEN = 12
TS_LEN = 8

class DroneProxy:
    def __init__(self, key, enc_listen, plain_forward_host, plain_forward_port, enc_remote_addr, enc_remote_port, ts_skew=3):
        self.key = key
        self.aesgcm = AESGCM(key)
        self.enc_listen = enc_listen
        self.plain_forward = (plain_forward_host, plain_forward_port)
        self.enc_remote = (enc_remote_addr, enc_remote_port)
        self.ts_skew = ts_skew
        self.seen_nonces = set()

    def start(self):
        t1 = threading.Thread(target=self._enc_listener, daemon=True)
        t2 = threading.Thread(target=self._plain_listener, daemon=True)
        t1.start(); t2.start()
        print('Drone proxy running. Enc listen:', self.enc_listen, 'Plain forward:', self.plain_forward)
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print('Shutting down')

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
            fwd.sendto(payload, self.plain_forward)
            fwd.close()

    def _plain_listener(self):
        # Listen for plaintext from autopilot and send encrypted back to GCS proxy
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind(('0.0.0.0', self.plain_forward[1] + 100))  # Different port for telemetry back
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

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Drone Secure Proxy (decrypting)')
    parser.add_argument('--key-file', default='psk.key')
    parser.add_argument('--enc-listen', type=int, default=14552, help='port to receive encrypted from GCS proxy')
    parser.add_argument('--plain-forward-host', default='127.0.0.1')
    parser.add_argument('--plain-forward-port', type=int, default=14550, help='where to forward plaintext to autopilot')
    parser.add_argument('--enc-remote-addr', default='127.0.0.1')
    parser.add_argument('--enc-remote-port', type=int, default=14554, help='GCS proxy encrypted listen port for telemetry')
    args = parser.parse_args()

    with open(args.key_file, 'rb') as f:
        key = f.read()
    proxy = DroneProxy(key, args.enc_listen, args.plain_forward_host, args.plain_forward_port, args.enc_remote_addr, args.enc_remote_port)
    proxy.start()
