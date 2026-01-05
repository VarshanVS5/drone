from pymavlink import mavutil
import hmac
import hashlib
import struct

SHARED_KEY = b"super_secret_256bit_key"

master = mavutil.mavlink_connection('udpin:0.0.0.0:14550')

while True:
    msg = master.recv_match(type='ENCAPSULATED_DATA', blocking=True)

    data = bytes(msg.data[:msg.seqnr])
    payload = data[:-32]
    received_mac = data[-32:]

    expected_mac = hmac.new(SHARED_KEY, payload, hashlib.sha256).digest()

    if not hmac.compare_digest(received_mac, expected_mac):
        print("Tampered packet rejected")
        continue

    command_id, param1 = struct.unpack('<If', payload)

    if command_id == 400:
        if param1 == 1:
            print("ARMING DRONE")
        else:
            print("DISARMING DRONE")
