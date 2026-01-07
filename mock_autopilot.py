"""
Mock autopilot that listens for MAVLink messages on UDP 14550 and logs received messages.
It uses pymavlink to parse incoming MAVLink packets where possible.
"""
import argparse
import socket
import time
from pymavlink import mavutil

LISTEN_PORT = 14550

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Mock Autopilot listener for MAVLink')
    parser.add_argument('--port', type=int, default=LISTEN_PORT)
    args = parser.parse_args()

    print('Starting mock autopilot listener on 0.0.0.0:%d' % args.port)
    # Use mavutil to create a listener socket that parses MAVLink messages
    conn = mavutil.mavlink_connection(f'udp:0.0.0.0:{args.port}', robust_parsing=True)
    print('Waiting for MAVLink messages...')
    try:
        while True:
            msg = conn.recv_match(blocking=True, timeout=5)
            if msg is None:
                continue
            print(f'[RECV] msg: {msg.get_type()}', msg.to_dict())
    except KeyboardInterrupt:
        print('\nMock autopilot stopped')
    finally:
        try:
            conn.close()
        except Exception:
            pass
