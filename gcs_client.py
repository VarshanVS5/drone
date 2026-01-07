"""
Simple GCS client to send a MISSION_ITEM_INT waypoint to the GCS proxy (plaintext port).
"""
import argparse
from pymavlink import mavutil

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='GCS client: send waypoint to GCS proxy')
    parser.add_argument('--host', default='127.0.0.1')
    parser.add_argument('--port', type=int, default=14551)
    parser.add_argument('--lat', type=float, default=37.4275)
    parser.add_argument('--lon', type=float, default=-122.1697)
    parser.add_argument('--alt', type=float, default=10.0)
    args = parser.parse_args()

    conn = mavutil.mavlink_connection(f'udpout:{args.host}:{args.port}', source_system=1)
    print('Sending MISSION_ITEM_INT to', args.host, args.port)
    conn.mav.mission_item_int_send(
        0, 0, 0,
        mavutil.mavlink.MAV_FRAME_GLOBAL_INT,
        mavutil.mavlink.MAV_CMD_NAV_WAYPOINT,
        0, 1, # current=0, autocontinue=1
        0, 0, 0, 0,  # param1, param2, param3, param4
        int(args.lat * 1e7),
        int(args.lon * 1e7),
        int(args.alt)  # z (altitude)
    )
    print('Sent waypoint', args.lat, args.lon, args.alt)
