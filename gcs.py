from pymavlink import mavutil
import hmac
import hashlib
import struct

# Connect to drone
master = mavutil.mavlink_connection('udpout:127.0.0.1:14550')
master.wait_heartbeat()

SHARED_KEY = b"super_secret_256bit_key"

def send_secure_command(command_id, param1=0):
    # Serialize command payload
    payload = struct.pack('<If', command_id, param1)

    # Generate HMAC
    mac = hmac.new(SHARED_KEY, payload, hashlib.sha256).digest()

    # Send as MAVLink message (ENCAPSULATED_DATA used as container)
    master.mav.encapsulated_data_send(
        len(payload + mac),
        payload + mac
    )

# Example: ARM command
MAV_CMD_COMPONENT_ARM_DISARM = 400
send_secure_command(MAV_CMD_COMPONENT_ARM_DISARM, 1)
