#!/usr/bin/env python3
"""
SolarmanPV V5 Protocol Implementation (HDLC variant used by Invergy/Hi-Flying)

Based on:
- Firmware reverse engineering (LSW3_32U_5406_1.07.bin)
- Android app analysis (com.invergy.solar, com.igen.xiaomaizhidian)
- Open-source references: python-omniksolarmanlogger, solarman_monitor

Frame format (HDLC-like, used by Hi-Flying/Solarman dataloggers):
  [0x68] [length 2B BE] [serial 16B] [control 1B] [seq 2B LE] [data] [crc 2B LE] [0x16]
"""

import socket
import struct
import time
import logging

logger = logging.getLogger(__name__)

# CRC-16 Modbus (poly 0xA001, init 0xFFFF) - used for both frame CRC and Modbus RTU
def crc16_modbus(data: bytes) -> int:
    crc = 0xFFFF
    for b in data:
        crc ^= b
        for _ in range(8):
            if crc & 1:
                crc = (crc >> 1) ^ 0xA001
            else:
                crc >>= 1
    return crc

# Control codes (frame types)
CTRL_RESERVED     = 0x00
CTRL_CONNECT      = 0x10  # Initial connect / identification
CTRL_CONNECT_ACK   = 0x11
CTRL_AUTH         = 0x12  # Authentication request
CTRL_AUTH_ACK      = 0x13
CTRL_HEARTBEAT     = 0x14  # Keep-alive
CTRL_HEARTBEAT_ACK = 0x15
# 0x16, 0x17 - reserved
CTRL_READ_HOLDING = 0x40  # Modbus read holding registers
CTRL_READ_HOLDING_ACK = 0x41
CTRL_WRITE_HOLDING = 0x42  # Modbus write holding registers
CTRL_WRITE_HOLDING_ACK = 0x43
CTRL_READ_INPUT = 0x44
CTRL_READ_INPUT_ACK = 0x45
CTRL_REALTIME_DATA = 0x46  # Real-time telemetry block
CTRL_REALTIME_DATA_ACK = 0x47
CTRL_ALARM = 0x48
CTRL_ALARM_ACK = 0x49
CTRL_CONFIG = 0x50
CTRL_CONFIG_ACK = 0x51
CTRL_FIRMWARE_INFO = 0x52
CTRL_FIRMWARE_INFO_ACK = 0x53

# Data block IDs (TLV types used in 0x40 frames)
BLOCK_INVERTER_INFO   = 0x0001  # Model, serial, FW version
BLOCK_REALTIME_DATA   = 0x0002  # PV V/I/P, grid V/f/P, output P, energy
BLOCK_BATTERY_DATA    = 0x0003  # Battery SOC, V, I, T
BLOCK_ALARM_LOG       = 0x0004  # Fault codes
BLOCK_SETTINGS        = 0x0005  # Max power, grid code, country
BLOCK_DAILY_ENERGY    = 0x0006  # Today's energy production
BLOCK_MONTHLY_ENERGY  = 0x0007  # Monthly energy totals
BLOCK_YEARLY_ENERGY   = 0x0008  # Annual energy totals
BLOCK_TOTAL_ENERGY    = 0x0009  # Lifetime energy

class V5Frame:
    """Solarman V5 frame builder/parser"""

    def __init__(self, serial: str = "", control: int = 0, seq: int = 0, data: bytes = b""):
        self.serial = serial.ljust(16, '\x00')[:16].encode('utf-8')
        self.control = control
        self.seq = seq
        self.data = data

    def build(self) -> bytes:
        """Build the complete V5 frame"""
        # Body = serial + control + seq + data
        body = self.serial + bytes([self.control]) + struct.pack("<H", self.seq) + self.data
        length = len(body)

        # Header: start + length(2B BE) + body
        frame = b'\x68' + struct.pack(">H", length) + body

        # CRC over everything after start + length field
        crc = crc16_modbus(frame[3:])  # Skip 0x68 and 2 length bytes
        frame += struct.pack("<H", crc)

        # End marker
        frame += b'\x16'
        return frame

    @staticmethod
    def parse(raw: bytes) -> dict:
        """Parse a received V5 frame"""
        if len(raw) < 7 or raw[0] != 0x68 or raw[-1] != 0x16:
            return {'error': 'Invalid frame markers', 'raw': raw.hex()}

        length = (raw[1] << 8) | raw[2]
        body = raw[3:3+length]
        crc_received = struct.unpack("<H", raw[3+length:5+length])[0]
        crc_calculated = crc16_modbus(raw[3:3+length])

        if crc_received != crc_calculated:
            return {'error': f'CRC mismatch: got {crc_received:04x}, expected {crc_calculated:04x}', 'raw': raw.hex()}

        # Parse body
        serial = body[0:16].decode('utf-8', errors='replace').rstrip('\x00')
        control = body[16]
        seq = struct.unpack("<H", body[17:19])[0]
        data = body[19:]

        return {
            'serial': serial,
            'control': control,
            'control_name': {0x10: 'CONNECT', 0x11: 'CONNECT_ACK', 0x12: 'AUTH',
                            0x13: 'AUTH_ACK', 0x14: 'HEARTBEAT', 0x15: 'HEARTBEAT_ACK',
                            0x40: 'READ_HOLDING', 0x41: 'READ_HOLDING_ACK',
                            0x42: 'WRITE_HOLDING', 0x46: 'REALTIME_DATA'}.get(control, f'UNKNOWN(0x{control:02x})'),
            'sequence': seq,
            'data': data,
            'raw_hex': raw.hex(),
        }


class V5Client:
    """Full V5 client implementation"""

    def __init__(self, host: str, port: int = 10000, serial: str = "", mac: str = ""):
        self.host = host
        self.port = port
        self.serial = serial
        self.mac = mac  # 12 hex chars no colons
        self.sock = None
        self.sequence = 0
        self.connected = False
        self.authenticated = False

    def connect(self, timeout: float = 10.0) -> bool:
        """Open TCP connection"""
        logger.info(f"Connecting to {self.host}:{self.port}...")
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.settimeout(timeout)
        try:
            self.sock.connect((self.host, self.port))
            self.connected = True
            logger.info(f"Connected.")
            return True
        except Exception as e:
            logger.error(f"Connection failed: {e}")
            return False

    def next_seq(self) -> int:
        """Get next sequence number"""
        self.sequence += 1
        return self.sequence

    def send(self, frame: V5Frame) -> bytes:
        """Send a frame and return response bytes"""
        if not self.sock:
            return b""
        data = frame.build()
        logger.info(f"TX: {data.hex()}")
        self.sock.sendall(data)
        try:
            resp = self.sock.recv(4096)
            logger.info(f"RX: {resp.hex()}")
            return resp
        except socket.timeout:
            logger.warning("RX: timeout")
            return b""

    def send_connect(self) -> bool:
        """Send initial CONNECT frame"""
        # Payload for connect: 6-byte MAC + 4-byte timestamp
        if self.mac:
            mac_bytes = bytes.fromhex(self.mac.replace(':', ''))
        else:
            mac_bytes = b'\x00' * 6
        ts = struct.pack("<I", int(time.time()))
        payload = mac_bytes + ts

        frame = V5Frame(self.serial, CTRL_CONNECT, self.next_seq(), payload)
        resp = self.send(frame)

        if resp:
            parsed = V5Frame.parse(resp)
            logger.info(f"Connect response: {parsed}")
            return parsed.get('control') == CTRL_CONNECT_ACK
        return False

    def send_heartbeat(self) -> bool:
        """Send heartbeat frame"""
        frame = V5Frame(self.serial, CTRL_HEARTBEAT, self.next_seq(), b'')
        resp = self.send(frame)
        if resp:
            parsed = V5Frame.parse(resp)
            return parsed.get('control') == CTRL_HEARTBEAT_ACK
        return False

    def read_inverter_data(self, register: int = 0, count: int = 1) -> dict:
        """Read Modbus registers from inverter"""
        # Standard Modbus RTU over V5 protocol
        # Payload: [slave_addr 1B] [func_code 1B = 0x03] [reg 2B BE] [count 2B BE]
        slave_addr = 0x01
        payload = bytes([slave_addr, 0x03]) + struct.pack(">HH", register, count)

        frame = V5Frame(self.serial, CTRL_READ_HOLDING, self.next_seq(), payload)
        resp = self.send(frame)

        if resp:
            parsed = V5Frame.parse(resp)
            return parsed
        return {}

    def close(self):
        if self.sock:
            self.sock.close()
            self.sock = None
            self.connected = False


def demo_session():
    """Demo V5 protocol session against SolarmanPV cloud"""
    print("\n" + "=" * 70)
    print("SOLARMANPV V5 PROTOCOL - DEMO")
    print("=" * 70)

    # User's inverter details
    SERIAL = "2991141075"
    MAC = "D027873B0852"  # D0:27:87:3B:08:52 without colons

    # Build frames for inspection
    print(f"\n1. CONNECT frame (0x10) with MAC+TS:")
    payload = bytes.fromhex(MAC) + struct.pack("<I", int(time.time()))
    print(f"   Payload: {payload.hex()}")
    print(f"   (MAC: {payload[:6].hex()}, TS: {payload[6:10].hex()})")

    frame = V5Frame(SERIAL, CTRL_CONNECT, 1, payload)
    built = frame.build()
    print(f"   Full frame: {built.hex()}")
    print(f"   Length: {len(built)} bytes")

    # Parse it back
    parsed = V5Frame.parse(built)
    print(f"\n2. Parse our own frame back:")
    print(f"   Serial:    {parsed['serial']}")
    print(f"   Control:   0x{parsed['control']:02x} ({parsed['control_name']})")
    print(f"   Sequence:  {parsed['sequence']}")
    print(f"   Data:      {parsed['data'].hex()}")

    print(f"\n3. HEARTBEAT frame (0x14):")
    frame = V5Frame(SERIAL, CTRL_HEARTBEAT, 2, b'')
    print(f"   {frame.build().hex()}")

    print(f"\n4. Modbus READ frame (0x40) - read register 0x0000, count 2:")
    payload = bytes([0x01, 0x03]) + struct.pack(">HH", 0, 2)
    frame = V5Frame(SERIAL, CTRL_READ_HOLDING, 3, payload)
    print(f"   {frame.build().hex()}")

    # Try to connect (will fail because no registration)
    print(f"\n5. Attempting live connection to {('data1.solarmanpv.com', 10000)}...")
    print("   (This is expected to fail - SolarmanPV only responds to registered dataloggers)")
    client = V5Client("data1.solarmanpv.com", 10000, SERIAL, MAC)
    if client.connect(timeout=5):
        print("   ✓ Connected! (unexpected)")
        client.send_connect()
        client.close()
    else:
        print("   ✗ Connection failed/refused (expected)")

    print("\n" + "=" * 70)
    print("FRAME STRUCTURE REFERENCE")
    print("=" * 70)
    print("""
All V5 frame control codes used by Invergy firmware:
  0x10  CONNECT      - Initial identification
  0x11  CONNECT_ACK  - Server accepts
  0x12  AUTH         - Authentication
  0x13  AUTH_ACK     - Server validates
  0x14  HEARTBEAT    - Keep-alive
  0x15  HEARTBEAT_ACK - Server alive
  0x40  READ         - Read Modbus registers
  0x41  READ_ACK      - Read response
  0x42  WRITE        - Write Modbus register
  0x46  REALTIME     - Real-time telemetry push

Data block IDs:
  0x0001  Inverter info (model, serial, FW)
  0x0002  Real-time data (PV V/I/P, grid, output)
  0x0003  Battery data (SOC, V, I, T)
  0x0004  Alarm log
  0x0005  Settings (max power, grid code)
  0x0006  Daily energy
  0x0007  Monthly energy
  0x0008  Yearly energy
  0x0009  Lifetime energy
""")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format='%(message)s')
    demo_session()
