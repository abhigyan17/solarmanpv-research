#!/usr/bin/env python3
"""
V5 Protocol Transmitter - Get ACK from SolarmanPV Cloud
Uses reverse-engineered firmware protocol to construct valid packets.

Based on decompilation of:
- orchestrator (fcn.0008b1d0) - HDLC framing
- func_0039 (0x1f5f0) - CONNECT/AUTH/HEARTBEAT/READ frame builders
- func_0046 (0x250f0) - CONNECT/HEARTBEAT
- func_0017 (0x0898e) - READ (Modbus)
- func_0204 (0x8ca0c) - REALTIME_DATA/ALARM

The server accepts TCP from any IP but only ACKs packets from REGISTERED
MAC+Serial pairs. To get an ACK we need to use a real registered pair.

Known registered values:
  Serial: 2991141075
  MAC: D0:27:87:3B:08:52
"""

import socket
import struct
import time
import sys
import json
import threading
from datetime import datetime

# CRC-16 Modbus (poly 0xA001, init 0xFFFF)
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


def build_v5_frame(serial: str, control: int, seq: int, payload: bytes) -> bytes:
    """Build V5 frame per firmware spec - exact match to func_0204/func_0039"""
    if len(serial) > 15:
        serial = serial[:15]
    serial_padded = serial.encode('ascii').ljust(16, b'\x00')[:16]

    body = serial_padded + bytes([control]) + struct.pack("<H", seq) + payload
    length = len(body)

    frame = b'\x68' + struct.pack(">H", length) + body
    crc = crc16_modbus(frame[3:])
    frame += struct.pack("<H", crc)
    frame += b'\x16'
    return frame


def parse_v5_frame(raw: bytes) -> dict:
    if len(raw) < 7 or raw[0] != 0x68 or raw[-1] != 0x16:
        return {'error': f'Invalid markers: {raw[:5].hex()}'}

    length = (raw[1] << 8) | raw[2]
    body = raw[3:3+length]
    if len(body) < 19:
        return {'error': 'Body too short', 'raw': raw.hex()}

    crc_received = struct.unpack("<H", raw[3+length:5+length])[0]
    crc_calculated = crc16_modbus(raw[3:3+length])

    serial = body[0:16].decode('ascii', errors='replace').rstrip('\x00')
    control = body[16]
    seq = struct.unpack("<H", body[17:19])[0]
    data = body[19:]

    ctrl_names = {0x10: 'CONNECT', 0x11: 'CONNECT_ACK', 0x12: 'AUTH',
                  0x13: 'AUTH_ACK', 0x14: 'HEARTBEAT', 0x15: 'HEARTBEAT_ACK',
                  0x40: 'READ', 0x41: 'READ_ACK', 0x46: 'REALTIME_DATA',
                  0x47: 'REALTIME_DATA_ACK', 0x48: 'ALARM', 0x49: 'ALARM_ACK'}

    return {
        'serial': serial,
        'control': control,
        'control_name': ctrl_names.get(control, f'0x{control:02x}'),
        'sequence': seq,
        'crc_ok': crc_received == crc_calculated,
        'data': data,
        'data_hex': data.hex(),
        'raw_hex': raw.hex(),
    }


# ============================================================================
# Cloud servers (from firmware config at offset 0xa4280)
# ============================================================================
CLOUD_SERVERS = {
    'primary_us':   ('data1.solarmanpv.com', 10000, '47.88.8.200'),
    'backup_cn':    ('data2.solarmanpv.com', 10000, '115.29.186.234'),
    'legacy':       ('www.solarmandata.com', 10000, None),
}


# ============================================================================
# V5 Frame constructors - based on decompiled func_0039, func_0046, func_0204
# ============================================================================

def make_connect_frame(serial: str, mac: str, seq: int = 1) -> bytes:
    """
    func_0046 @ 0x257b4: CONNECT frame payload
    func_0039 @ 0x20012: CONNECT frame payload
    Payload format: 6-byte MAC + 4-byte timestamp (little-endian)
    """
    mac_bytes = bytes.fromhex(mac.replace(':', ''))
    if len(mac_bytes) != 6:
        raise ValueError(f"Invalid MAC: {mac}")

    ts = struct.pack("<I", int(time.time()))
    payload = mac_bytes + ts
    return build_v5_frame(serial, 0x10, seq, payload)


def make_auth_frame(serial: str, seq: int, token: bytes = b'') -> bytes:
    """
    func_0039 @ 0x1f96e: AUTH frame
    Payload: variable, often empty or contains handshake data
    """
    payload = token if token else b'\x00' * 8
    return build_v5_frame(serial, 0x12, seq, payload)


def make_heartbeat_frame(serial: str, seq: int, ts: int = None) -> bytes:
    """
    func_0039 @ 0x1f8ba: HEARTBEAT frame
    func_0046 @ 0x2512a: HEARTBEAT frame
    Payload: typically empty or contains timestamp
    """
    if ts is None:
        ts = int(time.time())
    payload = struct.pack("<I", ts)
    return build_v5_frame(serial, 0x14, seq, payload)


def make_read_frame(serial: str, seq: int, register: int, count: int = 1,
                     slave_addr: int = 1) -> bytes:
    """
    func_0017 @ multiple: READ (Modbus) frame
    func_0022 @ 0x22248: READ frame
    Payload: Modbus RTU request over V5
      [1B slave_addr][1B func_code=0x03][2B reg BE][2B count BE]
    """
    payload = bytes([slave_addr, 0x03]) + struct.pack(">HH", register, count)
    return build_v5_frame(serial, 0x40, seq, payload)


def make_realtime_frame(serial: str, seq: int, telemetry: dict) -> bytes:
    """
    func_0204 @ 38x: REALTIME_DATA frame
    Payload: TLV blocks of inverter data
    """
    blocks = []

    # Block 0x0002: Real-time data (PV + Grid + Output)
    realtime = struct.pack(">HHHHHH",
        telemetry.get('pv_voltage_V', 0),
        telemetry.get('pv_current_A', 0) * 10,
        telemetry.get('pv_power_W', 0),
        telemetry.get('grid_voltage_V', 2300),
        telemetry.get('grid_freq_Hz', 5000),
        telemetry.get('output_power_W', 0),
    )
    realtime += struct.pack(">II",
        telemetry.get('energy_today_Wh', 0),
        telemetry.get('energy_total_Wh', 0),
    )
    blocks.append((0x0002, realtime))

    # Block 0x0005: Settings
    settings = bytes([0x01, 0x00]) + struct.pack(">H", telemetry.get('max_power_W', 600))
    blocks.append((0x0005, settings))

    payload = struct.pack(">H", len(blocks))
    for block_id, data in blocks:
        payload += struct.pack(">HI", block_id, len(data)) + data

    return build_v5_frame(serial, 0x46, seq, payload)


def make_alarm_frame(serial: str, seq: int, code: int = 1,
                     message: str = "") -> bytes:
    """
    func_0204 @ 0x91746: ALARM frame
    Payload: timestamp + alarm code + message
    """
    ts = struct.pack("<I", int(time.time()))
    payload = ts + struct.pack(">H", code) + message.encode('utf-8')[:64]
    return build_v5_frame(serial, 0x48, seq, payload)


# ============================================================================
# High-level session
# ============================================================================
class SolarmanSession:
    """Complete V5 protocol session against SolarmanPV cloud"""

    def __init__(self, serial: str, mac: str, server: str = 'primary_us'):
        self.serial = serial
        self.mac = mac
        self.host, self.port, self.expected_ip = CLOUD_SERVERS[server]
        self.sock = None
        self.sequence = 0
        self.connected = False
        self.authenticated = False
        self.session_log = []
        self.server_acks = []  # Track all received ACKs

    def next_seq(self) -> int:
        self.sequence += 1
        return self.sequence

    def connect(self, timeout: float = 10.0) -> bool:
        """Open TCP connection to SolarmanPV cloud"""
        print(f"\n[*] Connecting to {self.host}:{self.port} (IP: {self.expected_ip})...")
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.settimeout(timeout)
            t0 = time.time()
            self.sock.connect((self.host, self.port))
            elapsed = (time.time() - t0) * 1000
            self.connected = True
            print(f"[+] TCP CONNECTED in {elapsed:.0f}ms")
            self.session_log.append(f"{datetime.now().isoformat()} TCP_CONNECTED to {self.host}:{self.port}")
            return True
        except Exception as e:
            print(f"[-] Connection failed: {e}")
            self.session_log.append(f"CONNECT_FAILED: {e}")
            return False

    def send_frame(self, frame: bytes, name: str = "frame") -> bytes:
        """Send V5 frame and read response"""
        if not self.sock:
            return b""

        print(f"\n  → TX {name} ({len(frame):3d}B): {frame.hex()[:80]}{'...' if len(frame.hex()) > 80 else ''}")
        self.session_log.append(f"TX {name}: {frame.hex()[:60]}")
        try:
            self.sock.sendall(frame)
        except Exception as e:
            print(f"  ✗ Send failed: {e}")
            return b""

        try:
            self.sock.settimeout(8)
            resp = self.sock.recv(4096)
            if resp:
                parsed = parse_v5_frame(resp)
                print(f"  ← RX ACK ({len(resp):3d}B): {resp.hex()[:80]}{'...' if len(resp.hex()) > 80 else ''}")
                if parsed.get('error'):
                    print(f"     Parse error: {parsed['error']}")
                else:
                    print(f"     ctrl=0x{parsed['control']:02x}({parsed['control_name']}), "
                          f"seq=0x{parsed['sequence']:04x}, crc_ok={parsed['crc_ok']}")
                    if parsed['data']:
                        print(f"     data_len={len(parsed['data'])}, hex={parsed['data_hex'][:60]}")
                    self.server_acks.append(parsed)
                    self.session_log.append(f"RX {parsed['control_name']}: seq=0x{parsed['sequence']:04x}")
                return resp
            else:
                print(f"  ← RX: (empty - server closed)")
                self.session_log.append("RX: empty (server closed)")
                return b""
        except socket.timeout:
            print(f"  ← RX: timeout (server dropped silently)")
            self.session_log.append(f"RX timeout for {name}")
            return b""
        except Exception as e:
            print(f"  ← RX error: {e}")
            self.session_log.append(f"RX error: {e}")
            return b""

    def run_full_handshake(self) -> bool:
        """Run V5 handshake sequence as firmware does"""
        if not self.connected:
            return False

        print("\n" + "=" * 70)
        print("[1] CONNECT (func_0046 @ 0x257b4)")
        print("=" * 70)
        connect = make_connect_frame(self.serial, self.mac, self.next_seq())
        resp1 = self.send_frame(connect, "CONNECT")

        if resp1:
            parsed1 = parse_v5_frame(resp1)
            if parsed1.get('control') == 0x11:
                print(f"[+] Got CONNECT_ACK!")

        print("\n" + "=" * 70)
        print("[2] AUTH (func_0039 @ 0x1f96e)")
        print("=" * 70)
        auth = make_auth_frame(self.serial, self.next_seq())
        resp2 = self.send_frame(auth, "AUTH")

        if resp2:
            parsed2 = parse_v5_frame(resp2)
            if parsed2.get('control') == 0x13:
                print(f"[+] Got AUTH_ACK!")
                self.authenticated = True

        print("\n" + "=" * 70)
        print("[3] HEARTBEAT (func_0039 @ 0x1f8ba)")
        print("=" * 70)
        hb = make_heartbeat_frame(self.serial, self.next_seq())
        resp3 = self.send_frame(hb, "HEARTBEAT")

        if resp3:
            parsed3 = parse_v5_frame(resp3)
            if parsed3.get('control') == 0x15:
                print(f"[+] Got HEARTBEAT_ACK!")

        return len(resp1) > 0 or len(resp2) > 0 or len(resp3) > 0

    def send_telemetry(self) -> bool:
        """Send REALTIME_DATA frame"""
        if not self.connected:
            return False

        print("\n" + "=" * 70)
        print("[4] REALTIME_DATA (func_0204 @ 38x refs)")
        print("=" * 70)

        # Realistic telemetry for a 600W Deye inverter at midday
        telemetry = {
            'pv_voltage_V': 358,
            'pv_current_A': 14,
            'pv_power_W': 502,
            'grid_voltage_V': 2280,
            'grid_freq_Hz': 5000,
            'output_power_W': 485,
            'energy_today_Wh': 3245,
            'energy_total_Wh': 854212,
            'max_power_W': 600,
        }

        frame = make_realtime_frame(self.serial, self.next_seq(), telemetry)
        resp = self.send_frame(frame, "REALTIME_DATA")
        return len(resp) > 0

    def send_modbus_read(self, register: int = 0, count: int = 2) -> bool:
        """Send Modbus READ frame"""
        if not self.connected:
            return False

        print("\n" + "=" * 70)
        print(f"[5] MODBUS READ (func_0017 @ 0x0898e) - reg={register} count={count}")
        print("=" * 70)
        frame = make_read_frame(self.serial, self.next_seq(), register, count)
        resp = self.send_frame(frame, "MODBUS_READ")
        return len(resp) > 0

    def close(self):
        if self.sock:
            self.sock.close()
            self.sock = None
            self.connected = False

    def save_log(self, filename: str):
        log = {
            'target': f"{self.host}:{self.port}",
            'serial': self.serial,
            'mac': self.mac,
            'frames_sent': self.sequence,
            'acks_received': len(self.server_acks),
            'ack_details': self.server_acks,
            'session': self.session_log,
        }
        with open(filename, 'w') as f:
            json.dump(log, f, indent=1)
        print(f"\n[*] Session log: {filename}")


def demo():
    """Run a full V5 session against SolarmanPV cloud"""
    print("=" * 70)
    print("V5 PROTOCOL TRANSMITTER - LIVE TEST AGAINST SOLARMANPV CLOUD")
    print("=" * 70)
    print("Serial: 2991141075")
    print("MAC:    D0:27:87:3B:08:52")

    # Try BOTH cloud servers
    for server_name in ['primary_us', 'backup_cn']:
        print(f"\n{'#' * 70}")
        print(f"# SERVER: {server_name} ({CLOUD_SERVERS[server_name][0]})")
        print(f"{'#' * 70}")

        session = SolarmanSession("2991141075", "D027873B0852", server_name)

        if session.connect():
            session.run_full_handshake()
            session.send_telemetry()
            session.send_modbus_read(register=0, count=4)

            session.close()
            session.save_log(f"session_{server_name}.json")

            if session.server_acks:
                print(f"\n[+] RECEIVED {len(session.server_acks)} ACKs FROM SERVER!")
                for ack in session.server_acks:
                    print(f"    {ack.get('control_name')}: seq=0x{ack.get('sequence',0):04x}")
            else:
                print(f"\n[-] Server accepted TCP but did not ACK our frames")
                print(f"    (This is expected for unregistered MAC+Serial)")
        else:
            print(f"[-] Could not connect to {CLOUD_SERVERS[server_name][0]}")


if __name__ == "__main__":
    demo()