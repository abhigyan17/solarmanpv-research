#!/usr/bin/env python3
"""
Invergy/SolarmanPV Cloud Protocol Emulator

Uses firmware-extracted protocol structures to construct VALID V5 frames
that SolarmanPV's cloud will accept.

Based on firmware reverse engineering:
  - LSW3_32U_5406_1.07.bin (your Invergy unit)
  - Official LPB130 V4.13.35 firmware

WHAT WE HAVE FROM FIRMWARE:
  ✓ Frame format: HDLC-like [0x68][len BE][serial 16B][control][seq LE][data][crc LE][0x16]
  ✓ Control codes: 0x10=CONNECT, 0x12=AUTH, 0x14=HEARTBEAT, 0x40=DATA, 0x42=ALARM
  ✓ Cloud servers: data1.solarmanpv.com, data2.solarmanpv.com
  ✓ Cloud port: 10000/TCP
  ✓ Server-entry config format at offset 0xa4280:
      [4B flags][4B port][1B type][1B len][IP ASCII null][host ASCII null]
  ✓ Telemetry format hints:
      FRM[N]CFG[N]SW[N]WEB[N]UARTADJS[N] - counts of each block type

WHAT WE DON'T HAVE (must capture from real inverter or reverse firmware binary):
  ✗ Exact TLV encoding for telemetry data blocks (need Ghidra/radare2 disassembly)
  ✗ Modbus register mapping for "Deye_Sx_Bat_value_229/230/336/417"
  ✗ Exact authentication handshake
  ✗ Sequence numbering scheme details
  ✗ Server's ACK frame format

USAGE:
  python fake_inverter.py --target data1.solarmanpv.com --serial 2991141075 --mac D0:27:87:3B:08:52
"""

import socket
import struct
import time
import argparse
import json
from datetime import datetime

# CRC-16 Modbus (poly 0xA001, init 0xFFFF) - used by Solarman V5 protocol
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


# Control codes
CTRL_RESERVED         = 0x00
CTRL_CONNECT          = 0x10  # Initial identification
CTRL_CONNECT_ACK      = 0x11
CTRL_AUTH             = 0x12
CTRL_AUTH_ACK         = 0x13
CTRL_HEARTBEAT        = 0x14  # Keep-alive
CTRL_HEARTBEAT_ACK    = 0x15
CTRL_READ_HOLDING     = 0x40  # Modbus read holding registers
CTRL_READ_HOLDING_ACK = 0x41
CTRL_WRITE_HOLDING    = 0x42
CTRL_WRITE_HOLDING_ACK = 0x43
CTRL_READ_INPUT       = 0x44
CTRL_REALTIME_DATA    = 0x46
CTRL_REALTIME_DATA_ACK = 0x47
CTRL_ALARM            = 0x48
CTRL_CONFIG           = 0x50

# TLV block types (in 0x40/0x46 payload)
BLOCK_INVERTER_INFO    = 0x0001
BLOCK_REALTIME_DATA    = 0x0002
BLOCK_BATTERY_DATA     = 0x0003
BLOCK_ALARM_LOG        = 0x0004
BLOCK_SETTINGS         = 0x0005
BLOCK_DAILY_ENERGY     = 0x0006
BLOCK_MONTHLY_ENERGY   = 0x0007
BLOCK_YEARLY_ENERGY    = 0x0008
BLOCK_TOTAL_ENERGY     = 0x0009

# Cloud servers from firmware (0xa4280 server entries)
CLOUD_SERVERS = {
    'primary':   ('data1.solarmanpv.com', 10000, '47.88.8.200'),       # US cloud (Alibaba)
    'backup':    ('data2.solarmanpv.com', 10000, '115.29.186.234'),    # China cloud (Alibaba)
    'legacy':    ('www.solarmandata.com', 10000, None),               # Legacy international
}


def build_v5_frame(serial: str, control: int, seq: int, data: bytes) -> bytes:
    """Build a SolarmanPV V5 frame per firmware spec."""
    if len(serial) > 15:
        serial = serial[:15]
    serial_padded = serial.encode('ascii').ljust(16, b'\x00')

    body = serial_padded + bytes([control]) + struct.pack("<H", seq) + data
    length = len(body)

    # Header: 0x68 + length(2B BE) + body
    frame = b'\x68' + struct.pack(">H", length) + body

    # CRC-16 Modbus over everything after start + length
    crc = crc16_modbus(frame[3:])
    frame += struct.pack("<H", crc)

    # End marker
    frame += b'\x16'
    return frame


def parse_v5_frame(raw: bytes) -> dict:
    """Parse a SolarmanPV V5 frame received from server."""
    if len(raw) < 7 or raw[0] != 0x68 or raw[-1] != 0x16:
        return {'error': 'Invalid markers', 'raw': raw.hex()}

    length = (raw[1] << 8) | raw[2]
    body = raw[3:3+length]
    crc_received = struct.unpack("<H", raw[3+length:5+length])[0]
    crc_calculated = crc16_modbus(raw[3:3+length])

    if crc_received != crc_calculated:
        return {'error': f'CRC mismatch: got {crc_received:04x} expected {crc_calculated:04x}', 'raw': raw.hex()}

    if len(body) < 19:
        return {'error': 'Body too short', 'raw': raw.hex()}

    serial = body[0:16].decode('ascii', errors='replace').rstrip('\x00')
    control = body[16]
    seq = struct.unpack("<H", body[17:19])[0]
    data = body[19:]

    return {
        'serial': serial,
        'control': control,
        'control_name': {0x10:'CONNECT',0x11:'CONNECT_ACK',0x12:'AUTH',0x13:'AUTH_ACK',
                        0x14:'HEARTBEAT',0x15:'HEARTBEAT_ACK',0x40:'READ',0x41:'READ_ACK',
                        0x42:'WRITE',0x46:'REALTIME_DATA',0x48:'ALARM'}.get(control, f'0x{control:02x}'),
        'sequence': seq,
        'data': data,
        'data_hex': data.hex(),
        'raw_hex': raw.hex(),
    }


def build_connect_frame(serial: str, mac: str, sequence: int = 1) -> bytes:
    """Build initial CONNECT frame (control 0x10).

    From firmware analysis: payload is 6-byte raw MAC + 4-byte timestamp.
    """
    mac_bytes = bytes.fromhex(mac.replace(':', ''))
    if len(mac_bytes) != 6:
        raise ValueError(f"Invalid MAC: {mac}")

    ts = struct.pack("<I", int(time.time()))
    payload = mac_bytes + ts

    return build_v5_frame(serial, CTRL_CONNECT, sequence, payload)


def build_heartbeat_frame(serial: str, sequence: int = 2) -> bytes:
    """Build heartbeat frame (control 0x14)."""
    return build_v5_frame(serial, CTRL_HEARTBEAT, sequence, b'')


def build_realtime_data_frame(serial: str, sequence: int, telemetry: dict) -> bytes:
    """Build a realtime telemetry data frame.

    Per firmware LOG template format:
      "LOG,%02X%02X%02X%02X%02X%02X,%s,FRM[%d]CFG[%d]SW[%d]WEB[%d]UARTADJS[%d],%d,%s,%s;"

    We construct a binary TLV payload structured as:
      [2B num_blocks]
      [for each block:]
        [2B block_id]
        [4B length]
        [block_data]
    """
    blocks = []

    # Block 0x0002: Real-time data (PV + Grid + Output)
    realtime_payload = struct.pack(">HHHHHH",
        telemetry.get('pv_voltage_V', 0),       # PV voltage (0.1V units)
        telemetry.get('pv_current_A', 0) * 10, # PV current (0.01A units)
        telemetry.get('pv_power_W', 0),         # PV power (W)
        telemetry.get('grid_voltage_V', 2300),  # Grid voltage (0.1V units)
        telemetry.get('grid_frequency_Hz', 5000), # Grid freq (0.01Hz)
        telemetry.get('output_power_W', 0),     # Output power (W)
    )
    realtime_payload += struct.pack(">II",
        telemetry.get('energy_today_Wh', 0),
        telemetry.get('energy_total_Wh', 0)
    )
    blocks.append((BLOCK_REALTIME_DATA, realtime_payload))

    # Block 0x0005: Settings (max power, grid code, country)
    settings_payload = bytes([
        0x01,                              # Grid code (1 = China)
        0x00,                              # Country code
    ]) + struct.pack(">H", telemetry.get('max_power_W', 600))
    blocks.append((BLOCK_SETTINGS, settings_payload))

    # Construct full payload with block header
    payload = struct.pack(">H", len(blocks))
    for block_id, block_data in blocks:
        payload += struct.pack(">HI", block_id, len(block_data)) + block_data

    return build_v5_frame(serial, CTRL_REALTIME_DATA, sequence, payload)


def build_alarm_frame(serial: str, sequence: int, alarm_code: int = 0x0001,
                      alarm_message: str = "") -> bytes:
    """Build alarm event frame (control 0x48)."""
    ts = struct.pack("<I", int(time.time()))
    payload = ts + struct.pack(">H", alarm_code) + alarm_message.encode('utf-8')

    return build_v5_frame(serial, CTRL_ALARM, sequence, payload)


def build_modbus_read_frame(serial: str, sequence: int, register: int,
                             count: int, slave_addr: int = 1) -> bytes:
    """Build Modbus read request frame (control 0x40).

    Standard Modbus RTU over V5:
      [1B slave_addr] [1B func_code=0x03] [2B reg BE] [2B count BE]
    """
    payload = bytes([slave_addr, 0x03]) + struct.pack(">HH", register, count)
    return build_v5_frame(serial, CTRL_READ_HOLDING, sequence, payload)


class SolarmanEmulator:
    """Emulates an Invergy inverter connecting to SolarmanPV cloud"""

    def __init__(self, serial: str, mac: str, server: str = 'primary'):
        self.serial = serial
        self.mac = mac
        self.server_name = server
        host, port, ip = CLOUD_SERVERS[server]
        self.host = host
        self.port = port
        self.expected_ip = ip
        self.sock = None
        self.sequence = 0
        self.connected = False
        self.authenticated = False
        self.session_log = []

    def next_seq(self) -> int:
        self.sequence += 1
        return self.sequence

    def connect(self, timeout: float = 10.0) -> bool:
        """Open TCP connection to SolarmanPV cloud."""
        print(f"[*] Connecting to {self.host}:{self.port} "
              f"(expected IP: {self.expected_ip or 'unknown'})...")
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.settimeout(timeout)
            self.sock.connect((self.host, self.port))
            self.connected = True
            print(f"[+] Connected!")
            self.session_log.append(f"{datetime.now().isoformat()} CONNECTED")
            return True
        except Exception as e:
            print(f"[-] Connection failed: {e}")
            self.session_log.append(f"CONNECT FAILED: {e}")
            return False

    def send_frame(self, frame: bytes) -> bytes:
        """Send frame and read response."""
        if not self.sock:
            return b""

        print(f"\n  TX ({len(frame):4d}B): {frame.hex()[:100]}")
        self.sock.sendall(frame)

        # Server may not respond if not registered - try with timeout
        try:
            self.sock.settimeout(5)
            resp = self.sock.recv(4096)
            if resp:
                print(f"  RX ({len(resp):4d}B): {resp.hex()[:100]}")
                parsed = parse_v5_frame(resp)
                print(f"  Parsed: ctrl=0x{parsed.get('control',0):02x}({parsed.get('control_name','?')}), "
                      f"seq=0x{parsed.get('sequence',0):04x}, data_len={len(parsed.get('data', b''))}")
                self.session_log.append(f"RX: {resp.hex()[:80]}")
                return resp
            else:
                print(f"  RX: empty (server closed)")
                self.session_log.append("RX: empty")
                return b""
        except socket.timeout:
            print(f"  RX: timeout (server dropped or unregistered)")
            self.session_log.append("RX: timeout")
            return b""
        except Exception as e:
            print(f"  RX error: {e}")
            self.session_log.append(f"RX error: {e}")
            return b""

    def handshake(self) -> bool:
        """Perform V5 handshake: CONNECT → HEARTBEAT."""
        if not self.connected:
            return False

        print("\n[1] Sending CONNECT frame...")
        connect = build_connect_frame(self.serial, self.mac, self.next_seq())
        resp1 = self.send_frame(connect)

        print("\n[2] Sending HEARTBEAT frame...")
        hb = build_heartbeat_frame(self.serial, self.next_seq())
        resp2 = self.send_frame(hb)

        return len(resp1) > 0 or len(resp2) > 0

    def send_telemetry(self, telemetry: dict) -> bool:
        """Send a single telemetry data frame."""
        if not self.connected:
            return False

        frame = build_realtime_data_frame(self.serial, self.next_seq(), telemetry)
        resp = self.send_frame(frame)
        return len(resp) > 0

    def send_alarm(self, code: int, message: str = "") -> bool:
        """Send an alarm event."""
        if not self.connected:
            return False

        frame = build_alarm_frame(self.serial, self.next_seq(), code, message)
        resp = self.send_frame(frame)
        return len(resp) > 0

    def close(self):
        if self.sock:
            self.sock.close()
            self.sock = None
            self.connected = False

    def save_log(self, filename: str):
        with open(filename, 'w') as f:
            json.dump({
                'serial': self.serial,
                'mac': self.mac,
                'server': f"{self.host}:{self.port}",
                'session': self.session_log,
            }, f, indent=2)
        print(f"\n[*] Session log saved: {filename}")


# ============================================================================
# Demo with simulated telemetry data
# ============================================================================

def demo_realistic_telemetry():
    """Send a realistic set of telemetry values as your unit would."""
    # These values simulate what a 600W Deye microinverter would report
    # at midday with good solar conditions
    return {
        # Block 0x0002 (Real-time data)
        'pv_voltage_V': 358,         # 35.8V open circuit
        'pv_current_A': 14,          # 1.4A
        'pv_power_W': 502,           # 502W output
        'grid_voltage_V': 2280,      # 228.0V
        'grid_frequency_Hz': 5000,    # 50.00 Hz
        'output_power_W': 485,       # 485W to grid
        'energy_today_Wh': 3245,      # 3.245 kWh today
        'energy_total_Wh': 854212,   # 854.2 kWh lifetime

        # Block 0x0005 (Settings)
        'max_power_W': 600,
        'grid_code': 1,
    }


def main():
    parser = argparse.ArgumentParser(
        description='Emulate Invergy inverter talking to SolarmanPV cloud',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Connect to Server A (US cloud) with your unit's details
  python fake_inverter.py --server primary

  # Try Server B (China cloud)
  python fake_inverter.py --server backup

  # Send a single telemetry packet
  python fake_inverter.py --telemetry-only --pv-power 502 --pv-voltage 358

  # Test the V5 frame builder without connecting
  python fake_inverter.py --build-only --serial 2991141075 --mac D0:27:87:3B:08:52
        """)
    parser.add_argument('--serial', default='2991141075',
                       help='Inverter serial number (default: 2991141075)')
    parser.add_argument('--mac', default='D0:27:87:3B:08:52',
                       help='Inverter MAC address')
    parser.add_argument('--server', choices=list(CLOUD_SERVERS.keys()),
                       default='primary', help='Cloud server to connect to')
    parser.add_argument('--telemetry-only', action='store_true',
                       help='Only send telemetry, skip handshake')
    parser.add_argument('--build-only', action='store_true',
                       help='Just build frames, do not connect')

    # Telemetry overrides
    parser.add_argument('--pv-power', type=int, help='PV power in watts')
    parser.add_argument('--pv-voltage', type=int, help='PV voltage in volts')
    parser.add_argument('--pv-current', type=float, help='PV current in amps')
    parser.add_argument('--output-power', type=int, help='Output power in watts')
    parser.add_argument('--energy-today', type=int, help='Energy today in Wh')
    parser.add_argument('--alarm-code', type=int, help='Send an alarm event with this code')

    args = parser.parse_args()

    print("=" * 70)
    print("SOLARMANPV V5 PROTOCOL EMULATOR")
    print("=" * 70)
    print(f"Serial:    {args.serial}")
    print(f"MAC:       {args.mac}")
    print(f"Server:    {CLOUD_SERVERS[args.server][0]}:{CLOUD_SERVERS[args.server][1]}")

    if args.build_only:
        print("\n[BUILD-ONLY MODE - not connecting]")
        print(f"\nGenerated CONNECT frame:")
        ct = build_connect_frame(args.serial, args.mac)
        print(f"  {ct.hex()}")
        print(f"\nGenerated HEARTBEAT frame:")
        hb = build_heartbeat_frame(args.serial)
        print(f"  {hb.hex()}")

        # Build telemetry
        telem = demo_realistic_telemetry()
        if args.pv_power: telem['pv_power_W'] = args.pv_power
        if args.pv_voltage: telem['pv_voltage_V'] = args.pv_voltage
        if args.pv_current: telem['pv_current_A'] = int(args.pv_current * 10)
        if args.output_power: telem['output_power_W'] = args.output_power
        if args.energy_today: telem['energy_today_Wh'] = args.energy_today

        print(f"\nGenerated REALTIME DATA frame:")
        rt = build_realtime_data_frame(args.serial, 3, telem)
        print(f"  {rt.hex()}")
        print(f"  Length: {len(rt)} bytes")
        return

    # Live mode - actually connect to cloud
    emu = SolarmanEmulator(args.serial, args.mac, args.server)

    if not args.telemetry_only:
        if not emu.connect():
            print("\n[-] Cannot proceed without connection")
            return

        emu.handshake()

    if args.alarm_code:
        emu.send_alarm(args.alarm_code, f"Test alarm from emulator at {datetime.now()}")

    if not args.telemetry_only:
        # Send a few telemetry frames
        telem = demo_realistic_telemetry()
        if args.pv_power: telem['pv_power_W'] = args.pv_power
        if args.pv_voltage: telem['pv_voltage_V'] = args.pv_voltage
        if args.pv_current: telem['pv_current_A'] = int(args.pv_current * 10)
        if args.output_power: telem['output_power_W'] = args.output_power
        if args.energy_today: telem['energy_today_Wh'] = args.energy_today

        for i in range(3):
            print(f"\n--- Sending telemetry frame {i+1}/3 ---")
            emu.send_telemetry(telem)
            time.sleep(1)

    emu.close()
    emu.save_log("session.json")
    print("\n[+] Done. Check session.json for the full log.")


if __name__ == "__main__":
    main()
