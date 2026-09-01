#!/usr/bin/env python3
"""
Invergy Inverter Communication Tool
Reverse-engineered from app analysis.

This tool:
1. Discovers the inverter on the network via SmartLink V2 (UDP 48899)
2. Connects via TCP port 8899 (plaintext AT commands)
3. Sends AT commands to query/control the inverter

For LIVE interaction: connect laptop to inverter's AP first.
Default AP password: 12345678
"""

import socket
import struct
import json
import time
import sys
import argparse
from datetime import datetime

# === Constants from firmware + app reverse engineering ===

SMARTLINK_DISCOVERY_PORT = 48899   # UDP broadcast port (Hi-Flying SmartLink V2)
AT_COMMAND_PORT = 8899              # Local AT command port (from app code)
DEFAULT_AP_IP = "10.10.100.254"    # Default AP gateway IP
DEFAULT_AP_PASSWORD = "12345678"    # Default AP WPA2 password

# AT commands from app reverse engineering
AT_COMMANDS = {
    "VER": "Get firmware version",
    "DTYPE": "Get device type",
    "WMODE": "WiFi mode (STA/AP/APSTA)",
    "WSSSID": "Set STA SSID",
    "WSKEY": "Set STA password",
    "WANN": "Get WAN config",
    "FAPSTA": "Force AP+STA mode",
    "WSLK": "WiFi connection status",
    "INVDATA": "Inverter data",
    "IGCPW": "IGEN Cloud Platform Password",
    "IGTNETT": "IGEN net test",
    "YZAPN": "AP name config",
    "YZNETCHECK": "Net check",
    "RSTCOUNT": "Reset counter",
    "Z": "Reset",
}

# Cloud endpoints
CLOUD_SERVER_A = ("data1.solarmanpv.com", 10000)
CLOUD_SERVER_B = ("data2.solarmanpv.com", 10000)

# === Helper functions ===

def escape_for_at(value: str) -> str:
    """Escape special characters per firmware V1.0.08-04"""
    return (value.replace('\r', '\\0D')
                .replace('\n', '\\0A')
                .replace(' ', '\\20')
                .replace(',', '\\2C')
                .replace('=', '\\3D')
                .replace('?', '\\3F'))

def crc16_modbus(data: bytes) -> int:
    """Standard Modbus CRC-16"""
    crc = 0xFFFF
    for b in data:
        crc ^= b
        for _ in range(8):
            if crc & 1:
                crc = (crc >> 1) ^ 0xA001
            else:
                crc >>= 1
    return crc

def v5_frame(control: int, seq: int, payload: bytes) -> bytes:
    """Build SolarmanPV V5 frame"""
    length = 1 + 2 + len(payload)
    body = bytes([control]) + struct.pack(">H", seq) + payload
    return b'\x68' + struct.pack(">H", length) + body + \
           struct.pack("<H", crc16_modbus(body)) + b'\x16'


class SmartLinkDiscovery:
    """SmartLink V2 discovery (UDP 48899)"""

    def __init__(self, timeout: float = 5.0):
        self.timeout = timeout
        self.found_modules = []

    def discover(self, broadcast_addr: str = "255.255.255.255") -> list:
        """Send discovery packet, listen for replies"""
        print(f"\n[1/3] SmartLink V2 Discovery (UDP {SMARTLINK_DISCOVERY_PORT})")
        print("-" * 50)

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.settimeout(2)

        discovery_packet = b"HF-A11ASSISTHREAD"
        print(f"  TX → {broadcast_addr}:{SMARTLINK_DISCOVERY_PORT}")
        print(f"      Data: {discovery_packet.hex()}")

        sock.sendto(discovery_packet, (broadcast_addr, SMARTLINK_DISCOVERY_PORT))

        start = time.time()
        while time.time() - start < self.timeout:
            try:
                data, addr = sock.recvfrom(4096)
                print(f"  ← RX from {addr}")
                print(f"      Data: {data.hex()}")

                module = self._parse_response(data, addr)
                if module:
                    self.found_modules.append(module)
            except socket.timeout:
                break

        sock.close()

        if not self.found_modules:
            print(f"\n  ⚠ No modules found on network")
            print(f"  Hint: Connect laptop to inverter's AP first")
            print(f"        Default AP SSID: AP_SOLAR_PORTAL_M2M_20120615 (or similar)")
            print(f"        Default AP password: {DEFAULT_AP_PASSWORD}")

        return self.found_modules

    def _parse_response(self, data: bytes, addr: tuple) -> dict:
        """Parse module's discovery reply"""
        try:
            text = data.decode('latin-1', errors='replace')
            if b"HF-LPB" in data or b"HF-A11" in data or "HF-LPB" in text:
                return {
                    'ip': addr[0],
                    'mac': 'UNKNOWN',
                    'port': addr[1],
                    'raw_response': data.hex(),
                }
        except:
            pass
        return None


class ATCommunicator:
    """Plaintext AT command communicator (TCP 8899)"""

    def __init__(self, ip: str, port: int = AT_COMMAND_PORT, timeout: float = 5.0):
        self.ip = ip
        self.port = port
        self.timeout = timeout
        self.sock = None
        self.command_log = []

    def connect(self) -> bool:
        """Open TCP connection to the WiFi module"""
        print(f"\n[2/3] AT Command Connection (TCP {self.port})")
        print("-" * 50)
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.settimeout(self.timeout)
            start = time.time()
            self.sock.connect((self.ip, self.port))
            elapsed = (time.time() - start) * 1000
            print(f"  ✓ Connected to {self.ip}:{self.port} in {elapsed:.1f}ms")
            return True
        except Exception as e:
            print(f"  ✗ Connection failed: {e}")
            return False

    def send(self, cmd: str, wait_response: bool = True) -> str | None:
        """Send AT command, optionally read response"""
        if not self.sock:
            return None

        escaped = escape_for_at(cmd)
        self.command_log.append({
            'time': datetime.now().isoformat(),
            'command': escaped,
            'direction': 'tx',
        })

        try:
            self.sock.sendall((escaped + "\r\n").encode('utf-8'))
            print(f"  → TX: {escaped}")

            if wait_response:
                response = b""
                self.sock.settimeout(2)
                while True:
                    try:
                        chunk = self.sock.recv(1024)
                        if not chunk:
                            break
                        response += chunk
                        if b"\r\n" in response and len(response) > 4:
                            break
                    except socket.timeout:
                        break

                resp_str = response.decode('latin-1', errors='replace').strip()
                self.command_log.append({
                    'time': datetime.now().isoformat(),
                    'response': resp_str,
                    'direction': 'rx',
                })
                print(f"  ← RX: {resp_str}")
                return resp_str
            return ""
        except Exception as e:
            print(f"  ✗ Send failed: {e}")
            return None

    def close(self):
        if self.sock:
            self.sock.close()
            self.sock = None

    def save_log(self, filename: str = "at_session.json"):
        with open(filename, 'w') as f:
            json.dump(self.command_log, f, indent=2)
        print(f"\n  Session log saved to: {filename}")


def send_to_cloud(server: tuple, sn: str, mac: str, sim: bool = True):
    """Send a V5 frame to SolarmanPV cloud (simulated if not connected)"""
    host, port = server
    print(f"\n[3/3] SolarmanPV Cloud Connection")
    print("-" * 50)

    # Build a basic identification frame
    # Format: 6-byte raw MAC + 4-byte timestamp
    mac_bytes = bytes.fromhex(mac.replace(':', ''))
    ts = int(time.time())
    ts_bytes = struct.pack("<I", ts)
    payload = mac_bytes + ts_bytes

    frame = v5_frame(0x10, 0x0001, payload)
    print(f"  Target: {host}:{port}")
    print(f"  Frame:  {frame.hex()}")
    print(f"    Start: 0x{frame[0]:02x}")
    print(f"    Length: {(frame[1] << 8) | frame[2]}")
    print(f"    Control: 0x{frame[3]:02x}")
    print(f"    Payload: {payload.hex()} (MAC+TS)")

    if sim:
        print(f"\n  [SIMULATED] Real SolarmanPV server only responds to registered dataloggers")
        print(f"  Expected response: server drops connection silently if MAC not registered")
        return None

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        sock.connect(server)
        sock.sendall(frame)
        sock.settimeout(5)
        resp = sock.recv(4096)
        if resp:
            print(f"  ← RX: {resp.hex()}")
        else:
            print(f"  ← RX: (empty - server closed connection)")
        sock.close()
        return resp
    except Exception as e:
        print(f"  ✗ Error: {e}")
        return None


def main():
    parser = argparse.ArgumentParser(
        description="Invergy Inverter Communication Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Discover inverter on local network
  python inverter_tool.py discover

  # Connect and query a specific IP
  python inverter_tool.py query 192.168.1.100

  # Send specific AT commands
  python inverter_tool.py at 10.10.100.254 --cmd "AT+VER" --cmd "AT+DTYPE"

  # Capture full session to JSON
  python inverter_tool.py query 10.10.100.254 --save session.json
        """)
    subparsers = parser.add_subparsers(dest='command')

    # discover
    subparsers.add_parser('discover', help='Discover inverter via SmartLink')

    # query
    p_query = subparsers.add_parser('query', help='Query inverter info')
    p_query.add_argument('ip', help='Inverter IP address')
    p_query.add_argument('--port', type=int, default=AT_COMMAND_PORT)
    p_query.add_argument('--save', help='Save session log to JSON')

    # at
    p_at = subparsers.add_parser('at', help='Send AT commands')
    p_at.add_argument('ip', help='Inverter IP address')
    p_at.add_argument('--port', type=int, default=AT_COMMAND_PORT)
    p_at.add_argument('--cmd', action='append', required=True, help='AT command(s) to send')

    args = parser.parse_args()

    if args.command == 'discover':
        discovery = SmartLinkDiscovery()
        modules = discovery.discover()
        if modules:
            for m in modules:
                print(f"\n  Module: {m['ip']}:{m['port']}")
                print(f"    Raw: {m['raw_response']}")

    elif args.command == 'query':
        print(f"\n{'=' * 60}")
        print(f"Invergy Inverter Query Tool")
        print(f"{'=' * 60}")
        print(f"Target: {args.ip}:{args.port}")

        comm = ATCommunicator(args.ip, args.port)
        if comm.connect():
            for cmd in ['AT+VER', 'AT+DTYPE', 'AT+WMODE', 'AT+WANN', 'AT+YZAPN']:
                comm.send(cmd)
                time.sleep(0.1)
            comm.close()
            if args.save:
                comm.save_log(args.save)

    elif args.command == 'at':
        comm = ATCommunicator(args.ip, args.port)
        if comm.connect():
            for cmd in args.cmd:
                comm.send(cmd)
                time.sleep(0.1)
            comm.close()

    else:
        # Default: full demo
        print("\nNo command specified. Running demo mode...")
        print("\n[Demo 1] SmartLink Discovery")
        discovery = SmartLinkDiscovery(timeout=3)
        modules = discovery.discover()

        if modules:
            module = modules[0]
            print(f"\n[Demo 2] AT Command Session")
            comm = ATCommunicator(module['ip'])
            if comm.connect():
                for cmd in ['AT+VER', 'AT+DTYPE']:
                    comm.send(cmd)
                comm.close()

        print("\n[Demo 3] SolarmanPV Cloud Handshake (simulated)")
        send_to_cloud(CLOUD_SERVER_A, '2991141075', 'D0:27:87:3B:08:52', sim=True)


if __name__ == "__main__":
    main()
