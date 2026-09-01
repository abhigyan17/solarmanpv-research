#!/usr/bin/env python3
"""
Invergy Inverter Controller - Full AT Command Automation

Mimics the Invergy app's communication with the WiFi module.
All commands are sent PLAINTEXT (the app's encryption is broken).

For LIVE control: connect laptop to the inverter's AP first.
Default AP: 10.10.100.254 (gateway) or 10.10.10.3 (module)
Default AP password: 12345678
"""

import socket
import time
import json
import argparse
import sys
from datetime import datetime

# === Constants ===
AT_COMMAND_PORT = 8899
SMARTLINK_DISCOVERY_PORT = 48899
DEFAULT_AP_IP = "10.10.100.254"
DEFAULT_AP_PASSWORD = "12345678"
DEFAULT_ADMIN_URL = "http://10.10.100.254/"
DEFAULT_ADMIN_USER = "admin"
DEFAULT_ADMIN_PASS = "admin"

# === Helper Functions ===

def escape_for_at(value: str) -> str:
    """Escape special characters per firmware V1.0.08-04 spec"""
    return (value.replace('\r', '\\0D')
                .replace('\n', '\\0A')
                .replace(' ', '\\20')
                .replace(',', '\\2C')
                .replace('=', '\\3D')
                .replace('?', '\\3F'))


class InverterController:
    """Full controller for the Invergy inverter WiFi module"""

    def __init__(self, ip: str, port: int = AT_COMMAND_PORT, timeout: float = 5.0):
        self.ip = ip
        self.port = port
        self.timeout = timeout
        self.sock = None
        self.session_log = []
        self.connected = False

    def connect(self) -> bool:
        """Open TCP connection to inverter"""
        print(f"[*] Connecting to {self.ip}:{self.port}...")
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.settimeout(self.timeout)
            self.sock.connect((self.ip, self.port))
            self.connected = True
            print(f"[+] Connected!")
            self._log_event("connect", f"{self.ip}:{self.port}")
            return True
        except Exception as e:
            print(f"[-] Connection failed: {e}")
            return False

    def close(self):
        if self.sock:
            self.sock.close()
            self.sock = None
            self.connected = False

    def send_at(self, cmd: str, expect_response: bool = True, wait: float = 1.0) -> str:
        """Send AT command and read response"""
        if not self.sock:
            return ""

        escaped = escape_for_at(cmd)
        full_cmd = escaped + "\r\n"

        self._log_event("tx", escaped)
        self.sock.sendall(full_cmd.encode('utf-8'))
        print(f"  → TX: {escaped}")

        if not expect_response:
            time.sleep(0.1)
            return ""

        self.sock.settimeout(wait)
        response = b""
        try:
            while True:
                chunk = self.sock.recv(4096)
                if not chunk:
                    break
                response += chunk
                if b"\r\n" in response and len(response) > 4:
                    break
        except socket.timeout:
            pass

        resp_str = response.decode('latin-1', errors='replace').strip()
        self._log_event("rx", resp_str)
        print(f"  ← RX: {resp_str}")
        return resp_str

    # === High-level inverter operations ===

    def get_version(self) -> str:
        """Get firmware version"""
        return self.send_at("AT+VER")

    def get_device_type(self) -> str:
        """Get device type"""
        return self.send_at("AT+DTYPE")

    def get_wifi_mode(self) -> str:
        """Get current WiFi mode"""
        return self.send_at("AT+WMODE")

    def get_sta_ssid(self) -> str:
        """Get connected WiFi SSID"""
        return self.send_at("AT+WSSSID")

    def get_sta_status(self) -> str:
        """Get WiFi connection status"""
        return self.send_at("AT+WSLK")

    def get_wan_config(self) -> str:
        """Get WAN (internet) config"""
        return self.send_at("AT+WANN")

    def get_ap_name(self) -> str:
        """Get AP name"""
        return self.send_at("AT+YZAPN")

    def get_all_info(self) -> dict:
        """Get all inverter info"""
        info = {}
        info['version'] = self.get_version()
        info['device_type'] = self.get_device_type()
        info['wifi_mode'] = self.get_wifi_mode()
        info['sta_ssid'] = self.get_sta_ssid()
        info['sta_status'] = self.get_sta_status()
        info['wan_config'] = self.get_wan_config()
        info['ap_name'] = self.get_ap_name()
        return info

    def set_wifi_credentials(self, ssid: str, password: str, encryption: str = "WPA2PSK",
                              auth: str = "AES") -> str:
        """Configure WiFi station credentials"""
        print(f"\n[*] Setting WiFi to: {ssid}")

        # Set mode to STA
        self.send_at("AT+WMODE=STA")

        # Set SSID
        self.send_at(f"AT+WSSSID={escape_for_at(ssid)}")

        # Set password
        self.send_at(f"AT+WSKEY={encryption},{auth},{escape_for_at(password)}")

        # Trigger reconnect
        return self.send_at("AT+WANN")

    def force_apsta_mode(self) -> str:
        """Force AP+STA mode (enable AP for config while connected to WiFi)"""
        return self.send_at("AT+FAPSTA")

    def restart(self) -> str:
        """Restart the WiFi module"""
        print(f"\n[*] Restarting WiFi module...")
        return self.send_at("AT+Z", expect_response=False)

    def run_network_check(self) -> str:
        """Run network connectivity check"""
        return self.send_at("AT+YZNETCHECK", wait=5.0)

    def get_inverter_data(self) -> str:
        """Get current inverter telemetry data"""
        return self.send_at("AT+INVDATA?", wait=3.0)

    # === SmartLink Discovery ===

    @staticmethod
    def discover(timeout: float = 5.0) -> list:
        """Find inverters on the network via SmartLink discovery"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.settimeout(2)

        packet = b"HF-A11ASSISTHREAD"
        sock.sendto(packet, ("255.255.255.255", SMARTLINK_DISCOVERY_PORT))

        modules = []
        start = time.time()
        while time.time() - start < timeout:
            try:
                data, addr = sock.recvfrom(4096)
                modules.append({'ip': addr[0], 'port': addr[1], 'raw': data.hex()})
            except socket.timeout:
                break

        sock.close()
        return modules

    # === Logging ===

    def _log_event(self, direction: str, data: str):
        self.session_log.append({
            'time': datetime.now().isoformat(),
            'direction': direction,
            'data': data,
        })

    def save_log(self, filename: str):
        with open(filename, 'w') as f:
            json.dump({
                'target': f"{self.ip}:{self.port}",
                'session': self.session_log,
            }, f, indent=2)
        print(f"[*] Session saved to: {filename}")


# === CLI Commands ===

def cmd_info(args):
    """Get inverter info"""
    c = InverterController(args.target, args.port)
    if not c.connect():
        return

    info = c.get_all_info()
    print("\n" + "=" * 50)
    print("INVERTER INFORMATION")
    print("=" * 50)
    for k, v in info.items():
        print(f"  {k:15s}: {v}")

    c.close()
    if args.save:
        c.save_log(args.save)


def cmd_discover(args):
    """Discover inverters"""
    print("[*] Searching for inverters via SmartLink...")
    modules = InverterController.discover(args.timeout)
    if modules:
        print(f"\n[+] Found {len(modules)} module(s):")
        for m in modules:
            print(f"    {m['ip']}:{m['port']}  ({m['raw'][:32]}...)")
    else:
        print("[-] No modules found")


def cmd_setwifi(args):
    """Set WiFi credentials"""
    c = InverterController(args.target, args.port)
    if not c.connect():
        return

    c.set_wifi_credentials(args.ssid, args.password, args.encryption, args.auth)
    print("\n[+] WiFi credentials set. Module will restart in ~30s.")

    c.close()
    if args.save:
        c.save_log(args.save)


def cmd_inverter_data(args):
    """Get current inverter telemetry"""
    c = InverterController(args.target, args.port)
    if not c.connect():
        return

    print("[*] Reading inverter data...")
    data = c.get_inverter_data()
    print(f"\n[+] Inverter data:\n{data}")

    c.close()
    if args.save:
        c.save_log(args.save)


def cmd_at(args):
    """Send arbitrary AT command"""
    c = InverterController(args.target, args.port)
    if not c.connect():
        return

    for cmd in args.commands:
        c.send_at(cmd)
        time.sleep(0.1)

    c.close()
    if args.save:
        c.save_log(args.save)


def cmd_dump(args):
    """Dump full session - all available commands"""
    c = InverterController(args.target, args.port)
    if not c.connect():
        return

    commands = [
        ("AT+VER", "Firmware version"),
        ("AT+DTYPE", "Device type"),
        ("AT+WMODE", "WiFi mode"),
        ("AT+WSSSID", "STA SSID"),
        ("AT+WSKEY", "STA password (may not show)"),
        ("AT+WANN", "WAN config"),
        ("AT+WSLK", "WiFi link status"),
        ("AT+YZAPN", "AP name"),
        ("AT+YZNETCHECK", "Network check (slow)"),
        ("AT+INVDATA?", "Inverter data (slow)"),
        ("AT+UART", "UART config"),
    ]
    print(f"\n[*] Dumping {len(commands)} commands...\n")
    for cmd, desc in commands:
        if '?' in cmd or cmd in ['AT+YZNETCHECK', 'AT+INVDATA?']:
            continue  # Skip slow/optional ones
        print(f"--- {desc} ---")
        c.send_at(cmd)
        time.sleep(0.05)

    c.close()
    if args.save:
        c.save_log(args.save)


def cmd_web(args):
    """Query the web admin interface"""
    import urllib.request
    import urllib.error
    import base64

    print(f"[*] Querying {DEFAULT_ADMIN_URL} on {args.target}...")

    url = f"http://{args.target}/"
    auth_string = base64.b64encode(f"{args.user}:{args.password}".encode()).decode()

    try:
        req = urllib.request.Request(url, headers={
            'Authorization': f'Basic {auth_string}',
            'User-Agent': 'Mozilla/5.0',
            'Host': args.target,
        })
        r = urllib.request.urlopen(req, timeout=5)
        print(f"[+] HTTP {r.status}")
        body = r.read().decode('utf-8', errors='replace')
        print(f"  Body length: {len(body)} bytes")
        print(f"  First 500 chars:\n{body[:500]}")
    except urllib.error.HTTPError as e:
        print(f"[-] HTTP {e.code}: {e.reason}")
        print(f"  Body: {e.read().decode('utf-8', errors='replace')[:500]}")
    except Exception as e:
        print(f"[-] Error: {e}")


def main():
    parser = argparse.ArgumentParser(
        description="Invergy Inverter Controller",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Get all inverter info
  python controller.py info 10.10.100.254

  # Discover inverters on network
  python controller.py discover

  # Set WiFi credentials
  python controller.py setwifi 10.10.100.254 --ssid MyWiFi --password MyPass123

  # Get current inverter telemetry
  python controller.py inverter-data 10.10.100.254

  # Send arbitrary AT commands
  python controller.py at 10.10.100.254 --cmd "AT+VER" --cmd "AT+DTYPE"

  # Query web admin interface
  python controller.py web 10.10.100.254 --user admin --password admin

  # Full session dump
  python controller.py dump 10.10.100.254 --save session.json
        """)
    parser.add_argument('--port', type=int, default=AT_COMMAND_PORT,
                       help=f'AT command port (default: {AT_COMMAND_PORT})')

    subparsers = parser.add_subparsers(dest='command', required=True)

    # info
    p_info = subparsers.add_parser('info', help='Get all inverter info')
    p_info.add_argument('target', help='Inverter IP')
    p_info.add_argument('--save', help='Save session log')

    # discover
    p_disc = subparsers.add_parser('discover', help='Find inverters on network')
    p_disc.add_argument('--timeout', type=float, default=5.0)

    # setwifi
    p_set = subparsers.add_parser('setwifi', help='Configure WiFi')
    p_set.add_argument('target', help='Inverter IP')
    p_set.add_argument('--ssid', required=True)
    p_set.add_argument('--password', required=True)
    p_set.add_argument('--encryption', default='WPA2PSK')
    p_set.add_argument('--auth', default='AES')
    p_set.add_argument('--save', help='Save session log')

    # inverter-data
    p_data = subparsers.add_parser('inverter-data', help='Read inverter telemetry')
    p_data.add_argument('target', help='Inverter IP')
    p_data.add_argument('--save', help='Save session log')

    # at
    p_at = subparsers.add_parser('at', help='Send AT commands')
    p_at.add_argument('target', help='Inverter IP')
    p_at.add_argument('--cmd', action='append', required=True, dest='commands',
                    help='AT command(s) to send')
    p_at.add_argument('--save', help='Save session log')

    # dump
    p_dump = subparsers.add_parser('dump', help='Full session dump')
    p_dump.add_argument('target', help='Inverter IP')
    p_dump.add_argument('--save', help='Save session log')

    # web
    p_web = subparsers.add_parser('web', help='Query web admin interface')
    p_web.add_argument('target', help='Inverter IP')
    p_web.add_argument('--user', default='admin')
    p_web.add_argument('--password', default='admin')

    args = parser.parse_args()

    handlers = {
        'info': cmd_info,
        'discover': cmd_discover,
        'setwifi': cmd_setwifi,
        'inverter-data': cmd_inverter_data,
        'at': cmd_at,
        'dump': cmd_dump,
        'web': cmd_web,
    }

    if args.command in handlers:
        handlers[args.command](args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
