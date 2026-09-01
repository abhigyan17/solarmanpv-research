#!/usr/bin/env python3
"""
Interactive Inverter + BMS Emulator with Attack Showcase

This tool emulates:
1. The Inverter (master) - reads BMS data via Modbus RTU every 60s
2. The BMS (slave) - responds with battery telemetry
3. The Cloud Connection - uploads data via V5 protocol

You can launch ATTACK SCENARIOS to demonstrate the security vulnerabilities:
- Battery Overcharge Attack (spoof SOC to cause thermal runaway)
- Grid Injection Attack (dangerous during blackouts)
- Man-in-the-Middle (intercept and modify)

Usage:
    python inverter_bms_emulator.py                    # Interactive mode
    python inverter_bms_emulator.py --demo battery      # Demo battery attack
    python inverter_bms_emulator.py --demo grid        # Demo grid injection
    python inverter_bms_emulator.py --demo mitm        # Demo MITM
    python inverter_bms_emulator.py --all              # Run all demos
"""

import socket
import struct
import time
import threading
import json
import os
import sys
import argparse
from datetime import datetime
from collections import deque
import random

# ============================================================================
# COLORS FOR TERMINAL OUTPUT
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
    WHITE = '\033[97m'
    BG_RED = '\033[101m'
    BG_GREEN = '\033[102m'
    BG_YELLOW = '\033[103m'

def c(text, color):
    return f"{color}{text}{Colors.RESET}"

def cprint(text, color):
    print(c(text, color))

def header(text):
    print()
    print(c("=" * 70, Colors.CYAN))
    print(c(f"  {text}", Colors.CYAN + Colors.BOLD))
    print(c("=" * 70, Colors.CYAN))

def subsection(text):
    print()
    print(c(f"--- {text} ---", Colors.YELLOW))


# ============================================================================
# MODBUS CRC-16 (Used for BMS communication)
# ============================================================================
def modbus_crc16(data: bytes) -> bytes:
    """Calculate Modbus CRC-16 (polynomial 0xA001)"""
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
# V5 CRC-16 (Same Modbus CRC used for V5 cloud protocol)
# ============================================================================
def v5_crc16(data: bytes) -> bytes:
    """V5 protocol uses Modbus CRC-16"""
    return modbus_crc16(data)


# ============================================================================
# V5 FRAME BUILDER (SolarmanPV Cloud Protocol)
# ============================================================================
class V5Frame:
    """Build and parse V5 protocol frames for SolarmanPV cloud"""

    # Control codes
    CONNECT = 0x10
    AUTH = 0x12
    HEARTBEAT = 0x14
    READ = 0x40
    REALTIME = 0x46
    ALARM = 0x48

    @staticmethod
    def build(serial: str, ctrl: int, payload: bytes, seq: int = 1) -> bytes:
        """Build a complete V5 frame"""
        # Serial number padded to 16 bytes
        serial_padded = serial.encode('ascii').ljust(16, b'\x00')

        # Frame body: serial + ctrl + seq + payload
        body = serial_padded + bytes([ctrl]) + struct.pack('<H', seq) + payload

        # Length (big-endian, size of body)
        length = struct.pack('>H', len(body))

        # CRC-16 over body (little-endian)
        crc = v5_crc16(body)

        # Complete frame: 0x68 + length + body + crc + 0x16
        frame = b'\x68' + length + body + crc + b'\x16'
        return frame

    @staticmethod
    def parse(frame: bytes) -> dict:
        """Parse a V5 frame"""
        if len(frame) < 21 or frame[0] != 0x68 or frame[-1] != 0x16:
            return None

        length = struct.unpack('>H', frame[1:3])[0]
        body = frame[3:3+length]
        crc = frame[3+length:3+length+2]

        if len(body) < 19:
            return None

        serial = body[:16].rstrip(b'\x00').decode('ascii', errors='replace')
        ctrl = body[16]
        seq = struct.unpack('<H', body[17:19])[0]
        payload = body[19:]

        return {
            'serial': serial,
            'ctrl': ctrl,
            'seq': seq,
            'payload': payload,
            'crc_valid': v5_crc16(body) == crc
        }


# ============================================================================
# REALISTIC BATTERY SIMULATION
# ============================================================================
class Battery:
    """Simulates a real lithium battery pack"""

    def __init__(self, capacity_kwh=10.0, voltage_nominal=48.0):
        self.capacity_kwh = capacity_kwh
        self.voltage_nominal = voltage_nominal
        self.voltage = voltage_nominal  # Current voltage
        self.current = 0.0  # Positive = charging, negative = discharging
        self.soc = 80.0  # Start at 80%
        self.temperature = 25.0  # Celsius
        self.cycles = 100
        self.soh = 95.0  # State of Health
        self.max_voltage = voltage_nominal * 1.05  # 50.4V for 48V pack
        self.min_voltage = voltage_nominal * 0.95  # 45.6V for 48V pack

        # Charge rate (per second of real time)
        self.charge_rate = 0.1  # % per second when charging

        # Status flags
        self.cells_balanced = True
        self.bms_comm_error = False

    def charge(self, power_watts):
        """Charge the battery with given power"""
        if self.soc >= 100:
            return False
        # Increase SOC based on power
        energy_added_wh = power_watts * (1/3600)  # 1 second
        soc_increase = (energy_added_wh / (self.capacity_kwh * 1000)) * 100
        self.soc = min(100, self.soc + soc_increase)

        # Update voltage based on SOC (simplified curve)
        self.voltage = self.min_voltage + (self.max_voltage - self.min_voltage) * (self.soc / 100)

        # Update current (positive = charging)
        if power_watts > 0:
            self.current = power_watts / self.voltage

        # Temperature rises slightly when charging
        if self.soc > 80:
            self.temperature += 0.05
        return True

    def discharge(self, power_watts):
        """Discharge the battery with given power"""
        if self.soc <= 0:
            return False
        # Decrease SOC
        energy_removed_wh = power_watts * (1/3600)
        soc_decrease = (energy_removed_wh / (self.capacity_kwh * 1000)) * 100
        self.soc = max(0, self.soc - soc_decrease)

        # Update voltage
        self.voltage = self.min_voltage + (self.max_voltage - self.min_voltage) * (self.soc / 100)
        self.current = -power_watts / self.voltage  # Negative = discharging
        return True

    def get_register_value(self, register):
        """Get Modbus register value"""
        if register == 24:  # Voltage (0.1V units)
            return int(self.voltage * 10)
        elif register == 229:  # Current (0.1A units, signed)
            return int(self.current * 10)
        elif register == 230:  # SOC (%)
            return int(self.soc)
        elif register == 336:  # Temperature (0.1°C)
            return int(self.temperature * 10)
        elif register == 19:  # Status flags
            return 0x0001 if self.cells_balanced else 0x0000
        elif register == 417:  # Pack count
            return 1
        return 0

    def get_status(self):
        """Get human-readable status"""
        return {
            'voltage': f"{self.voltage:.2f}V",
            'current': f"{abs(self.current):.2f}A ({'CHG' if self.current > 0 else 'DIS'})",
            'soc': f"{self.soc:.1f}%",
            'temperature': f"{self.temperature:.1f}°C",
            'soh': f"{self.soh:.0f}%"
        }


# ============================================================================
# BMS EMULATOR (Realistic Modbus RTU Server)
# ============================================================================
class BMSEmulator:
    """Modbus RTU server emulating a battery management system"""

    def __init__(self, port=5020, host='127.0.0.1'):
        self.port = port
        self.host = host
        self.battery = Battery()
        self.running = False
        self.server_socket = None
        self.client_socket = None
        self.permission_to_run = True  # Can be flipped by attack
        self.log = deque(maxlen=50)

        # Registers (real BMS values from firmware analysis)
        self.registers = {}
        self.update_registers()

        # Start TCP server in background thread
        self.server_thread = None
        self.start_server()

    def update_registers(self):
        """Update Modbus registers from battery state"""
        if not self.permission_to_run:
            return  # Attack disabled BMS

        self.registers = {
            24: self.battery.get_register_value(24),
            229: self.battery.get_register_value(229),
            230: self.battery.get_register_value(230),
            336: self.battery.get_register_value(336),
            19: self.battery.get_register_value(19),
            417: self.battery.get_register_value(417),
        }

    def start_server(self):
        """Start TCP server to accept Modbus RTU connections"""
        def server_loop():
            try:
                self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                self.server_socket.bind((self.host, self.port))
                self.server_socket.listen(1)
                self.server_socket.settimeout(0.5)
                self.running = True

                while self.running:
                    try:
                        client, addr = self.server_socket.accept()
                        self.client_socket = client
                        client.settimeout(5.0)

                        # Handle requests in a loop
                        while self.running:
                            try:
                                data = client.recv(1024)
                                if not data:
                                    break

                                response = self.handle_request(data)
                                if response:
                                    client.send(response)
                            except socket.timeout:
                                break
                            except Exception:
                                break

                        client.close()
                        self.client_socket = None

                    except socket.timeout:
                        continue
                    except Exception:
                        pass

            except Exception as e:
                print(f"  [BMS Server Error] {e}")

        self.server_thread = threading.Thread(target=server_loop, daemon=True)
        self.server_thread.start()
        time.sleep(0.3)  # Give server time to start

    def stop_server(self):
        """Stop the TCP server"""
        self.running = False
        if self.server_socket:
            try:
                self.server_socket.close()
            except:
                pass

    def handle_request(self, request: bytes) -> bytes:
        """Process a Modbus RTU request and return response"""
        if len(request) < 8:
            return b''

        slave_id = request[0]
        func_code = request[1]
        start_reg = struct.unpack('>H', request[2:4])[0]
        reg_count = struct.unpack('>H', request[4:6])[0]

        crc_received = struct.unpack('<H', request[-2:])[0]
        crc_calc = struct.unpack('<H', modbus_crc16(request[:-2]))[0]

        if crc_received != crc_calc:
            self.log.append(f"[{datetime.now().strftime('%H:%M:%S')}] CRC ERROR from slave {slave_id}")
            return b''

        # Function 0x03: Read Holding Registers
        if func_code == 0x03 and slave_id == 1:
            # ALWAYS update from battery state first (unless attack disabled it)
            if self.permission_to_run:
                self.update_registers()
            # If permission_to_run is False, the attacker is controlling the response

            # Check if requested register exists
            valid_regs = [24, 229, 230, 336, 19, 417]
            if start_reg in valid_regs:
                # Build response with all requested registers
                values = []
                for reg in range(start_reg, start_reg + reg_count):
                    if reg in self.registers:
                        values.append(self.registers[reg])
                    else:
                        values.append(0)

                # Response: slave, func, byte_count, [values...]
                response_data = struct.pack('>' + 'H' * len(values), *values)
                byte_count = len(response_data)
                response = bytes([slave_id, func_code, byte_count]) + response_data
                response += modbus_crc16(response)

                self.log.append(f"[{datetime.now().strftime('%H:%M:%S')}] READ reg {start_reg}: {values}")
                return response
            else:
                # Illegal data address exception
                response = bytes([slave_id, 0x83, 0x02])  # Exception, illegal data address
                response += modbus_crc16(response)
                return response

        return b''


# ============================================================================
# INVERTER EMULATOR (Master that polls BMS)
# ============================================================================
class InverterEmulator:
    """Emulates the inverter that polls BMS via Modbus RTU every 60 seconds"""

    def __init__(self, bms_host='127.0.0.1', bms_port=5020):
        self.bms_host = bms_host
        self.bms_port = bms_port
        self.running = False
        self.bms_socket = None
        self.last_data = {}
        self.log = deque(maxlen=100)

        # Cloud connection (V5 protocol)
        self.cloud_serial = "2991141075"  # User's actual serial
        self.cloud_seq = 1
        self.cloud_connected = False
        self.cloud_socket = None

        # Statistics
        self.poll_count = 0
        self.cloud_upload_count = 0
        self.alarm_count = 0

        # Safety state
        self.grid_blackout = False
        self.charging_enabled = True
        self.discharging_enabled = True

    def connect_bms(self):
        """Connect to BMS via TCP (simulating RS-485)"""
        try:
            self.bms_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.bms_socket.settimeout(2.0)
            self.bms_socket.connect((self.bms_host, self.bms_port))
            return True
        except Exception as e:
            self.log.append(f"[{datetime.now().strftime('%H:%M:%S')}] BMS connection failed: {e}")
            return False

    def read_bms_register(self, register):
        """Read a Modbus register from BMS"""
        try:
            if not self.bms_socket:
                if not self.connect_bms():
                    return None

            # Build Modbus RTU request: slave=1, func=0x03, reg, count=1, crc
            request = struct.pack('>BBHH', 1, 0x03, register, 1)
            request += modbus_crc16(request)

            self.bms_socket.send(request)
            response = self.bms_socket.recv(1024)

            if len(response) >= 7:
                # Parse response: slave, func, byte_count, value_hi, value_lo, crc
                byte_count = response[2]
                value = struct.unpack('>H', response[3:5])[0]
                return value

        except Exception as e:
            self.log.append(f"[{datetime.now().strftime('%H:%M:%S')}] BMS read error reg {register}: {e}")
            self.bms_socket = None

        return None

    def read_all_registers(self):
        """Read all BMS registers"""
        registers = {}

        for reg in [24, 229, 230, 336, 19, 417]:
            value = self.read_bms_register(reg)
            if value is not None:
                registers[reg] = value
                time.sleep(0.1)  # Small delay between reads

        self.poll_count += 1
        self.last_data = registers

        # Convert to real units
        return {
            'voltage': registers.get(24, 0) / 10.0,
            'current': self._to_signed(registers.get(229, 0)) / 10.0,
            'soc': registers.get(230, 0),
            'temperature': self._to_signed(registers.get(336, 0)) / 10.0,
            'status': registers.get(19, 0),
            'pack_count': registers.get(417, 0)
        }

    def _to_signed(self, value):
        """Convert unsigned 16-bit to signed"""
        return value - 65536 if value > 32767 else value

    def upload_to_cloud(self, data):
        """Upload data to SolarmanPV cloud via V5 protocol"""
        # Build telemetry payload
        payload = b''
        payload += struct.pack('>H', 0x0001)  # Data type
        payload += b'\x00\x01'  # Flags

        # Add telemetry
        for key, value in [
            ('voltage', int(data['voltage'] * 10)),
            ('current', int(data['current'] * 10)),
            ('soc', int(data['soc'])),
            ('temp', int(data['temperature'] * 10)),
        ]:
            payload += struct.pack('>H', value)

        # Build V5 frame
        frame = V5Frame.build(self.cloud_serial, V5Frame.REALTIME, payload, self.cloud_seq)
        self.cloud_seq += 1

        # Simulate cloud upload (don't actually send)
        self.cloud_upload_count += 1
        self.log.append(f"[{datetime.now().strftime('%H:%M:%S')}] ☁ Cloud: TX {len(frame)}B REALTIME frame")

        return frame

    def display_data(self, data):
        """Display inverter readings"""
        subsection("INVERTER READING (from BMS)")

        voltage = data['voltage']
        soc = data['soc']
        temp = data['temperature']
        current = data['current']

        # Visual battery
        bar_len = 30
        filled = int((soc / 100) * bar_len)
        bar = '█' * filled + '░' * (bar_len - filled)

        # Color based on state
        if soc >= 95:
            soc_color = Colors.RED
            soc_status = "⚠ CRITICAL - NEAR FULL"
        elif soc >= 80:
            soc_color = Colors.YELLOW
            soc_status = "⚡ HIGH"
        elif soc >= 30:
            soc_color = Colors.GREEN
            soc_status = "✓ NORMAL"
        else:
            soc_color = Colors.YELLOW
            soc_status = "⚠ LOW"

        print(f"\n  Battery State:")
        print(f"    SOC:      [{bar}] {soc:5.1f}% {c(soc_status, soc_color)}")
        print(f"    Voltage:  {voltage:6.2f}V")
        print(f"    Current:  {abs(current):6.2f}A {'(Charging)' if current > 0 else '(Discharging)' if current < 0 else '(Idle)'}")
        print(f"    Temp:     {temp:6.1f}°C")

        # Inverter decisions
        print(f"\n  Inverter Decisions:")
        if self.grid_blackout:
            print(f"    {c('⚠ GRID BLACKOUT - Operating in islanded mode', Colors.RED)}")
        else:
            print(f"    Grid Status: {c('CONNECTED', Colors.GREEN)}")

        if self.charging_enabled:
            if soc < 95:
                print(f"    {c('→', Colors.GREEN)} Charging: {c('ENABLED', Colors.GREEN)} (solar power available)")
            else:
                print(f"    {c('→', Colors.YELLOW)} Charging: {c('DISABLED', Colors.YELLOW)} (battery near full)")
        else:
            print(f"    → Charging: {c('DISABLED', Colors.RED)} (system fault)")

    def run_normal_cycle(self):
        """Normal polling cycle"""
        subsection("60-SECOND POLLING CYCLE")

        print(f"  [{datetime.now().strftime('%H:%M:%S')}] Inverter master polls BMS via Modbus RTU...")

        # Read all registers
        data = self.read_all_registers()

        if not data:
            print(f"  {c('✗ Failed to read BMS data', Colors.RED)}")
            return False

        print(f"  {c('✓ BMS data received', Colors.GREEN)}")

        # Display data
        self.display_data(data)

        # Make decisions
        self.make_decisions(data)

        # Upload to cloud
        frame = self.upload_to_cloud(data)
        print(f"\n  {c('→', Colors.CYAN)} Uploaded to SolarmanPV cloud ({len(frame)} bytes)")

        return True

    def make_decisions(self, data):
        """Inverter makes decisions based on BMS data"""
        subsection("INVERTER DECISION LOGIC")

        soc = data['soc']

        # Charge logic
        if soc >= 95:
            print(f"  [{datetime.now().strftime('%H:%M:%S')}] Decision: STOP CHARGING (SOC >= 95%)")
            self.charging_enabled = False
        elif soc < 90:
            if not self.charging_enabled:
                print(f"  [{datetime.now().strftime('%H:%M:%S')}] Decision: RESUME CHARGING (SOC dropped below 90%)")
            self.charging_enabled = True

        # Grid logic
        if self.grid_blackout and soc > 80:
            print(f"  [{datetime.now().strftime('%H:%M:%S')}] {c('Decision: ATTEMPT TO GRID-TIE (high SOC)', Colors.RED)} ⚠ DANGEROUS")


# ============================================================================
# ATTACK SIMULATION TOOLS
# ============================================================================
class AttackSimulator:
    """Simulates various attacks on the BMS communication"""

    def __init__(self, inverter, bms):
        self.inverter = inverter
        self.bms = bms
        self.active_attack = None

    def soc_spoof_attack(self, target_soc=60.0):
        """Spoof SOC value to keep inverter charging past safe limit"""
        header("ATTACK 1: BATTERY OVERCHARGE - SOC SPOOFING")

        cprint("Objective: Cause battery to overcharge by sending false SOC values", Colors.MAGENTA)
        print()

        cprint("Attack Flow:", Colors.YELLOW)
        cprint("  1. Attacker connects between inverter and BMS", Colors.WHITE)
        cprint("  2. Real battery at 95% SOC (near full)", Colors.WHITE)
        cprint("  3. Inverter wants to stop charging (safe behavior)", Colors.WHITE)
        cprint("  4. Attacker spoofs SOC = 60% to make inverter think battery is low", Colors.WHITE)
        cprint("  5. Inverter continues charging past safe limit", Colors.WHITE)
        cprint("  6. Result: THERMAL RUNAWAY → FIRE", Colors.WHITE)

        print()
        cprint("Demonstrating attack with 5 polling cycles...", Colors.CYAN)

        # Save original behavior
        original_register = self.bms.registers.copy()

        for cycle in range(5):
            print(f"\n{'='*70}")
            cprint(f"CYCLE {cycle + 1}/5", Colors.BOLD)
            print('='*70)

            # Show REAL battery state
            print(f"\n  {c('REAL Battery State:', Colors.GREEN)}")
            print(f"    Voltage:    {self.bms.battery.voltage:.2f}V")
            print(f"    SOC:        {self.bms.battery.soc:.1f}% {c('(NEAR FULL!)', Colors.RED) if self.bms.battery.soc > 90 else ''}")
            print(f"    Temperature: {self.bms.battery.temperature:.1f}°C")

            # ATTACK: Spoof SOC to 60%
            spoofed_soc = target_soc
            self.bms.registers[230] = int(spoofed_soc)  # Override SOC register
            self.bms.permission_to_run = False  # Disable real BMS data
            print(f"\n  {c('ATTACK: Spoofing SOC = 60%', Colors.RED)}")
            print(f"    Real SOC: 95% → {c('Spoofed SOC: 60%', Colors.RED + Colors.BOLD)}")

            # Inverter reads the spoofed value
            data = self.inverter.read_all_registers()
            self.inverter.display_data(data)

            # Show what inverter thinks
            if data['soc'] < 90:
                print(f"\n  {c('INVERTER MISLED:', Colors.RED)}")
                print(f"    Inverter believes SOC = {data['soc']:.1f}%")
                print(f"    Therefore, it CONTINUES CHARGING")
                print(f"    But real battery is at 95%!")

            # Actually charge the battery
            if self.bms.battery.soc < 100:
                self.bms.battery.charge(2000)  # 2kW charge
                if self.bms.battery.soc >= 95:
                    # Force overcharge
                    self.bms.battery.soc = 99.5
                    self.bms.battery.temperature += 5
                    self.bms.battery.voltage = 52.0  # Overvoltage!

            time.sleep(1)

        # Final state
        print(f"\n{'='*70}")
        cprint("ATTACK RESULT:", Colors.RED + Colors.BOLD)
        print('='*70)
        print(f"  Real Battery: SOC = {self.bms.battery.soc:.1f}%, Voltage = {self.bms.battery.voltage:.2f}V")
        print(f"  Temperature: {self.bms.battery.temperature:.1f}°C {c('(ELEVATED!)', Colors.RED)}")

        if self.bms.battery.voltage > 51.0:
            print(f"\n  {c('⚠ BATTERY EXCEEDED SAFE VOLTAGE ⚠', Colors.RED + Colors.BOLD)}")
            print(f"  {c('THERMAL RUNAWAY INITIATED', Colors.RED + Colors.BOLD)}")
            print(f"  {c('FIRE RISK: CRITICAL', Colors.RED + Colors.BOLD)}")

        # Restore
        self.bms.permission_to_run = True
        self.bms.registers = original_register

    def grid_injection_attack(self):
        """Demonstrate grid injection during blackout"""
        header("ATTACK 2: GRID INJECTION DURING BLACKOUT")

        cprint("Objective: Cause inverter to energize grid during blackout", Colors.MAGENTA)
        print()

        cprint("Attack Flow:", Colors.YELLOW)
        cprint("  1. Power outage occurs (grid blackout)", Colors.WHITE)
        cprint("  2. Inverter detects outage, disconnects from grid (anti-islanding)", Colors.WHITE)
        cprint("  3. Attacker spoofs high SOC and voltage", Colors.WHITE)
        cprint("  4. Inverter thinks battery is full, tries to feed power to home", Colors.WHITE)
        cprint("  5. Inverter energizes local grid segment", Colors.WHITE)
        cprint("  6. Utility worker arrives, touches 'dead' line", Colors.WHITE)
        cprint("  7. Result: ELECTROCUTION", Colors.WHITE)

        print()
        cprint("Simulating blackout + attack...", Colors.CYAN)

        # Simulate grid blackout
        print(f"\n  [{datetime.now().strftime('%H:%M:%S')}] {c('⚡ GRID BLACKOUT DETECTED', Colors.RED)}")
        self.inverter.grid_blackout = True

        print(f"\n  [{datetime.now().strftime('%H:%M:%S')}] Inverter anti-islanding protection activated")
        print(f"  [{datetime.now().strftime('%H:%M:%S')}] Inverter disconnected from grid")

        # Spoof high SOC
        print(f"\n  {c('ATTACK: Spoofing high SOC to force grid-tie attempt', Colors.RED)}")
        self.bms.registers[230] = 95  # 95%
        self.bms.registers[24] = 540  # 54V
        self.bms.permission_to_run = False

        for cycle in range(3):
            print(f"\n--- Cycle {cycle+1} ---")
            data = self.inverter.read_all_registers()
            self.inverter.display_data(data)

            if data['soc'] > 90:
                print(f"\n  {c('⚠ INVERTER ATTEMPTING GRID-TIE ⚠', Colors.RED + Colors.BOLD)}")
                print(f"  Inverter sees high SOC ({data['soc']:.1f}%) and voltage ({data['voltage']:.1f}V)")
                print(f"  Inverter is trying to backfeed power to the grid")
                print(f"  But the grid is DOWN!")

                print(f"\n  {c('CONSEQUENCE:', Colors.RED + Colors.BOLD)}")
                print(f"  → Local grid segment is now ENERGIZED")
                print(f"  → Utility workers believe line is 'dead'")
                print(f"  → Risk of ELECTROCUTION when they touch the line")

            time.sleep(1)

        # Restore
        self.bms.permission_to_run = True
        self.inverter.grid_blackout = False

    def mitm_attack(self):
        """Demonstrate Man-in-the-Middle attack"""
        header("ATTACK 3: MAN-IN-THE-MIDDLE (MITM)")

        cprint("Objective: Intercept and modify all BMS-Inverter communication", Colors.MAGENTA)
        print()

        cprint("Attack Flow:", Colors.YELLOW)
        cprint("  1. Attacker positions between inverter and BMS", Colors.WHITE)
        cprint("  2. All Modbus traffic flows through attacker", Colors.WHITE)
        cprint("  3. Attacker can READ, MODIFY, or DROP any message", Colors.WHITE)
        cprint("  4. Attacker forges responses with chosen values", Colors.WHITE)
        cprint("  5. Inverter has NO WAY to detect the tampering", Colors.WHITE)

        print()
        cprint("Demonstrating MITM with 4 modified messages...", Colors.CYAN)

        modifications = [
            ("Voltage: 48.5V", "Voltage: 35.0V", "Falsely report LOW voltage → triggers pre-charge circuit"),
            ("SOC: 85%", "SOC: 95%", "Report full battery → inverter stops charging prematurely"),
            ("Temp: 25°C", "Temp: 75°C", "Falsely report HIGH temp → inverter reduces power output"),
            ("Status: OK", "Status: FAULT", "Inject fault condition → inverter shuts down for 'safety'"),
        ]

        for i, (original, modified, impact) in enumerate(modifications, 1):
            print(f"\n{'─'*70}")
            cprint(f"INTERCEPTION {i}/4", Colors.BOLD)
            print('─'*70)

            print(f"\n  {c('Inverter request:', Colors.CYAN)} [Modbus READ]")

            if 'Voltage' in original:
                self.bms.registers[24] = 355  # 35.5V
                display_value = "35.5V"
            elif 'SOC' in original:
                self.bms.registers[230] = 95
                display_value = "95%"
            elif 'Temp' in original:
                self.bms.registers[336] = 280  # 28.0°C → modified to 75.0°C
                display_value = "75.0°C"
            else:
                self.bms.registers[19] = 0xFFFF  # Fault
                display_value = "FAULT (0xFFFF)"

            print(f"  {c('Legitimate BMS response:', Colors.GREEN)} {original}")
            print(f"  {c('MITM modified value:    ', Colors.RED)} {c(modified, Colors.RED + Colors.BOLD)}")
            print(f"  {c('Inverter receives:      ', Colors.MAGENTA)} {c(modified, Colors.RED)}")
            print(f"\n  {c('Impact:', Colors.YELLOW)} {impact}")

            time.sleep(1.5)

        # Restore
        self.bms.permission_to_run = True
        self.bms.update_registers()

        print(f"\n{c('MITM attack complete - all messages were modified without detection', Colors.RED)}")


# ============================================================================
# SIMULATION ORCHESTRATOR
# ============================================================================
class SimulationOrchestrator:
    """Orchestrates the full simulation: Inverter + BMS + Cloud + Attacker"""

    def __init__(self):
        self.bms_port = 5020
        self.bms_host = '127.0.0.1'
        self.bms = None
        self.inverter = None
        self.attacker = None

    def setup(self):
        """Start BMS and inverter"""
        header("INITIALIZING SIMULATION ENVIRONMENT")

        # Start BMS
        print(f"\n  Starting BMS Emulator (port {self.bms_port})...")
        self.bms = BMSEmulator(port=self.bms_port, host=self.bms_host)
        print(f"  {c('✓ BMS started', Colors.GREEN)}")
        print(f"    - RS-485 interface emulated over TCP")
        print(f"    - Modbus RTU protocol")
        print(f"    - Slave address: 1")
        print(f"    - Battery: 10 kWh LiFePO4, 48V nominal")
        print(f"    - Initial state: 80% SOC, 48V, 25°C")

        print(f"\n  Starting Inverter Emulator...")
        self.inverter = InverterEmulator(bms_host=self.bms_host, bms_port=self.bms_port)
        print(f"  {c('✓ Inverter started', Colors.GREEN)}")
        print(f"    - Deye 5406 master controller")
        print(f"    - Polls BMS every 60 seconds")
        print(f"    - Uploads to data1.solarmanpv.com:10000")
        print(f"    - Solarman serial: {self.inverter.cloud_serial}")

        # Connect inverter to BMS
        print(f"\n  Establishing BMS-Inverter connection...")
        if self.inverter.connect_bms():
            print(f"  {c('✓ Connected', Colors.GREEN)}")

        # Setup attacker
        self.attacker = AttackSimulator(self.inverter, self.bms)
        print(f"\n  {c('Attacker Simulator initialized', Colors.MAGENTA)}")
        print(f"    - Connected via RS-485 bus tap")
        print(f"    - No authentication required")
        print(f"    - Can intercept/modify all Modbus traffic")

    def run_normal_operation(self, cycles=2):
        """Run normal inverter-BMS operation"""
        header("NORMAL OPERATION MODE")

        cprint("This is how the system normally operates:", Colors.CYAN)
        cprint("- Inverter polls BMS every 60 seconds", Colors.WHITE)
        cprint("- Inverter makes decisions based on battery state", Colors.WHITE)
        cprint("- Inverter uploads data to SolarmanPV cloud", Colors.WHITE)
        print()

        for cycle in range(cycles):
            self.inverter.run_normal_cycle()
            time.sleep(2)  # Shorten 60s for demo

    def run_demo(self, scenario):
        """Run a specific attack scenario"""
        if scenario == 'battery' or scenario == 'all':
            self.attacker.soc_spoof_attack()
            time.sleep(2)

        if scenario == 'grid' or scenario == 'all':
            self.attacker.grid_injection_attack()
            time.sleep(2)

        if scenario == 'mitm' or scenario == 'all':
            self.attacker.mitm_attack()
            time.sleep(2)

    def interactive_mode(self):
        """Interactive command mode"""
        header("INTERACTIVE MODE")

        cprint("Commands available:", Colors.CYAN)
        cprint("  poll       - Run one polling cycle", Colors.WHITE)
        cprint("  spoofsoc   - Spoof SOC value (attack)", Colors.WHITE)
        cprint("  spoofgrid  - Grid injection attack", Colors.WHITE)
        cprint("  mitm       - Man-in-the-Middle demo", Colors.WHITE)
        cprint("  status     - Show current battery state", Colors.WHITE)
        cprint("  charge     - Force battery to charge", Colors.WHITE)
        cprint("  quit       - Exit", Colors.WHITE)

        while True:
            try:
                cmd = input(f"\n{c('inverter>', Colors.CYAN)} ").strip().lower()

                if cmd == 'poll':
                    self.inverter.run_normal_cycle()
                elif cmd == 'spoofsoc':
                    self.attacker.soc_spoof_attack()
                elif cmd == 'spoofgrid':
                    self.attacker.grid_injection_attack()
                elif cmd == 'mitm':
                    self.attacker.mitm_attack()
                elif cmd == 'status':
                    status = self.bms.battery.get_status()
                    print(f"\n  Battery State:")
                    for k, v in status.items():
                        print(f"    {k}: {v}")
                elif cmd == 'charge':
                    self.bms.battery.charge(2000)
                    print(f"  {c('✓ Charged 2kW for 1 second', Colors.GREEN)}")
                elif cmd in ['quit', 'exit', 'q']:
                    print(f"\n  {c('Goodbye!', Colors.CYAN)}")
                    break
                else:
                    print(f"  {c('Unknown command', Colors.RED)}")

            except KeyboardInterrupt:
                print(f"\n  {c('Interrupted', Colors.YELLOW)}")
                break
            except Exception as e:
                print(f"  {c(f'Error: {e}', Colors.RED)}")

    def cleanup(self):
        """Cleanup"""
        if self.bms:
            self.bms.stop_server()
        if self.inverter and self.inverter.bms_socket:
            self.inverter.bms_socket.close()


# ============================================================================
# MAIN
# ============================================================================
def main():
    parser = argparse.ArgumentParser(description='Interactive Inverter + BMS Emulator')
    parser.add_argument('--demo', choices=['battery', 'grid', 'mitm', 'all'],
                       help='Run attack demonstration')
    parser.add_argument('--interactive', action='store_true',
                       help='Start interactive mode')
    parser.add_argument('--cycles', type=int, default=2,
                       help='Number of normal cycles to run before attacks')

    args = parser.parse_args()

    # Create orchestrator
    orch = SimulationOrchestrator()
    orch.setup()

    if args.interactive:
        orch.interactive_mode()
    elif args.demo:
        orch.run_normal_operation(cycles=args.cycles)
        orch.run_demo(args.demo)
    else:
        # Default: show normal operation then run all demos
        orch.run_normal_operation(cycles=args.cycles)
        orch.run_demo('all')

    orch.cleanup()

    # Final summary
    print()
    print(c("=" * 70, Colors.GREEN))
    cprint("  SIMULATION COMPLETE", Colors.GREEN + Colors.BOLD)
    print(c("=" * 70, Colors.GREEN))
    print()
    cprint("Total polls performed:", Colors.CYAN)
    print(f"  Inverter→BMS polls: {orch.inverter.poll_count}")
    print(f"  Cloud uploads:      {orch.inverter.cloud_upload_count}")
    print(f"  Alarms triggered:   {orch.inverter.alarm_count}")

    print()
    cprint("KEY TAKEAWAYS:", Colors.YELLOW + Colors.BOLD)
    cprint("  1. BMS communication has NO authentication", Colors.WHITE)
    cprint("  2. Any device on RS-485 can spoof battery data", Colors.WHITE)
    cprint("  3. These attacks cost <$50 to execute", Colors.WHITE)
    cprint("  4. Real batteries would catch fire, not just show 99.5% SOC", Colors.WHITE)
    cprint("  5. The inverter has NO WAY to detect the attack", Colors.WHITE)
    print()
    cprint("This is why IoT solar security matters.", Colors.RED + Colors.BOLD)


if __name__ == "__main__":
    main()
