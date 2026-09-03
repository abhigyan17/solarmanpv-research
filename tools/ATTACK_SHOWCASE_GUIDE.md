# 🎯 Attack Showcase Guide - SolarmanPV IoT Security Lab

**Complete guide to showcasing the ACTUAL attack in 4 different ways.**

---

## 🚀 QUICK START (5 minutes)

### Option 1: Standalone with Web Dashboard (EASIEST)

This is the quickest way to see the attack in action.

**Step 1:** Start the platform

```bash
cd "D:\Browsers_Downloads\Invergy_Inverter_Firmware_Analysis\tools"
python virtual_attack_platform.py --start --dashboard
```

**Step 2:** Open the web dashboard

```
http://127.0.0.1:8080
```

**Step 3:** Click attack buttons

- 🔋 **Spoof SOC** - Battery overcharge attack (most dangerous)
- ⚡ **Modify Voltage** - Voltage tampering
- ☠️ **Grid Injection** - Utility worker electrocution risk
- 💥 **Inject Fault** - Force inverter shutdown
- 🚫 **Denial of Service** - Block all BMS data

You will see:
- Terminal showing real attack steps
- Web dashboard with live stats
- Wireshark-compatible traffic capture

---

## 🎓 DETAILED WALKTHROUGH (with Wireshark)

### Prerequisites

- Wireshark installed (free download: https://www.wireshark.org/)
- For Windows: Npcap (comes with Wireshark installer)
- The attack platform running (see Quick Start)

### Setup Layout

```
┌─────────────────────────┬─────────────────────────┐
│                         │                         │
│   WIRESHARK             │   WEB DASHBOARD         │
│   (Real-time packets)   │   (Attack controls)     │
│                         │                         │
├─────────────────────────┴─────────────────────────┤
│                                                   │
│   TERMINAL (Platform logs)                        │
│                                                   │
└───────────────────────────────────────────────────┘
```

### Step 1: Start the Platform

```bash
python virtual_attack_platform.py --start
```

You should see:
```
══════════════════════════════════════════════════
  COMPONENTS RUNNING:
    ✓ BMS Emulator (Port 5020) - Realistic battery
    ✓ Modbus MITM Proxy (Port 5021) - Intercept traffic
    ✓ Virtual Inverter - Polls BMS every 5s
    ✓ V5 Protocol Proxy (Port 10001) - Cloud traffic
    ✓ Packet Capture → attack_capture.pcap
══════════════════════════════════════════════════
```

### Step 2: Configure Wireshark

1. **Launch Wireshark**
2. **Double-click your interface:**
   - Linux/Mac: "Loopback: lo"
   - Windows: "Adapter for loopback traffic capture" (Npcap)
3. **Set display filter to:**
   ```
   tcp.port == 5021 or tcp.port == 10001
   ```
4. **Click Start**

**You'll see packets flowing:**
- Every 5 seconds: Inverter polls BMS via Modbus RTU
- Every cycle: V5 frames going to "cloud" (actually to your proxy)

### Step 3: Observe Normal Operation

Looking at Wireshark, you'll see Modbus requests like:
```
01 03 00 E6 00 01 XX XX    ← Read register 230 (SOC)
```

And responses:
```
01 03 02 01 6E XX XX    ← Response: SOC = 95% (0x016E)
```

### Step 4: Launch the Attack!

**In your terminal, type:**
```
attack> 1
```

This selects the **SOC Spoofing Attack**.

**What happens in Wireshark:**

Before attack:
```
Frame: 01 03 02 01 6E XX XX    ← SOC = 95
```

After attack (within 1 second):
```
Frame: 01 03 02 00 3C XX XX    ← SOC = 60 (SPOOFED!)
```

**To see this clearly:**
1. Right-click the Modbus response packet
2. Select "Follow → TCP Stream"
3. Look for the SOC bytes changing in real-time

### Step 5: Watch the Consequences

In your terminal, you'll see:
```
CYCLE 1/5
  REAL Battery State:
    Voltage:  50.4V (NEAR FULL!)
    SOC:      95.0%

  ATTACK: Spoofing SOC = 60%
    Real SOC: 95% → Spoofed SOC: 60%

  INVERTER MISLED:
    Inverter believes SOC = 60.0%
    Therefore, it CONTINUES CHARGING
    But real battery is at 95%!

  [Battery] Voltage rising... 52.0V
  [Battery] Voltage rising... 54.0V
  ⚠⚠⚠ CRITICAL: THERMAL RUNAWAY INITIATED ⚠⚠⚠
  ⚠⚠⚠ BATTERY FIRE IMMINENT ⚠⚠⚠
```

That's the attack in action!

---

## 🕵️ WITH BURPSUITE (Cloud/API Traffic)

### Prerequisites

- BurpSuite Community (free: https://portswigger.net/burp/communitydownload)
- A SolarmanPV web/app login (optional, for testing API)

### Step 1: Start the Platform

```bash
python virtual_attack_platform.py --start
```

### Step 2: Configure BurpSuite

1. **Open Burp Suite Community**
2. **Go to:** Proxy → Options
3. **Add a new proxy listener:**
   - Address: 127.0.0.1
   - Port: 8081
   - Enable "Redirect to host" → 127.0.0.1:10001
4. **In your browser, configure proxy:**
   - HTTP Proxy: 127.0.0.1:8081
   - Apply to all protocols

### Step 3: Configure the V5 Proxy to Forward via Burp

When you set the inverter to point at Burp's listener (127.0.0.1:8081), Burp will forward it to the V5 proxy (127.0.0.1:10001).

### Step 4: Capture Cloud Traffic

1. **In Burp:** Proxy → Intercept → Open browser
2. **Visit:** https://homeappapi.solarmanpv.com (or your local dashboard)
3. **Login** with your SolarmanPV account
4. **Watch HTTP history in Burp Suite:**
   - GET /oauth2-s/oauth/token
   - GET /device-s/device/product-device-list
   - GET /device-s/diy/currentData/getById

### Step 5: Modify Response Data

1. In Burp, find a real-time data response
2. Forward it to "Response to this request"
3. **Modify the JSON response:**
   ```json
   {"soc": "95", "voltage": "540", ...}
   ```
4. **Change to:**
   ```json
   {"soc": "60", "voltage": "480", ...}
   ```
5. Forward the modified response
6. The app displays the fake values as if they're real

---

## 🎬 RECORDING GUIDE (For Video Demonstrations)

### Optimal Screen Layout

```
┌─────────────────────────┬─────────────────────────┐
│                         │                         │
│   WIRESHARK             │   WEB DASHBOARD         │
│   (Top-Left)            │   (Top-Right)           │
│                         │                         │
├─────────────────────────┴─────────────────────────┤
│                                                   │
│   TERMINAL (Bottom, full width)                  │
│                                                   │
└───────────────────────────────────────────────────┘
```

### Recording Timeline (3 minutes)

| Time | Action |
|------|--------|
| 0:00 | Terminal showing platform startup |
| 0:30 | Wireshark showing initial BMS polls (SOC=95%) |
| 1:00 | Click "Spoof SOC" button on dashboard |
| 1:05 | Wireshark shows SOC value changing in packet |
| 1:30 | Battery overcharges (voltage rises past 54V) |
| 2:00 | Trigger fire alarm warning |
| 2:30 | Show consequences for all stakeholders |

### Free Recording Tools

| Platform | Tool |
|----------|------|
| Windows | Built-in Game Bar (Win + G) |
| macOS | QuickTime Player → New Screen Recording |
| Linux | SimpleScreenRecorder or OBS Studio |
| Cross-platform | OBS Studio (recommended) |

### Tips for Quality Recording

- Record at 1080p minimum
- Use a microphone to narrate
- Zoom in on packet details
- Show both Wireshark AND terminal simultaneously
- Use captions or labels for attack steps
- Add a 5-second pause at the end for emphasis

---

## 🧪 TESTING WITH REAL HARDWARE (Optional)

If you have a physical Invergy inverter and want to demonstrate the attack against the actual device:

**Required Hardware:**
- USB-to-RS485 adapter: $15 (FTDI FT232 or CH340 chip)
- Computer with the platform running
- Physical access to the inverter's RS-485 bus
- 30 minutes for setup

**Steps:**

1. **Identify the RS-485 wires** in the inverter (usually labeled A+/B-)
2. **Connect the USB-to-RS485 adapter** to those wires
3. **Modify the platform to use the real COM port:**
   ```python
   # In virtual_attack_platform.py, change:
   self.modbus_proxy = ModbusMITMProxy(
       listen_port=5021,
       target_host='',  # Use real COM port instead
       target_port=0
   )
   ```
4. **The same Modbus proxy code** works against the real inverter

**⚠️ SAFETY WARNING:**
- Only do this in a controlled environment
- Have fire safety equipment ready
- Do NOT do this on a battery you cannot afford to lose
- Document everything for responsible disclosure

---

## 📊 UNDERSTANDING THE PACKETS YOU SEE

### Modbus RTU Frames (Port 5021)

```
READ REQUEST (Inverter → BMS):
01 03 00 E6 00 01 [CRC]
│  │  └────┘ └─┘
│  │  Reg=230  Count=1
│  Func=0x03 (Read Holding Registers)
Slave=1

READ RESPONSE (BMS → Inverter):
01 03 02 01 6E [CRC]
│  │  │  └────┘
│  │  │  Value=0x016E = 366 = 95% SOC
│  │  Byte count=2
Func=0x03 (Response)
```

### V5 Protocol Frames (Port 10001)

```
V5 FRAME:
68 00 1D <serial 16B> 46 01 00 <payload> [CRC] 16
│  │  │              │  └─┘  │        │      │
│  │  │              │  Seq=1 │        │      End marker
│  │  │              Ctrl=0x46       Payload End
│  │  │              (REALTIME_DATA)
│  │  Serial number
Len=29 (big-endian)
Start marker=0x68
```

---

## 🎯 ATTACK DEMONSTRATION CHECKLIST

Before showing this attack to anyone (academic committee, vendor, conference):

- [ ] Wireshark showing real packet capture
- [ ] Terminal showing attack steps clearly
- [ ] Battery state visible (SOC, voltage, temperature)
- [ ] Attacker decision logic explained
- [ ] Impact shown (fire risk, electrocution, etc.)
- [ ] Industry comparison (Tesla/Enphase vs Invergy)
- [ ] Remediation recommendations discussed
- [ ] Responsible disclosure reminder

---

## 🐛 TROUBLESHOOTING

### "Can't capture on loopback"

**Windows:** Install Npcap (comes with Wireshark installer)
**Linux:** Run Wireshark as root or with sudo
**macOS:** Use ChmodBPF or run as root

### "No packets showing"

Make sure:
1. The platform is fully started (all components ready)
2. The display filter is exactly `tcp.port == 5021 or tcp.port == 10001`
3. You're capturing on the **loopback** interface
4. Try removing the filter first to see if any traffic is captured

### "BurpSuite not intercepting"

1. Make sure your browser/system proxy is set to 127.0.0.1:8081
2. Check Burp's "Proxy → Intercept" is enabled
3. For HTTPS, export Burp's CA certificate and install it in your browser

### "Attack not working"

1. Make sure you typed `1` (or the correct attack number)
2. Check that the dashboard/terminal shows "Override set"
3. Look at Wireshark - the response packet should have a different SOC value

---

## 📚 RELATED FILES

- `tools/virtual_attack_platform.py` - Main attack platform (1324 lines)
- `tools/inverter_bms_emulator.py` - Standalone attack simulator (983 lines)
- `attack_capture.pcap` - Captured packets (saved during demos)
- `attack_platform.log` - Event log

---

## 🎓 ACADEMIC SUBMISSION SUPPORT

For your IEEE paper submission, this tool provides:

- **Real attack execution** (not just simulation)
- **Packet-level evidence** (Wireshark captures)
- **Reproducible demonstrations** (anyone can run it)
- **Visual proof** (videos, screenshots)
- **Quantitative metrics** (frame counts, response times)

Combine this with:
1. The IEEE-formatted manuscript (in `SolarmanPV_Protocol_Manuscript.pdf`)
2. The static analysis report (`ANALYSIS_REPORT.md`)
3. The captured pcap files

= A complete, peer-review-ready research package.

---

**Questions? Issues? Found something interesting?**

The platform logs everything to `attack_platform.log` for debugging. Check there first.
