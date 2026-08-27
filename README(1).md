# 🛡️ Network Intrusion Detection System Using Snort 3

A basic **Network Intrusion Detection System (NIDS)** built using **Snort 3 on Kali Linux**. The project continuously monitors network traffic, applies custom detection rules, generates security alerts, stores logs, and demonstrates basic response mechanisms for suspicious traffic.

---

## 📌 Project Overview

The objective of this project is to implement a network-based intrusion detection system capable of identifying potentially suspicious or malicious network activity.

The system uses **Snort 3** to inspect network traffic and compare packets against custom rules. When a rule matches, Snort generates an alert and records the event in the configured log directory.

### Task Requirements Covered

- ✅ Set up a network-based intrusion detection system using Snort.
- ✅ Configure rules and alerts to detect suspicious activity.
- ✅ Continuously monitor network traffic for potential threats.
- ✅ Implement response mechanisms for detected intrusions.
- ✅ Generate and store security logs.
- ✅ Demonstrate IDS operation in a controlled lab environment.

---

## 🏗️ Architecture

```text
                    ┌──────────────────────┐
                    │   Network / LAN      │
                    └──────────┬───────────┘
                               │
                               ▼
                    ┌──────────────────────┐
                    │      Kali Linux      │
                    │       Snort 3        │
                    └──────────┬───────────┘
                               │
                         Packet Inspection
                               │
                               ▼
                    ┌──────────────────────┐
                    │   Custom Snort Rules │
                    └──────────┬───────────┘
                               │
                     Rule Match / Detection
                               │
                               ▼
                    ┌──────────────────────┐
                    │    Security Alert    │
                    └──────────┬───────────┘
                               │
                    ┌──────────┴───────────┐
                    ▼                      ▼
              ┌───────────┐          ┌───────────┐
              │   Logs    │          │ Response  │
              │ / Alerts  │          │ Alert/Drop│
              └───────────┘          └───────────┘
```

---

## 🔄 Workflow

```text
Network Traffic
      ↓
Snort 3 Packet Capture
      ↓
Traffic Inspection
      ↓
Custom Rule Matching
      ↓
┌───────────────┐
│ Rule Matched? │
└───────┬───────┘
        │
   ┌────┴────┐
   │         │
  YES        NO
   │         │
   ▼         ▼
 ALERT     Continue
   │        Monitoring
   ▼
Log Event
   │
   ▼
Response
(Alert / Drop / Block)
```

---

## 🧰 Technologies and Tools

| Component | Technology |
|---|---|
| Operating System | Kali Linux |
| IDS | Snort 3 |
| Configuration | Lua |
| Detection Rules | Snort Rule Language |
| Packet Capture | Snort / LibDAQ |
| Testing Tools | Ping, Netcat, Curl |
| Logging | Snort Fast / JSON Alerts |
| Network | Local LAN / Controlled Lab |

---

## 📂 Project Structure

```text
snort-project/
│
├── rules/
│   └── local.rules
│
├── logs/
│   └── Snort alert and log files
│
└── README.md
```

Snort's main configuration is normally located at:

```text
/etc/snort/snort.lua
```

---

## ⚙️ Installation

### 1. Check Snort Installation

```bash
snort -V
```

Check the executable:

```bash
which snort
```

---

### 2. Identify Network Interface

```bash
ip -br addr
```

Example:

```text
lo       UNKNOWN   127.0.0.1/8
wlan0    UP        192.168.1.20/24
```

In this example, the network interface is:

```text
wlan0
```

Use your actual interface name.

---

### 3. Identify the Network

```bash
ip route
```

Example:

```text
default via 192.168.1.1 dev wlan0
192.168.1.0/24 dev wlan0
```

Therefore:

```text
HOME_NET = 192.168.1.0/24
```

---

## ⚙️ Snort Configuration

Open the Snort configuration:

```bash
sudo nano /etc/snort/snort.lua
```

Set `HOME_NET` according to your own lab network.

Example:

```lua
HOME_NET = '192.168.1.0/24'
```

> **Important:** Do not blindly copy the example network. Use the network shown by your own `ip route` command.

---

## 📝 Custom Detection Rules

Create the local rules file:

```bash
mkdir -p ~/snort-project/rules
nano ~/snort-project/rules/local.rules
```

Example rules:

```text
alert icmp any any -> $HOME_NET any (
    msg:"LOCAL-IDS ICMP Ping Detected";
    sid:1000001;
    rev:1;
)

alert tcp any any -> $HOME_NET any (
    flags:S;
    msg:"LOCAL-IDS TCP SYN Connection Attempt";
    sid:1000002;
    rev:1;
)

alert tcp any any -> $HOME_NET 22 (
    msg:"LOCAL-IDS SSH Connection Attempt";
    sid:1000003;
    rev:1;
)

alert tcp any any -> $HOME_NET 80 (
    msg:"LOCAL-IDS HTTP Connection Detected";
    sid:1000004;
    rev:1;
)

alert tcp any any -> $HOME_NET 80 (
    flow:to_server;
    content:"../";
    msg:"LOCAL-IDS Possible Directory Traversal Attempt";
    sid:1000005;
    rev:1;
)

alert tcp any any -> $HOME_NET 80 (
    flow:to_server;
    content:"UNION";
    nocase;
    msg:"LOCAL-IDS Possible SQL Injection Pattern";
    sid:1000006;
    rev:1;
)

alert tcp any any -> $HOME_NET 80 (
    flow:to_server;
    content:"<script";
    nocase;
    msg:"LOCAL-IDS Possible XSS Attempt";
    sid:1000007;
    rev:1;
)

alert tcp any any -> $HOME_NET 23 (
    msg:"LOCAL-IDS Telnet Connection Attempt";
    sid:1000008;
    rev:1;
)

alert tcp any any -> $HOME_NET 21 (
    msg:"LOCAL-IDS FTP Connection Attempt";
    sid:1000009;
    rev:1;
)

alert udp any any -> $HOME_NET 53 (
    msg:"LOCAL-IDS DNS Request Detected";
    sid:1000010;
    rev:1;
)
```

---

## 🧪 Validate the Configuration

Before starting live monitoring, validate the Snort configuration and rules:

```bash
sudo snort \
-c /etc/snort/snort.lua \
-R ~/snort-project/rules/local.rules \
-T
```

A successful validation indicates that the configuration can be loaded without configuration/rule errors.

---

## 🚀 Start Snort IDS

Replace `wlan0` with your actual network interface:

```bash
sudo snort \
-c /etc/snort/snort.lua \
-R ~/snort-project/rules/local.rules \
-i wlan0 \
-A alert_fast \
-l ~/snort-project/logs
```

Snort will now inspect traffic on the selected interface and generate alerts when traffic matches the configured rules.

---

## 🔎 Testing the IDS

### Test 1 — ICMP Detection

Find the IP address of the Snort machine:

```bash
ip addr
```

From another machine in your controlled lab:

```bash
ping <KALI-IP>
```

Expected alert:

```text
LOCAL-IDS ICMP Ping Detected
```

---

### Test 2 — SSH Detection

From a lab machine:

```bash
nc -vz <KALI-IP> 22
```

Expected alert:

```text
LOCAL-IDS SSH Connection Attempt
```

---

### Test 3 — HTTP Detection

If a test web service is available on the monitored host:

```bash
curl http://<KALI-IP>
```

Expected alert:

```text
LOCAL-IDS HTTP Connection Detected
```

---

## 📊 Alert Logging

Create the log directory:

```bash
mkdir -p ~/snort-project/logs
```

View generated files:

```bash
ls -lah ~/snort-project/logs
```

For a more structured format, Snort can be run with JSON alert output:

```bash
sudo snort \
-c /etc/snort/snort.lua \
-R ~/snort-project/rules/local.rules \
-i wlan0 \
-A alert_json \
-l ~/snort-project/logs
```

JSON logs can be useful for integrating Snort with a Python-based dashboard, SIEM, or SOC monitoring interface.

---

## 🚨 Response Mechanism

The project demonstrates two response levels.

### 1. Alert-Based Response

The default IDS response is:

```text
Suspicious Traffic
       ↓
   Snort Rule
       ↓
      ALERT
       ↓
   Event Logged
```

This is recommended for initial testing because it detects suspicious traffic without intentionally disrupting the network.

### 2. Drop / Block Response

Snort also supports response actions such as `drop` and `block`.

Example for a controlled lab rule:

```text
drop tcp any any -> $HOME_NET 23 (
    msg:"LOCAL-IPS Telnet Connection Blocked";
    sid:1000011;
    rev:1;
)
```

This should only be tested in an isolated environment where you have authorization to block traffic.

---

## 📈 Detection Examples

| Detection | Protocol | Example Alert |
|---|---|---|
| ICMP Ping | ICMP | ICMP Ping Detected |
| TCP SYN | TCP | TCP SYN Connection Attempt |
| SSH | TCP/22 | SSH Connection Attempt |
| HTTP | TCP/80 | HTTP Connection Detected |
| Directory Traversal Pattern | HTTP | Possible Directory Traversal |
| SQL Injection Pattern | HTTP | Possible SQL Injection |
| XSS Pattern | HTTP | Possible XSS Attempt |
| Telnet | TCP/23 | Telnet Connection Attempt |
| FTP | TCP/21 | FTP Connection Attempt |
| DNS | UDP/53 | DNS Request Detected |

---

## 🎯 Project Objectives

The project demonstrates the following cybersecurity concepts:

- Network traffic monitoring
- Intrusion detection
- Signature-based detection
- Custom Snort rules
- Security alert generation
- Event logging
- Network protocol monitoring
- Basic incident response
- IDS vs IPS concepts
- SOC-style security monitoring

---

## 🔐 Security and Ethical Usage

This project should be used only on:

- Your own computer
- Your own virtual machines
- An authorized lab network
- Systems where you have explicit permission to monitor

Do not use the detection or blocking configuration to interfere with networks or systems that you do not own or have permission to test.

---

## 🧪 Recommended Lab Setup

A simple virtual lab can contain:

```text
┌─────────────────────┐
│   Attacker/Test VM  │
│      Kali Linux     │
└──────────┬──────────┘
           │
       Host-Only /
       Internal LAN
           │
           ▼
┌─────────────────────┐
│     Target VM       │
│ Web/SSH Test Server │
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│     Snort 3 IDS     │
│     Monitoring      │
└─────────────────────┘
```

For safer testing, keep the attack/test traffic inside an isolated virtual network.

---

## 📋 Project Demonstration

A recommended demonstration sequence is:

```text
1. Show Snort version
        ↓
2. Show network interface
        ↓
3. Show HOME_NET
        ↓
4. Show custom rules
        ↓
5. Validate Snort configuration
        ↓
6. Start Snort
        ↓
7. Generate controlled test traffic
        ↓
8. Show Snort alerts
        ↓
9. Show log files
        ↓
10. Demonstrate alert/drop response
```

---

## 🖥️ Future Enhancements

The project can be extended into a SOC-style monitoring platform by adding:

- 🖥️ Python/Tkinter dashboard
- 🔴 Critical/High/Medium/Low severity
- 📊 Real-time alert counters
- 🌐 Source and destination IP visualization
- 📡 Protocol statistics
- 🔎 Alert filtering and searching
- 📁 JSON log parser
- 📈 Traffic statistics
- 🔔 Desktop notifications
- 📝 Incident notes
- 🚫 Automated IP blocking in an isolated lab
- 📤 SIEM integration
- 📊 Historical alert charts

---

## 📚 Learning Outcomes

After completing this project, you should understand:

1. How a network-based IDS monitors traffic.
2. How Snort processes packets.
3. How Snort rules identify suspicious traffic.
4. How alerts are generated and logged.
5. The difference between IDS alerting and IPS blocking.
6. How to perform controlled security testing.
7. How IDS alerts can be integrated into a SOC dashboard.

---

## 👨‍💻 Project Type

**Cybersecurity / Network Security / Intrusion Detection**

**Level:** Beginner to Intermediate

**Platform:** Kali Linux

**Primary Tool:** Snort 3

---

## ⭐ Conclusion

This project implements a basic **Network Intrusion Detection System using Snort 3**. It monitors network traffic, applies custom detection rules, generates alerts for suspicious activity, stores security events, and demonstrates basic response mechanisms.

The project provides a practical foundation for learning **network security monitoring, intrusion detection, Snort rule creation, security alert analysis, and SOC operations**.

---

## 📜 License

This project is intended for **educational and authorized security-testing purposes only**.
