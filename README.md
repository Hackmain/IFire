# IFIRE — AI-Enhanced IDS/IPS Firewall

```
  ██╗███████╗██╗██████╗ ███████╗
  ██║██╔════╝██║██╔══██╗██╔════╝
  ██║█████╗  ██║██████╔╝█████╗
  ██║██╔══╝  ██║██╔══██╗██╔══╝
  ██║██║     ██║██║  ██║███████╗
  ╚═╝╚═╝     ╚═╝╚═╝  ╚═╝╚══════╝
```

**IFIRE** is an open-source Linux network **Intrusion Detection and Prevention System (IDS/IPS)** written in C with a Python AI anomaly-detection engine.

It captures live network traffic via `libpcap`, runs multiple threat detectors in real time, logs structured JSON events, and — in IPS mode — automatically blocks attackers with `iptables`. A companion Python module (Isolation Forest) learns baseline traffic and flags statistical anomalies.

---

## Features

| Category | Details |
|---|---|
| **Protocol analysis** | Ethernet · ARP · IPv4 · ICMP · TCP · UDP · TFTP |
| **Threat detection** | ARP spoofing · Ping flood · Port scan · SYN flood · TCP session tracking · TFTP monitoring |
| **IPS / Firewall** | Auto-block via `iptables` · Whitelist / Blacklist support |
| **AI engine** | Isolation Forest unsupervised anomaly detection on per-IP traffic features |
| **Logging** | JSON-lines structured event log compatible with SIEM / ELK stack |
| **Performance** | Single-threaded C core; multi-detector bitmask flags |

---

## Quick Start

### 1. Build

```sh
# Install libpcap (Debian/Ubuntu)
sudo apt install libpcap-dev

# Build IFIRE
make

# Or with debug symbols
make debug
```

### 2. Run (IDS mode — detection only)

```sh
sudo ./ifire -q -j /tmp/ifire.jsonl
```

### 3. Run (IPS mode — auto-block attackers)

```sh
sudo ./ifire -B \
     -b config/blacklist.txt \
     -W config/whitelist.txt \
     -q -j /tmp/ifire.jsonl
```

### 4. Train AI model on baseline traffic

```sh
# 1. Capture baseline (benign) traffic for a few minutes
sudo ./ifire -q -j /tmp/baseline.jsonl -n 10000

# 2. Install Python dependencies
pip install -r ai/requirements.txt

# 3. Train
python3 ai/ifire_ai.py train /tmp/baseline.jsonl --model-dir ai/models

# 4. Detect anomalies in live log
python3 ai/ifire_ai.py infer /tmp/ifire.jsonl

# 5. Continuous watch
python3 ai/ifire_ai.py watch /tmp/ifire.jsonl --interval 30
```

---

## Usage Reference

```
Usage: ifire [OPTIONS]

  Capture & Detection
    -d <dev>    Network device to capture (default: auto)
    -i <file>   Read packets from pcap file
    -f <bpf>    BPF filter expression (e.g. 'tcp or udp')
    -n <count>  Stop after N packets
    -p          Enable promiscuous mode
    -q          Quiet mode (alerts only)
    -r          Show raw packet bytes

  Logging
    -l <file>   Write captured packets to pcap file
    -j <file>   Write JSON event log to file

  Detection (-s <mode>, use multiple times)
    -s arpspoof   ARP spoofing detection
    -s pingflood  Ping flood detection
    -s portscan   Port scan detection (15 unique ports / 5 s)
    -s synflood   SYN flood detection (100 SYNs, ratio ≥5, 10 s)
    -s tcptrack   TCP session tracking
    -s tftptrack  TFTP session tracking
    -s all        Enable all detections (default)
    -S <ip>       TFTP server IP (required with tftptrack)

  IPS / Firewall
    -B            Enable IPS blocking mode (requires root + iptables)
    -b <file>     Load IP blacklist on startup
    -w <ip>       Whitelist an IP address
    -W <file>     Load IP whitelist from file

  Other
    -h            Show this help
```

---

## AI Engine

```
python3 ai/ifire_ai.py <command> [options]

Commands:
  train  <log>              Train Isolation Forest on baseline JSON log
  infer  <log>              Score a log file; print anomalous source IPs
  watch  <log>              Continuously monitor a live log file

Options:
  --model-dir DIR           Model storage directory (default: models/)
  --interval  SECONDS       Watch interval in seconds (default: 30)
```

### AI Features (per source IP)

| Feature | Description |
|---|---|
| `packets_total` | Total event count |
| `unique_dst_ports` | Distinct destination ports |
| `syn_count` | SYN-only packet count |
| `rst_count` | RST packet count |
| `icmp_count` | ICMP/ping packet count |
| `alert_count` | ALERT-level events triggered |
| `block_count` | BLOCK events |
| `avg_src_port` | Mean source port (low = scanner) |
| `port_entropy` | Shannon entropy of dst-port distribution |

---

## Directory Structure

```
ifire/
├── src/              C source files (sensor core + detectors)
│   ├── ifire.c       Main entry point
│   ├── firewall.c/h  iptables IPS integration
│   ├── portscan.c/h  Port scan detector
│   ├── synflood.c/h  SYN flood detector
│   ├── logger.c/h    JSON structured logging
│   └── ...           Protocol parsers (IP, TCP, UDP, ARP, ICMP, TFTP)
├── ai/
│   ├── ifire_ai.py   AI anomaly detection engine
│   ├── requirements.txt
│   └── models/       Trained model files (git-ignored)
├── config/
│   ├── ifire.conf    Main configuration reference
│   ├── blacklist.txt IP block list
│   └── whitelist.txt IP allow list
├── scripts/
│   ├── install.sh    System installation
│   └── ifire.sh      Management helper
├── Makefile
├── LICENSE           MIT
└── README.md
```

---

## Dependencies

| Component | Dependency |
|---|---|
| C sensor | `libpcap` · `iptables` (for IPS) |
| AI engine | Python 3.8+ · `numpy` · `scikit-learn` |

---

## Architecture

```
Network Interface
      │
      ▼
  libpcap (packet capture)
      │
      ▼
┌─────────────────────────────────────────┐
│           IFIRE Sensor (C)              │
│  ┌──────────┐  ┌──────────────────────┐ │
│  │ Protocol │  │   Threat Detectors   │ │
│  │ Parsers  │─▶│  ARP · Ping · Scan   │ │
│  │ ETH/IP/  │  │  SYN · TCP · TFTP    │ │
│  │ TCP/UDP  │  └──────────┬───────────┘ │
│  └──────────┘             │ alert       │
│                    ┌──────▼──────┐      │
│                    │  Firewall   │      │
│                    │  (iptables) │      │
│                    └──────┬──────┘      │
│                    ┌──────▼──────┐      │
│                    │ JSON Logger │      │
│                    └─────────────┘      │
└─────────────────────────────────────────┘
                           │
                           ▼ ifire.jsonl
┌─────────────────────────────────────────┐
│         IFIRE AI Engine (Python)        │
│   Isolation Forest · Feature Extract   │
│   Per-IP Anomaly Scoring · Alerting    │
└─────────────────────────────────────────┘
```

---

## License

MIT — see [LICENSE](LICENSE).

Built on the packet-parsing foundation from [tcpip.marcolavoie.ca](http://tcpip.marcolavoie.ca) (originally C++, adapted to C by the original IDS_Sniffer project), extended with IPS, port scan / SYN flood detection, structured logging, and AI anomaly detection by the IFIRE contributors.
