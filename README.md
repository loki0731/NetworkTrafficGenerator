# Network Traffic Generator

Modern PyQt6 GUI for iperf3 with real-time monitoring and SSH-based remote server control.

![Python](https://img.shields.io/badge/Python-3.10+-blue)
![PyQt6](https://img.shields.io/badge/PyQt6-GUI-green)
![iperf3](https://img.shields.io/badge/iperf3-supported-orange)
![License](https://img.shields.io/badge/License-MIT-lightgrey)

## Features

- TCP throughput testing
- UDP performance testing
- Bidirectional mode
- TCP congestion analysis
- Multi-stream stress testing
- Real-time graphs
- SSH remote server startup
- Live bandwidth, jitter and packet loss monitoring

## Screenshot

![Application](docs/screenshots/main.png)

---

## Requirements

### Client

- Python 3.10+
- PyQt6
- pyqtgraph
- paramiko

### Server

- iperf3

---

## Installation

```bash
git clone https://github.com/<your_username>/network-traffic-generator.git
cd network-traffic-generator

python3 -m venv venv
source venv/bin/activate

pip install -r requirements.txt
```

## Run

```bash
python3 main.py
```

---

## Server Setup

Ubuntu / Debian:

```bash
sudo apt update
sudo apt install iperf3
```

Start server:

```bash
iperf3 -s
```

---

## Quick Start

1. Enter server IP address
2. Select test mode
3. Configure duration and streams
4. Click **Start**
5. Monitor results in real time

---

## Test Modes

| Mode | Description |
|--------|-------------|
| TCP | Bandwidth measurement |
| UDP | Jitter and packet loss analysis |
| Bidirectional | Simultaneous send/receive |
| Congestion | TCP behavior under load |
| Multi-Stream | Parallel connection stress test |

---

## Tech Stack

- Python
- PyQt6
- pyqtgraph
- Paramiko
- iperf3

---

## License

MIT

---

## Author

**Vladislav Guznov**

Network Performance Testing Tool built on top of iperf3.