# Network Traffic Generator

Modern PyQt6 GUI wrapper for **iperf3** with real-time monitoring, graphing and remote server management over SSH.

![Python](https://img.shields.io/badge/Python-3.10+-blue)
![PyQt6](https://img.shields.io/badge/PyQt6-GUI-green)
![iperf3](https://img.shields.io/badge/iperf3-supported-orange)

## Features

* TCP throughput testing
* UDP performance testing
* Bidirectional traffic tests
* TCP congestion analysis
* Multi-stream load testing
* Real-time bandwidth graphs
* SSH remote iperf3 startup
* Packet loss and jitter monitoring

---

## Installation

### Clone repository

```bash
git clone https://github.com/loki0731/NetworkTrafficGenerator.git
cd NetworkTrafficGenerator
```

### Install Python dependencies

```bash
sudo apt update
sudo apt install -y iperf3
pip3 install PyQt6 pyqtgraph paramiko
```

### Ubuntu/Debian additional dependencies

```bash
sudo apt update

sudo apt install -y python3-pip iperf3 libxcb-cursor0 libxkbcommon-x11-0 libxcb-icccm4 libxcb-image0 libxcb-keysyms1 libxcb-render-util0 libxcb-xinerama0
```

---

## Running

```bash
python3 ntg.py
```

---

## Remote Server Setup

Install iperf3 on the remote host:

```bash
sudo apt update
sudo apt install -y iperf3
```

Start server manually:

```bash
iperf3 -s
```

Or use the built-in SSH server startup feature.

---

## Quick Start

1. Enter server IP address
2. Select test mode
3. Configure test parameters
4. Click **Start**
5. Monitor results in real time

---

## Test Modes

| Mode          | Description                        |
| ------------- | ---------------------------------- |
| TCP           | Throughput measurement             |
| UDP           | Jitter and packet loss analysis    |
| Bidirectional | Full-duplex testing                |
| Congestion    | TCP congestion monitoring          |
| Multi-Stream  | Parallel connection stress testing |

---

## Requirements

* Python 3.10+
* PyQt6
* pyqtgraph
* paramiko
* iperf3

