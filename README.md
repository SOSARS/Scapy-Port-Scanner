# ScapyScan - A Stealthy & Fast Python Port Scanner

<div align="center">
  <img src="https://i.imgur.com/vHqX6xV.png" alt="ScapyScan Logo" width="150"/>
</div>

<p align="center">
  <a href="https://www.python.org/">
    <img src="https://img.shields.io/badge/python-3.8+-blue.svg" alt="Python Version">
  </a>
  <a href="https://github.com/[SOSARS]/[Scapy-Port-Scanner]/blob/main/LICENSE">
    <img src="https://img.shields.io/badge/license-MIT-green.svg" alt="License">
  </a>
  <a href="#">
    <img src="https://img.shields.io/badge/Maintained%3F-yes-green.svg" alt="Maintained">
  </a>
</p>

<p align="center">
  A multi-threaded TCP SYN port scanner built with Scapy for fast, efficient, and stealthy network reconnaissance, featuring service/version detection and file output.
</p>

---

## 🚀 Key Features

* **Stealthy SYN Scans**: Utilises Scapy to perform half-open TCP SYN scans to remain discreet on the network.
* **High-Speed Performance**: Employs a multi-threaded, queue-based architecture for rapid scanning of large port ranges.
* **Service & Version Detection**: Grabs service banners to identify what's running on open ports.
* **Flexible & User-Friendly**: Accepts hostnames or IP addresses, with intuitive options for specifying ports and threads.
* **Save & Analyse**: Saves scan results to a clean text file for documentation and later analysis.

---

## 🎬 Demo

* Video dropping shortly *
---

## 🛠️ Installation & Setup

Follow these steps to get ScapyScan up and running on your local machine. This script requires root/administrator privileges to run.

**1. Clone the Repository**
```bash
git clone [https://github.com/](https://github.com/)[SOSARS]/[Scapy-Port-Scanner].git
cd [Scapy-Port-Scanner]
```

**2. Install Dependencies**
It's recommended to use a virtual environment.
```bash
python3 -m venv venv
source venv/bin/activate  # On Windows, use `venv\Scripts\activate`
pip install -r requirements.txt
```

---

## ⚙️ Usage Guide

The script is run from the command line, providing a target and optional arguments for ports, threads, and output.

### Command Arguments

| Argument          | Shorthand | Description                                           | Default   |
| ----------------- | --------- | ----------------------------------------------------- | --------- |
| `target`          |           | **Required.** The target IP or hostname to scan.      |           |
| `--ports`         | `-p`      | Port range (`1-1024`) or specific ports (`80,443`).   | `1-1024`  |
| `--threads`       | `-t`      | Number of threads to use for the scan.                | `100`     |
| `--output`        | `-o`      | File to save the scan results to.                     | `None`    |

### Examples

* **Scan a target for common ports:**
    ```bash
    sudo python3 scapy-port-scanner.py 192.168.1.1
    ```

* **Scan a hostname for a specific port range with high threads:**
    ```bash
    sudo python3 scapy-port-scanner.py scanme.nmap.org -p 1-200 -t 200
    ```

* **Scan for specific ports and save the results to a file:**
    ```bash
    sudo python3 scapy-port-scanner.py 10.0.0.5 -p 22,80,443,8080 -o scan_results.txt
    ```

---
