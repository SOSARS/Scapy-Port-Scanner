# ScapyScan - A Stealthy & Fast Python Port Scanner

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

## 🎯 Why ScapyScan? Purpose & Use Cases

Understanding what services are exposed to a network is the foundational first step in both offensive and defensive security. ScapyScan was built to automate this crucial reconnaissance phase efficiently and discreetly. It helps answer the fundamental question: "What doors are open on this target?"

This tool is designed for several key purposes:

* **Ethical Hacking & Penetration Testing**: During the initial information-gathering phase, a penetration tester can use ScapyScan to quickly map out a target's attack surface, identifying open ports and running services that could be potential vectors for exploitation.

* **Network Security Auditing**: A system administrator can use this tool to audit their own systems and firewalls. By scanning their servers from an external perspective, they can verify that only intended ports are open and that no unauthorised services are exposed to the internet.

* **Educational Learning**: For anyone studying cybersecurity, this project serves as a practical, hands-on example of core concepts like TCP/IP protocols (SYN scans), raw packet crafting with Scapy, and concurrent programming with Python's multi-threading.

---

## 🎬 Demo

... maybe one day. Stay tuned 😂

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
