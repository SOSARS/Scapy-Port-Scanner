#!/usr/bin/env python3
"""
scapy_port_scanner-v2.py
Professional Scapy port scanner with full feature implementation:
- SYN (raw) scan using Scapy (requires root) with correct RST handling
- TCP connect fallback (socket.connect_ex)
- ThreadPoolExecutor concurrency
- Robust port parsing (comma / ranges)
- Banner grabbing with protocol-specific probes
- CSV / JSON output
- Rate limiting, timeouts, and graceful Ctrl+C handling

Usage examples:
sudo python3 scapy_port_scanner-v2.py -t 192.168.1.30 -p 1-1024 --scan syn -T 200 --timeout 1.0 -o scan_results.csv
python3 scapy_port_scanner-v2.py -t 192.168.56.101 -p 22,80,139 --scan connect -T 50 -o out.json
"""

import argparse
import csv
import json
import os
import sys
import time
import socket
import signal
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import List, Tuple, Dict, Optional
from queue import Queue

try:
    from scapy.all import IP, TCP, sr1, send, conf, RandShort

    SCAPY_AVAILABLE = True
    conf.verb = 0  # Remove Scapy noise
except ImportError:
    SCAPY_AVAILABLE = False
    print("[!] Warning: Scapy not installed. Only connect scan will be available.")

# Global configuration
print_lock = threading.Lock()
shutdown_flag = threading.Event()


def signal_handler(sig, frame):
    """Handle Ctrl+C gracefully"""
    print("\n[!] Scan interrupted by user. Shutting down gracefully...")
    shutdown_flag.set()
    sys.exit(0)


signal.signal(signal.SIGINT, signal_handler)


def grab_banner(target_ip: str, port: int, timeout: float = 2.0) -> str:
    """
    Connects to an open port and attempts to grab the service banner.
    Sends protocol-specific probes for better banner detection.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((target_ip, port))

        # Send protocol-specific probes
        probes = {
            80: b"GET / HTTP/1.0\r\n\r\n",
            443: b"GET / HTTP/1.0\r\n\r\n",
            21: b"\r\n",
            22: b"\r\n",
            25: b"EHLO test\r\n",
            110: b"\r\n",
            143: b"\r\n",
            3306: b"\r\n",
        }

        if port in probes:
            sock.send(probes[port])

        banner = sock.recv(1024)
        sock.close()

        decoded = banner.decode("utf-8", errors="ignore").strip()
        return decoded[:100] if decoded else "Banner received (binary data)"

    except socket.timeout:
        return "No banner (timeout)"
    except Exception as e:
        return "No banner"


def scan_port_syn(target_ip: str, port: int, timeout: float = 1.5) -> Tuple[bool, str]:
    """
    Scans a single port using Scapy SYN scan.
    Returns (is_open, banner)
    """
    if not SCAPY_AVAILABLE:
        return False, "Scapy not available"

    try:
        source_port = RandShort()
        packet = IP(dst=target_ip) / TCP(sport=source_port, dport=port, flags="S")

        response = sr1(packet, timeout=timeout, verbose=0)

        if response is not None and response.haslayer(TCP):
            if response.getlayer(TCP).flags == 0x12:  # SYN/ACK
                # Send RST to close connection cleanly
                send(IP(dst=target_ip) / TCP(sport=source_port, dport=port, flags="R"),
                     verbose=0)

                # Grab banner
                banner = grab_banner(target_ip, port)
                return True, banner

        return False, ""

    except Exception as e:
        return False, f"Error: {str(e)}"


def scan_port_connect(target_ip: str, port: int, timeout: float = 2.0) -> Tuple[bool, str]:
    """
    Scans a single port using TCP connect scan (socket.connect_ex).
    Returns (is_open, banner)
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((target_ip, port))
        sock.close()

        if result == 0:
            banner = grab_banner(target_ip, port, timeout)
            return True, banner
        return False, ""

    except Exception as e:
        return False, f"Error: {str(e)}"


def parse_ports(port_string: str) -> List[int]:
    """
    Parse port specification into a list of port numbers.
    Supports: '80', '1-1024', '22,80,443', '1-100,443,8000-9000'
    """
    ports = []

    try:
        parts = port_string.split(",")
        for part in parts:
            part = part.strip()
            if "-" in part:
                start, end = map(int, part.split("-"))
                if start > end or start < 1 or end > 65535:
                    raise ValueError(f"Invalid port range: {part}")
                ports.extend(range(start, end + 1))
            else:
                port = int(part)
                if port < 1 or port > 65535:
                    raise ValueError(f"Invalid port number: {port}")
                ports.append(port)

        return sorted(set(ports))  # Remove duplicates and sort

    except ValueError as e:
        raise ValueError(f"Invalid port specification '{port_string}': {e}")


def format_result(port: int, banner: str, scan_type: str) -> Dict:
    """Format scan result as a dictionary"""
    return {
        "port": port,
        "state": "open",
        "banner": banner,
        "scan_type": scan_type,
        "timestamp": datetime.now().isoformat()
    }


def save_results_csv(results: List[Dict], filename: str):
    """Save results to CSV file"""
    if not results:
        print("[!] No results to save.")
        return

    with open(filename, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["port", "state", "banner", "scan_type", "timestamp"])
        writer.writeheader()
        writer.writerows(results)

    print(f"[*] Results saved to {filename}")


def save_results_json(results: List[Dict], filename: str):
    """Save results to JSON file"""
    if not results:
        print("[!] No results to save.")
        return

    with open(filename, "w") as f:
        json.dump(results, f, indent=2)

    print(f"[*] Results saved to {filename}")


def save_results_txt(results: List[Dict], filename: str):
    """Save results to plain text file"""
    if not results:
        print("[!] No results to save.")
        return

    with open(filename, "w") as f:
        for result in results:
            f.write(f"[+] Port {result['port']:<5} is open\t{result['banner']}\n")

    print(f"[*] Results saved to {filename}")


def worker_threadpool(target_ip: str, port: int, scan_type: str, timeout: float, rate_limiter=None):
    """
    Worker function for ThreadPoolExecutor.
    Returns result dictionary if port is open, None otherwise.
    """
    if shutdown_flag.is_set():
        return None

    # Rate limiting
    if rate_limiter:
        rate_limiter.acquire()

    # Perform scan based on type
    if scan_type == "syn":
        is_open, banner = scan_port_syn(target_ip, port, timeout)
    else:  # connect
        is_open, banner = scan_port_connect(target_ip, port, timeout)

    if is_open:
        result = format_result(port, banner, scan_type)
        with print_lock:
            print(f"[+] Port {port:<5} is open\t{banner}")
        return result

    return None


class RateLimiter:
    """Simple rate limiter using threading.Semaphore"""

    def __init__(self, rate: int):
        """
        rate: maximum number of operations per second
        """
        self.rate = rate
        self.semaphore = threading.Semaphore(rate)
        self.lock = threading.Lock()

    def acquire(self):
        """Acquire permission to proceed"""
        self.semaphore.acquire()
        threading.Timer(1.0, self.semaphore.release).start()


def main():
    """Main function to parse arguments and orchestrate the scan."""
    parser = argparse.ArgumentParser(
        description="A fast, multi-threaded port scanner with SYN and Connect scan support.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  sudo python3 %(prog)s -t 192.168.1.1 -p 1-1024 --scan syn -T 200
  python3 %(prog)s -t example.com -p 22,80,443 --scan connect -o results.json
  python3 %(prog)s -t 10.0.0.1 -p 1-65535 --scan syn -T 500 --timeout 0.5 --rate-limit 100
        """
    )

    parser.add_argument("-t", "--target", required=True,
                        help="Target IP address or hostname to scan")
    parser.add_argument("-p", "--ports", default="1-1024",
                        help="Ports to scan. Examples: '80', '1-1024', '22,80,443' (default: 1-1024)")
    parser.add_argument("--scan", choices=["syn", "connect"], default="connect",
                        help="Scan type: 'syn' (requires root) or 'connect' (default: connect)")
    parser.add_argument("-T", "--threads", type=int, default=100,
                        help="Number of concurrent threads (default: 100)")
    parser.add_argument("--timeout", type=float, default=1.5,
                        help="Timeout for each port scan in seconds (default: 1.5)")
    parser.add_argument("--rate-limit", type=int, default=None,
                        help="Maximum scans per second (optional)")
    parser.add_argument("-o", "--output", help="Output file (format determined by extension: .csv, .json, or .txt)")

    args = parser.parse_args()

    # Check for root privileges if SYN scan is requested
    if args.scan == "syn":
        if not SCAPY_AVAILABLE:
            print("[!] Error: Scapy is required for SYN scanning. Install with: pip install scapy")
            sys.exit(1)

        # Check for admin privileges (cross-platform)
        if sys.platform == "win32":
            try:
                import ctypes
                is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
            except:
                is_admin = False
            if not is_admin:
                print("[!] Error: SYN scanning requires administrator privileges.")
                print("[!] Please run Command Prompt as Administrator and try again.")
                sys.exit(1)
        else:  # Unix/Linux/Mac
            if os.geteuid() != 0:
                print("[!] Error: SYN scanning requires root privileges. Run with sudo.")
                sys.exit(1)

    # Resolve hostname to IP
    try:
        target_ip = socket.gethostbyname(args.target)
        print(f"[*] Resolved '{args.target}' to {target_ip}")
    except socket.gaierror:
        print(f"[!] Error: Could not resolve hostname '{args.target}'. Exiting.")
        sys.exit(1)

    # Parse ports
    try:
        ports = parse_ports(args.ports)
        print(f"[*] Parsed {len(ports)} ports to scan")
    except ValueError as e:
        print(f"[!] Error: {e}")
        sys.exit(1)

    # Display scan info
    print(f"[*] Starting {args.scan.upper()} scan on {target_ip}")
    print(f"[*] Threads: {args.threads} | Timeout: {args.timeout}s | Ports: {len(ports)}")
    if args.scan == "syn":
        print("[!] Running with root privileges for SYN scanning")
    if args.rate_limit:
        print(f"[*] Rate limit: {args.rate_limit} scans/second")
    print()

    # Initialize rate limiter if requested
    rate_limiter = RateLimiter(args.rate_limit) if args.rate_limit else None

    # Scan with ThreadPoolExecutor
    results = []
    start_time = time.time()

    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        future_to_port = {
            executor.submit(worker_threadpool, target_ip, port, args.scan, args.timeout, rate_limiter): port
            for port in ports
        }

        for future in as_completed(future_to_port):
            if shutdown_flag.is_set():
                break
            try:
                result = future.result()
                if result:
                    results.append(result)
            except Exception as e:
                pass  # Silently handle errors in individual scans

    elapsed_time = time.time() - start_time

    # Display summary
    print(f"\n[*] Scan complete in {elapsed_time:.2f} seconds")
    print(f"[*] Found {len(results)} open ports")

    if not results:
        print("[*] No open ports found.")

    # Save results if output file specified
    if args.output and results:
        results.sort(key=lambda x: x["port"])

        if args.output.endswith(".csv"):
            save_results_csv(results, args.output)
        elif args.output.endswith(".json"):
            save_results_json(results, args.output)
        else:
            save_results_txt(results, args.output)


if __name__ == "__main__":
    main()