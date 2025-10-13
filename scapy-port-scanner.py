#!/usr/bin/env python3
# The line above is a 'shebang', which tells the system how to execute this script,
# making it runnable directly from the command line (e.g., ./scanner.py) after giving it execute permissions (chmod +x scanner.py).

import socket
import threading
import sys
import logging
from queue import Queue
import argparse  # Handles command-line arguments.

# Import Scapy components
try:
    from scapy.all import IP, TCP, sr1, RandShort
except ImportError:
    print("Scapy is not installed. Please run 'pip install scapy' and try again.")
    sys.exit(1)  # Exit the script if a critical dependency is missing.

# Suppress Scapy's verbose startup messages
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

# --- Global Configuration ---
# A lock is still needed for thread-safe printing to avoid jumbled output.
print_lock = threading.Lock()


def grab_banners(target_ip, port):
    """Connects to an open port and attempts to grab the service banner"""
    try:
        sock = socket.socket()
        sock.settimeout(2)
        sock.connect((target_ip, port))
        banner = socket.recv(1024)  # Receive up to 1024 bytes of data
        sock.close()

        return banner.decode("utf-8", errors="ignore").strip()
    except Exception:
        return "Could not retrieve the banner ☹️"


def scan_port_scapy(target_ip, port, results_list):
    """
    Scans a single port on the target IP using a Scapy SYN scan.
    This function accepts the target_ip as an argument instead of relying
    on a hardcoded global variable, making it more reusable and predictable.
    Results are added to a list.
    """
    try:
        source_port = RandShort()
        packet = IP(dst=target_ip) / TCP(sport=source_port, dport=port, flags="S")

        # Set `verbose=0` to prevent Scapy from flooding the console.
        # A shorter timeout (e.g., 1 or 2 seconds) makes the scan faster.
        response = sr1(packet, timeout=1.5, verbose=0)

        if response is not None and response.haslayer(TCP):
            if response.getlayer(TCP).flags == 0x12:  # SYN/ACK

                # Grab the banner if the port is open
                banner = grab_banners(target_ip, port)

                # Send an RST packet to cleanly close the half-open connection.
                sr1(IP(dst=target_ip) / TCP(sport=source_port, dport=port, flags="R"), timeout=1, verbose=0)

                # Create a result string
                result_string = f"[+] Port {port:<5} is open\t{banner}"
                with print_lock:
                    print(result_string)
                    results_list.append(result_string)

    except Exception as e:
        # It's good practice to handle potential exceptions.
        # "pass" keeps the output clean.
        pass


def worker(target_ip, port_queue, results_list):
    """
    The worker function for each thread.
    Takes the target_ip and port_queue as arguments for better encapsulation.
    """
    while not port_queue.empty():
        port = port_queue.get()
        scan_port_scapy(target_ip, port, results_list)
        port_queue.task_done()


def main():
    """Main function to parse arguments and orchestrate the scan."""
    # The argparse setup makes the script a real command-line tool.
    # It provides help messages and validates user input.
    parser = argparse.ArgumentParser(description="A fast, multi-threaded TCP SYN port scanner.")
    parser.add_argument("target", help="The target IP address or hostname to scan.")
    parser.add_argument("-p", "--ports", default="1-1024", help="Port range to scan. E.g., '1-1024', '80,443'.")
    parser.add_argument("-t", "--threads", type=int, default=100, help="Number of threads to use for the scan.")
    parser.add_argument("-o", "--output", help="Save the scan results to a file.")
    args = parser.parse_args()

    # This block resolves a hostname to an IP address.
    try:
        target_ip = socket.gethostbyname(args.target)
        print(f"[*] Resolved '{args.target}' to {target_ip}")
    except socket.gaierror:
        print(f"[!] Error: Could not resolve hostname '{args.target}'. Exiting.")
        sys.exit(1)

    print(f"[*] Starting scan on {target_ip} with {args.threads} threads... 🤔")
    print("!!! This script must be run with sudo/admin privileges !!!\n")

    port_queue = Queue()
    scan_results = []  # List to hold results for the file

    # This logic parses the user-provided port string, allowing for ranges (e.g., 1-1024)
    # and comma-separated values (e.g., 80,443,8080).
    try:
        if "-" in args.ports:
            start, end = map(int, args.ports.split("-"))
            for port in range(start, end + 1):
                port_queue.put(port)
        elif "-" in args.ports:
            for port in args.ports.split(","):
                port_queue.put(int(port))
        else:
            port_queue.put(int(args.ports))
    except ValueError:
        print("[!] Error: Invalid port specification. Use a range (e.g., 1-1024) or commas (e.g., 80,443).")
        sys.exit(1)

    # Create and start the worker threads
    for index in range(args.threads):
        thread = threading.Thread(target=worker, args=(target_ip, port_queue, scan_results))
        thread.daemon = True
        thread.start()

    port_queue.join()  # Wait for all ports to be processed

    if args.output:
        print(f"[*] Saving results to {args.output}... ✍️")
        with open(args.output, "w") as file:
            scan_results.sort(key=lambda x: int(x.split()[2]))
            for result in scan_results:
                file.write(result + "\n")
        print(f"[*] Your results have been saved successfully! 😁")


    print("\n[*] Scan complete.")
    print(f"You should be seeing all of your open ports above.\nIf not, you're looking good! 👌 😊")


if __name__ == "__main__":
    main()