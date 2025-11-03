#!/usr/bin/env python3

# Upgraded version of Port Scanner v1, this includes threading for
# concurrent processing and more efficient scanning, alongside some
# extra features and outputs.

"""
Concurrent port scanner with flexible port-range parsing.

- "1-100"    -> ports 1 through 100 (inclusive)
- "1,100"    -> only ports 1 and 100
- "1-5,22,80"-> combined ranges and individual ports

Uses a thread pool to scan ports concurrently and prints a summary.
Only scan hosts you own or have permission to scan.
"""

import socket
import sys
from typing import Set, Iterable, List
from concurrent.futures import ThreadPoolExecutor, as_completed


def parse_port_spec(spec: str) -> Set[int]:
    """
    Parse a port specification string into a set of integer ports.

    Accepts:
      - single ports: "22"
      - ranges: "1-100"
      - comma separated mixture: "1-5,22,80"

    Returns a set of unique port numbers.

    Raises ValueError on invalid input (non-integers, out-of-range ports, bad format).
    """
    ports: Set[int] = set()
    if not spec:
        raise ValueError("Empty port specification")

    for token in spec.split(','):
        token = token.strip()
        if not token:
            continue

        if '-' in token:
            try:
                start_str, end_str = token.split('-', 1)
                start = int(start_str)
                end = int(end_str)
            except ValueError:
                raise ValueError(f"Invalid range token: '{token}' (must be integers like 1-100)")

            if start < 1 or end < 1 or start > 65535 or end > 65535:
                raise ValueError(f"Port numbers must be in 1-65535: '{token}'")
            if start > end:
                raise ValueError(f"Range start must be <= end: '{token}'")

            for p in range(start, end + 1):
                ports.add(p)

        else:
            try:
                p = int(token)
            except ValueError:
                raise ValueError(f"Invalid port token: '{token}' (must be an integer)")

            if p < 1 or p > 65535:
                raise ValueError(f"Port numbers must be in 1-65535: '{token}'")

            ports.add(p)

    return ports


def scan_port(target_ip: str, port: int, timeout: float = 1.0) -> str:
    """
    Attempt to connect to (target_ip, port).
    Returns one of: "open", "closed", "timeout", "error: <msg>"
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            result = s.connect_ex((target_ip, port))
            if result == 0:
                return "open"
            else:
                return "closed"
    except socket.timeout:
        return "timeout"
    except Exception as e:
        return f"error: {e}"


def scan_ports_concurrent(target_ip: str, port_iter: Iterable[int], timeout: float = 1.0,
                          max_workers: int = 100) -> None:
    """
    Concurrently scan ports in port_iter on target_ip using a thread pool.
    Prints status while scanning and a final summary of open ports.
    """
    ports_sorted = sorted(port_iter)
    if not ports_sorted:
        print("No ports to scan.")
        return

    # Resolve target upfront (gives clearer error if hostname invalid)
    try:
        resolved_ip = socket.gethostbyname(target_ip)
    except socket.gaierror:
        print(f"Error: Could not resolve target '{target_ip}'.")
        return

    total_ports = len(ports_sorted)
    print(f"Starting concurrent scan of {target_ip} ({resolved_ip}) on {total_ports} port(s)")
    print("Tip: only scan systems you own or have permission to scan.\n")

    # Clamp workers to sensible bounds: at most number of ports, and between 1 and 1000
    max_workers = max(1, min(max_workers, min(1000, total_ports)))

    open_ports: List[int] = []

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # submit tasks
        future_to_port = {
            executor.submit(scan_port, resolved_ip, port, timeout): port
            for port in ports_sorted
        }

        try:
            for future in as_completed(future_to_port):
                port = future_to_port[future]
                try:
                    status = future.result()
                except Exception as e:
                    status = f"error: unexpected exception: {e}"

                # Show immediate, human-friendly feedback
                if status == "open":
                    print(f"Port {port}: OPEN")
                    open_ports.append(port)
                elif status == "closed":
                    print(f"Port {port}: closed")
                elif status == "timeout":
                    print(f"Port {port}: timeout")
                else:
                    print(f"Port {port}: {status}")

        except KeyboardInterrupt:
            print("\nScan interrupted by user. Exiting early.")
            return

    # Final summary
    open_ports.sort()
    print("\n--- Scan Summary ---")
    print(f"Target: {target_ip} ({resolved_ip})")
    print(f"Ports scanned: {total_ports}")
    if open_ports:
        print(f"Open ports ({len(open_ports)}): {', '.join(str(p) for p in open_ports)}")
    else:
        print("No open ports found in the scanned range.")
    print("--------------------\n")


def main():
    # Command-line or interactive usage
    if len(sys.argv) >= 3:
        target = sys.argv[1]
        port_spec = sys.argv[2]
    else:
        target = input("Enter target (IP or hostname): ").strip()
        port_spec = input("Enter ports (e.g. 1-100  OR  22,80  OR  1-5,80,443): ").strip()

    try:
        ports = parse_port_spec(port_spec)
    except ValueError as e:
        print(f"Invalid port specification: {e}")
        sys.exit(1)

    timeout_input = input("Timeout per port in seconds [default 1.0]: ").strip()
    try:
        timeout = float(timeout_input) if timeout_input else 1.0
    except ValueError:
        print("Invalid timeout value; using default 1.0s")
        timeout = 1.0

    workers_input = input("Max concurrent workers [default 100]: ").strip()
    try:
        workers = int(workers_input) if workers_input else 100
    except ValueError:
        print("Invalid workers value; using default 100")
        workers = 100

    try:
        scan_ports_concurrent(target, ports, timeout=timeout, max_workers=workers)
    except KeyboardInterrupt:
        print("\nScan aborted by user.")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")


if __name__ == "__main__":
    main()
