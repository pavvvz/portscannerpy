#!/usr/bin/env python3
"""Simple threaded TCP port scanner.

Usage:
    python main.py target [--start START] [--end END] [--threads N] [--output]

If --output is set, results are written to a file named "scan_results_<MM-DD-YYYY_HH-MM-SS>.txt".
"""
from __future__ import annotations

import argparse
import datetime
import socket
import threading
from queue import Queue
from typing import List


def scan_port(target: str, port: int, timeout: float = 1.0) -> bool:
    """Try to connect to target:port. Return True if open."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            result = s.connect_ex((target, port))
            return result == 0
    except Exception:
        return False


def worker(target: str, q: Queue, results: List[int], timeout: float) -> None:
    """Thread worker: get ports from queue and scan them."""
    while True:
        port = q.get()
        if port is None:
            q.task_done()
            break
        if scan_port(target, port, timeout=timeout):
            results.append(port)
            print(f"[+] Port {port} is open")
        else:
            print(f"[-] Port {port} is closed")
        q.task_done()


def run_scan(target: str, start: int, end: int, threads: int, timeout: float, write_output: bool) -> List[int]:
    """Run threaded scan and optionally write output to a dated file.

    Returns list of open ports.
    """
    q: Queue = Queue()
    results: List[int] = []

    # enqueue ports
    for port in range(start, end + 1):
        q.put(port)

    # start worker threads
    thread_list: List[threading.Thread] = []
    for _ in range(threads):
        t = threading.Thread(target=worker, args=(target, q, results, timeout), daemon=True)
        t.start()
        thread_list.append(t)

    # block until queue empty
    q.join()

    # stop workers
    for _ in thread_list:
        q.put(None)
    for t in thread_list:
        t.join(timeout=1.0)

    results.sort()

    if write_output:
        now = datetime.datetime.now()
        filename = now.strftime("scan_results_%m-%d-%Y_%H-%M-%S.txt")
        with open(filename, "w", encoding="utf-8") as f:
            f.write(f"Scan target: {target}\n")
            f.write(f"Range: {start}-{end}\n")
            f.write(f"Threads: {threads}\n")
            f.write(f"Timestamp: {now.isoformat()}\n\n")
            if results:
                f.write("Open ports:\n")
                for p in results:
                    f.write(f"{p}\n")
            else:
                f.write("No open ports found.\n")
        print(f"Results written to {filename}")

    return results


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Simple threaded TCP port scanner")
    parser.add_argument("target", help="Target hostname or IP address to scan")
    parser.add_argument("--start", type=int, default=1, help="Start port (default: 1)")
    parser.add_argument("--end", type=int, default=1024, help="End port (default: 1024)")
    parser.add_argument("--threads", type=int, default=100, help="Number of worker threads (default: 100)")
    parser.add_argument("--timeout", type=float, default=0.5, help="Socket timeout in seconds (default: 0.5)")
    parser.add_argument("--output", action="store_true", help="Write results to dated file")
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    # Basic validation
    if args.start < 1 or args.end > 65535 or args.start > args.end:
        print("Invalid port range. Ports must be 1-65535 and start <= end.")
        return

    print(f"Scanning {args.target} ports {args.start}-{args.end} with {args.threads} threads...")
    open_ports = run_scan(args.target, args.start, args.end, args.threads, args.timeout, args.output)

    print("\nScan complete. Open ports:")
    if open_ports:
        for p in open_ports:
            print(f" - {p}")
    else:
        print(" (none)")


if __name__ == "__main__":
    main()
