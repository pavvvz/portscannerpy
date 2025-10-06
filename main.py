#!/usr/bin/env python3
"""Upgraded simple TCP port scanner.

This version uses ThreadPoolExecutor for concurrency, supports --verbose printing,
and can save results to a timestamped file with selectable format (txt/csv/json).
"""
from __future__ import annotations

import argparse
import datetime
import json
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Tuple, Optional


def scan_port(target: str, port: int, timeout: float = 1.0) -> Tuple[int, bool]:
    """Attempt to open a TCP connection to target:port.

    Returns a tuple (port, is_open).
    """
    try:
        # socket.create_connection resolves the host and attempts a TCP connect
        conn = socket.create_connection((target, port), timeout=timeout)
        conn.close()
        return port, True
    except Exception:
        return port, False


def run_scan(
    target: str,
    start: int,
    end: int,
    workers: int,
    timeout: float,
    verbose: bool = True,
) -> List[int]:
    """Scan ports [start..end] using a ThreadPoolExecutor and return sorted open ports."""
    open_ports: List[int] = []

    ports = range(start, end + 1)
    with ThreadPoolExecutor(max_workers=workers) as executor:
        future_to_port = {executor.submit(scan_port, target, p, timeout): p for p in ports}

        try:
            for future in as_completed(future_to_port):
                port, is_open = future.result()
                if is_open:
                    open_ports.append(port)
                    if verbose:
                        print(f"[+] Port {port} is open")
                else:
                    if verbose:
                        print(f"[-] Port {port} is closed")
        except KeyboardInterrupt:
            # Attempt a polite shutdown
            print("\nInterrupted by user, shutting down...")
            executor.shutdown(wait=False)
            raise

    open_ports.sort()
    return open_ports


def write_output(
    target: str,
    start: int,
    end: int,
    workers: int,
    open_ports: List[int],
    outname_prefix: str = "scan_results",
    fmt: str = "txt",
) -> str:
    """Write results to a timestamped file. Returns filename."""
    now = datetime.datetime.now()
    timestamp = now.strftime("%m-%d-%Y_%H-%M-%S")
    ext = fmt if fmt != "txt" else "txt"
    filename = f"{outname_prefix}_{timestamp}.{ext}"

    if fmt == "txt":
        with open(filename, "w", encoding="utf-8") as f:
            f.write(f"Scan target: {target}\n")
            f.write(f"Range: {start}-{end}\n")
            f.write(f"Workers: {workers}\n")
            f.write(f"Timestamp: {now.isoformat()}\n\n")
            if open_ports:
                f.write("Open ports:\n")
                for p in open_ports:
                    f.write(f"{p}\n")
            else:
                f.write("No open ports found.\n")

    elif fmt == "csv":
        with open(filename, "w", encoding="utf-8") as f:
            f.write("port\n")
            for p in open_ports:
                f.write(f"{p}\n")

    elif fmt == "json":
        payload = {
            "target": target,
            "range": f"{start}-{end}",
            "workers": workers,
            "timestamp": now.isoformat(),
            "open_ports": open_ports,
        }
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2)

    else:
        raise ValueError("unsupported format")

    print(f"Results written to {filename}")
    return filename


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Simple threaded TCP port scanner (upgraded)")
    parser.add_argument("target", help="Target hostname or IP address to scan")
    parser.add_argument("--start", type=int, default=1, help="Start port (default: 1)")
    parser.add_argument("--end", type=int, default=1024, help="End port (default: 1024)")
    parser.add_argument("--workers", type=int, default=100, help="Number of worker threads (default: 100)")
    parser.add_argument("--timeout", type=float, default=0.5, help="Socket timeout in seconds (default: 0.5)")
    parser.add_argument("--no-verbose", dest="verbose", action="store_false", help="Do not print per-port status")
    parser.add_argument("--output", action="store_true", help="Write results to dated file")
    parser.add_argument("--outname", type=str, default="scan_results", help="Prefix for output filename (default: scan_results)")
    parser.add_argument("--format", choices=("txt", "csv", "json"), default="txt", help="Output file format (txt, csv, json)")
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    # Basic validation
    if args.start < 1 or args.end > 65535 or args.start > args.end:
        print("Invalid port range. Ports must be 1-65535 and start <= end.")
        return

    print(f"Scanning {args.target} ports {args.start}-{args.end} with {args.workers} workers...")

    try:
        open_ports = run_scan(args.target, args.start, args.end, args.workers, args.timeout, args.verbose)
    except KeyboardInterrupt:
        print("Scan aborted by user.")
        return

    print("\nScan complete. Open ports:")
    if open_ports:
        for p in open_ports:
            print(f" - {p}")
    else:
        print(" (none)")

    if args.output:
        write_output(args.target, args.start, args.end, args.workers, open_ports, outname_prefix=args.outname, fmt=args.format)


if __name__ == "__main__":
    main()
