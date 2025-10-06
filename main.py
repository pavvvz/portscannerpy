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
import ipaddress


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


def probe_host(ip: str, port: int = 80, timeout: float = 0.5) -> Tuple[str, bool]:
    """Probe an IP address by attempting a TCP connection to (ip, port).

    Returns (ip, is_reachable).
    """
    try:
        conn = socket.create_connection((ip, port), timeout=timeout)
        conn.close()
        return ip, True
    except Exception:
        return ip, False


def iter_ips_from_cidr(cidr: str):
    """Yield usable IP addresses from a CIDR (skips network and broadcast when applicable)."""
    net = ipaddress.ip_network(cidr, strict=False)
    for ip in net.hosts():
        yield str(ip)


def discover_network(cidr: str, probe_port: int = 80, timeout: float = 0.5, workers: int = 100, max_hosts: int = 50) -> List[str]:
    """Discover live hosts in a CIDR using TCP probe.

    Returns a list of discovered IP addresses, capped at max_hosts to keep output readable.
    """
    discovered: List[str] = []
    ips = list(iter_ips_from_cidr(cidr))

    with ThreadPoolExecutor(max_workers=min(workers, len(ips) or 1)) as executor:
        future_to_ip = {executor.submit(probe_host, ip, probe_port, timeout): ip for ip in ips}
        try:
            for future in as_completed(future_to_ip):
                ip, alive = future.result()
                if alive:
                    discovered.append(ip)
                    print(f"[+] Host {ip} appears up (port {probe_port})")
                    if len(discovered) >= max_hosts:
                        print(f"Reached discovery cap of {max_hosts} hosts; stopping discovery to keep output concise.")
                        break
        except KeyboardInterrupt:
            print("\nDiscovery interrupted by user.")
            executor.shutdown(wait=False)
            raise

    return discovered


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
    # Make target optional because discovery may supply targets
    parser.add_argument("target", nargs="?", help="Target hostname or IP address to scan (optional when using --discover)")
    parser.add_argument("--start", type=int, default=1, help="Start port (default: 1)")
    parser.add_argument("--end", type=int, default=1024, help="End port (default: 1024)")
    parser.add_argument("--workers", type=int, default=100, help="Number of worker threads (default: 100)")
    parser.add_argument("--timeout", type=float, default=0.5, help="Socket timeout in seconds (default: 0.5)")
    parser.add_argument("--no-verbose", dest="verbose", action="store_false", help="Do not print per-port status")
    parser.add_argument("--output", action="store_true", help="Write results to dated file")
    parser.add_argument("--outname", type=str, default="scan_results", help="Prefix for output filename (default: scan_results)")
    parser.add_argument("--format", choices=("txt", "csv", "json"), default="txt", help="Output file format (txt, csv, json)")
    # Discovery options
    parser.add_argument("--discover", help="Discover live hosts in a CIDR (e.g. 192.168.1.0/24)")
    parser.add_argument("--discover-port", type=int, default=80, help="TCP port used to probe hosts during discovery (default: 80)")
    parser.add_argument("--discover-max", type=int, default=50, help="Maximum number of discovered hosts to return (keeps output readable, default 50)")
    parser.add_argument("--scan-discovered", action="store_true", help="After discovery, run the port scan against discovered hosts")
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    # Basic validation
    if args.start < 1 or args.end > 65535 or args.start > args.end:
        print("Invalid port range. Ports must be 1-65535 and start <= end.")
        return

    # If discovery mode is used
    if args.discover:
        print(f"Discovering hosts in {args.discover} (probing TCP/{args.discover_port})...")
        try:
            discovered = discover_network(args.discover, probe_port=args.discover_port, timeout=args.timeout, workers=args.workers, max_hosts=args.discover_max)
        except KeyboardInterrupt:
            print("Discovery aborted by user.")
            return

        if not discovered:
            print("No hosts discovered.")
            return

        print("\nDiscovered hosts:")
        for ip in discovered:
            print(f" - {ip}")

        # Optionally scan discovered hosts
        if args.scan_discovered:
            print("\nScanning discovered hosts (limited output)...")
            # Cap scanning to the discover_max to avoid excessive scans
            for ip in discovered:
                print(f"\nScanning host {ip}...")
                try:
                    open_ports = run_scan(ip, args.start, args.end, args.workers, args.timeout, args.verbose)
                except KeyboardInterrupt:
                    print("Scan aborted by user.")
                    return

                if open_ports:
                    print("Open ports:")
                    for p in open_ports:
                        print(f" - {p}")
                else:
                    print(" (none)")

                if args.output:
                    write_output(ip, args.start, args.end, args.workers, open_ports, outname_prefix=f"{args.outname}_{ip}", fmt=args.format)

        return

    # Standard single-target scan
    if not args.target:
        print("No target specified. Provide a target or use --discover to find hosts.")
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
