# Simple Port Scanner (Python)

This repository contains an upgraded threaded TCP port scanner implemented in `main.py`.

It scans a range of TCP ports on a target host and can optionally save results to a timestamped file. The scanner now uses Python's
`concurrent.futures.ThreadPoolExecutor`, supports `--no-verbose` to reduce per-port output, and can write results in `txt`, `csv`, or `json` format.

Below is a row-by-row explanation of the new `main.py` so you can follow how it works and what each section does.

File: `main.py` (high-level sections)

- Shebang and module docstring
  - `#!/usr/bin/env python3` ensures the script runs with Python3 when executed directly.
  - The module docstring briefly describes the script and the new features.

- Imports
  - `argparse` to parse CLI arguments.
  - `datetime` and `json` for timestamped output files and JSON output.
  - `socket` to create TCP connections.
  - `ThreadPoolExecutor` and `as_completed` from `concurrent.futures` to scan ports concurrently.
  - `typing` for type hints.

- `scan_port(target, port, timeout)`
  - Uses `socket.create_connection((target, port), timeout=timeout)` which resolves the target and attempts to connect.
  - Returns `(port, True)` when a connection succeeds (port open), otherwise `(port, False)`.

- `run_scan(target, start, end, workers, timeout, verbose)`
  - Builds a thread pool with `max_workers=workers` and submits `scan_port` for each port in the range.
  - As each future completes, `future.result()` gives `(port, is_open)`.
  - If `verbose` is True, prints per-port status lines like `[+] Port 22 is open` or `[-] Port 23 is closed`.
  - Handles `KeyboardInterrupt` by politely asking the executor to shutdown and re-raising.
  - Returns a sorted list of open ports.

- `write_output(...)`
  - Creates a timestamped filename with the provided `outname_prefix` and the chosen `fmt` extension.
  - For `txt`, writes metadata and a simple list of open ports.
  - For `csv`, writes a single-column CSV with `port` header.
  - For `json`, writes a structured JSON object with metadata and `open_ports` array.

- `parse_args()`
  - New CLI options:
    - `--workers` instead of `--threads` (default 100)
    - `--no-verbose` to disable per-port printing
    - `--output` to save results
    - `--outname` to change filename prefix
    - `--format` choose between `txt`, `csv`, and `json`

- `main()`
  - Validates the port range.
  - Calls `run_scan` and prints a final summary of open ports.
  - If `--output` is set, calls `write_output` to save results.

Usage examples

- Scan localhost (print per-port output):

```bash
python main.py 127.0.0.1 --start 1 --end 1024
```

- Scan and save results as JSON with a custom filename prefix:

```bash
python main.py example.com --start 1 --end 65535 --workers 200 --output --format json --outname myscan
```

Notes and cautions
- Scanning networks or hosts without permission may be illegal or against terms of service. Only scan systems you own or have explicit permission to test.
- Use appropriate worker and timeout values for your network conditions to avoid false negatives or overwhelming your machine.


Discovery feature
-----------------

The scanner now includes a lightweight discovery mode to find live hosts inside a CIDR block using TCP connect probes. Discovery is intentionally concise and capped so you get a readable list instead of an endless output.

Flags:
- `--discover <CIDR>`: discover hosts in a CIDR range (e.g. `192.168.1.0/24`).
 - `--discover-ports <p1,p2,...>`: comma-separated list of ports to try during discovery (e.g. `22,80,443`). If provided, the discovery phase will consider a host "up" if any of the listed ports responds; this improves coverage compared to probing a single port.

Tip: to improve discovery coverage, try several ports commonly open in your environment. Example:

```bash
python main.py --discover 192.168.1.0/24 --discover-ports 22,80,443 --discover-max 100
```

Output behavior and progress
---------------------------

The scanner now reduces noisy per-port output by default (when `--no-verbose` is used). Instead of printing a line for every scanned port, the scanner prints periodic progress percentage updates and only lists the open ports at the end.

Behavior summary:
- Verbose (default): per-port status lines are printed, e.g. `[+] Port 22 is open` or `[-] Port 23 is closed`.
- Quiet (`--no-verbose`): periodic progress updates like `Progress: 20% (200/1000)` are printed roughly every 5% (or more frequently for small scans). At the end you get a short list of open ports only.

Examples:

- Verbose (per-port lines):

```bash
python main.py 10.0.0.5 --start 1 --end 200
```

- Quiet (progress percentages + final open ports):

```bash
python main.py 10.0.0.5 --start 1 --end 200 --no-verbose
```

Progress tuning (advanced):
- If you want more control over progress output frequency, let me add a `--progress-interval` option that prints progress every N ports or every N percent. Tell me if you want that and I'll add it.
```bash
python main.py --discover 127.0.0.1/32 --discover-port 80 --discover-max 10 --scan-discovered --no-verbose --start 1 --end 1024
```

Notes on discovery behavior:
- Discovery uses a TCP connect to a specified probe port; it does not use raw ICMP so it doesn't require elevated privileges.
- The discovery result list is capped at `--discover-max` to avoid overwhelming output; if the cap is reached a message will be printed and discovery stops early.
- After discovery, if `--scan-discovered` is used, scans are performed serially per discovered host to keep output clear. If you want parallel scanning across many hosts, consider scripting multiple runs or extending the tool.

