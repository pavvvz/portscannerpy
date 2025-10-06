# Simple Port Scanner (Python)

This repository contains a small threaded TCP port scanner implemented in `main.py`.

It scans a range of TCP ports on a target host and optionally writes results to a dated output file named `scan_results_<MM-DD-YYYY_HH-MM-SS>.txt`.

Below is a row-by-row explanation of `main.py` so you can understand exactly what each line does.

File: `main.py`

1-3: Shebang and module docstring
 - #!/usr/bin/env python3
   - Tells the system to run this script with the user's python3 interpreter when executed directly.
 - Triple-quoted string
   - Provides a short description and usage example for the script.

5: from __future__ import annotations
 - Enables postponed evaluation of annotations (PEP 563) so type hints are stored as strings. Safe for modern Python.

7-13: imports
 - argparse: parse CLI arguments
 - datetime: build timestamped filenames
 - socket: create TCP sockets for scanning
 - threading: run worker threads
 - Queue from queue: thread-safe queue for ports to scan
 - typing: List for type hints

15-23: scan_port function
 - def scan_port(target: str, port: int, timeout: float = 1.0) -> bool:
   - Attempts a TCP connection to target:port using socket.socket.
 - s.settimeout(timeout): limits wait time for connection attempt.
 - s.connect_ex((target, port)) returns 0 on success (open), non-zero on failure.
 - Returns True if port is open, False otherwise. Any exceptions return False.

25-41: worker function
 - Each thread runs this function, repeatedly pulling a port from the queue and scanning it.
 - If the queue returns None, the worker treats that as a sentinel to exit.
 - If a port is open, it appends the port to the shared results list and prints a message.
 - q.task_done() signals the queue that the task has been processed.

43-86: run_scan function
 - Sets up the queue, enqueues the requested port range, and starts the worker threads.
 - Waits for the queue to be fully processed with q.join().
 - Sends None sentinel values to stop worker threads and joins them.
 - Sorts the results list of open ports.
 - If write_output is True, writes a text file with a timestamped filename containing scan metadata and the open ports.
 - Returns the list of open ports.

88-97: parse_args function
 - Defines CLI arguments:
   - target (positional): hostname or IP to scan
   - --start / --end: port range (defaults 1 to 1024)
   - --threads: number of worker threads (default 100)
   - --timeout: socket timeout in seconds (default 0.5)
   - --output: boolean flag to write results to a dated file

99-120: main function
 - Parses arguments and validates the port range.
 - Calls run_scan with the provided options and prints the final summary of open ports.

122-123: if __name__ == "__main__":
 - Standard Python pattern so the script runs main() when executed directly.

Usage examples
 - Scan localhost common ports and print output:

```bash
python main.py 127.0.0.1 --start 1 --end 1024
```

 - Scan with output file saved (file name includes timestamp):

```bash
python main.py example.com --start 1 --end 65535 --threads 200 --output
```

Notes and cautions
 - Scanning networks or hosts without permission may be illegal or against terms of service. Only scan systems you own or have explicit permission to test.
 - Use appropriate thread and timeout values for your network conditions.

Optional improvements (left as exercises)
 - Add reverse DNS or service banner grabbing.
 - Add async/asyncio-based scanner for potentially higher throughput.
 - Add CSV/JSON output formats and more detailed logging.
