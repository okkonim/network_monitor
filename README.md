# Advanced Network Connection Monitor

A comprehensive, cross-platform tool for monitoring network connections and detecting suspicious activity. Built with Python, this monitor provides detailed insights into your system's network behavior.


## Overview

This tool is designed to help system administrators, security analysts, and curious users to:
- Get a detailed list of all active network connections.
- Establish a "baseline" of normal network activity.
- Detect anomalies by comparing the current state against the baseline.
- Identify potentially suspicious connections using various patterns.
- On Linux, detect advanced threats like hidden processes and network hiding techniques used by rootkits.

The script is designed to be cross-platform, with core features working on Windows, macOS, and Linux. Advanced, low-level detection capabilities are available on Linux systems.

## Key Features

- **Cross-Platform Support**: Core functionality works on any OS with Python and `psutil`.
- **Comprehensive Scans**: Gathers detailed information about connections, including PID, process name, local/remote addresses, and status.
- **Baseline Comparison**: Create a snapshot of normal network activity and compare against it later to find new or disappeared connections.
- **Flexible Filtering**: Sift through connections by PID, process name, port, connection type (TCP/UDP), state, and more.
- **Multiple Export Formats**: Save scan results as a detailed `JSON` file or a user-friendly `HTML` report.
- **Interactive Mode**: An easy-to-use menu for running common commands without remembering all the flags.
- **Database Logging**: Persistently stores alerts in an SQLite database for later review.

### Linux-Specific Features
- **Hidden Process Detection**: Discovers processes that are running but hidden from the standard `ps` utility.
- **Rootkit Network Hiding Check**: Compares network data from different sources (`psutil` vs. `/proc`) to find connections that might be hidden by a rootkit.
- **Network Namespace Scanning**: Identifies and inspects network activity within different network namespaces (used by containers and other tools).
- **Deep Packet Inspection**: (Requires `tcpdump`) Captures and performs a basic analysis of network packets to find potentially suspicious traffic patterns.

## Requirements

- Python 3.6+
- `psutil` library

## Installation

1.  **Clone the repository or download the source code.**
    ```bash
    git clone <repository_url>
    cd <repository_directory>
    ```

2.  **Install the required dependencies.**
    A `requirements.txt` file is included for easy installation.
    ```bash
    pip install -r requirements.txt
    ```

## Usage

The script can be run from the command line.

```bash
python3 network_monitor.py [COMMAND] [OPTIONS]
```

### Main Commands

| Command                 | Description                                                                                                   |
| ----------------------- | ------------------------------------------------------------------------------------------------------------- |
| (no command)            | Runs a quick default scan for active connections and basic suspicious patterns.                               |
| `--scan`                | Performs a full, comprehensive security scan. Recommended for a thorough analysis. (Requires `sudo` on Linux). |
| `--baseline`            | Creates a `network_baseline.json` file with a snapshot of the current network state.                          |
| `--compare`             | Compares the current network state against the saved baseline and reports anomalies.                          |
| `--monitor SECONDS`     | Enters continuous monitoring mode for the specified duration, logging any new connections.                      |
| `--interactive`, `-i`   | Starts an interactive menu to guide you through the available commands.                                       |
| `--detailed-help`       | Shows a detailed help message with all commands, filters, and examples.                                       |

### Examples

**1. Run a full security scan and generate an HTML report (recommended on Linux):**
```bash
sudo python3 network_monitor.py --scan --export html
```

**2. Create a baseline of normal activity:**
```bash
python3 network_monitor.py --baseline
```

**3. A day later, check for any new or unusual activity:**
```bash
python3 network_monitor.py --compare --verbose
```

**4. Show only established TCP connections to external IPs on port 443:**
```bash
python3 network_monitor.py --filter-type tcp --filter-state ESTABLISHED --only-external --filter-port 443
```

**5. Find all network activity from a process with "chrome" in its name:**
```bash
python3 network_monitor.py --filter-process chrome
```

**6. Monitor all network activity for the next 15 minutes (900 seconds):**
```bash
python3 network_monitor.py --monitor 900
```

### Platform Notes
- **Linux**: For best results, run with `sudo` to allow access to process details and enable low-level scanning features.
- **Windows**: Run as Administrator to get the most detailed information about running processes. Linux-specific features are unavailable.
- **macOS**: Works similarly to Windows. `sudo` may be required to view details for processes owned by other users. Linux-specific features are unavailable.

## Output Files

The script can generate the following files in the same directory:
- `network_scan_[timestamp].json`: A detailed JSON file containing all the raw data from a scan.
- `network_report_[timestamp].html`: A clean, readable HTML report summarizing the scan results.
- `network_baseline.json`: Stores the data for the baseline comparison.
- `network_monitor.db`: An SQLite database where all generated alerts are stored.

## License

This project is licensed under the MIT License.
