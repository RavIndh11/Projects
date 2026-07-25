# Process Sentinel

## Overview
Process Sentinel is a lightweight, host-based intrusion detection script (EDR Lite) that monitors running processes for suspicious activity. It leverages configurable heuristics to identify potential threats such as unauthorized code execution from temporary directories, web servers spawning interactive shells, and the use of known reverse shell arguments.

## Problem Statement
Attackers frequently establish persistence and escalate privileges by running malicious payloads from world-writable directories (e.g., `/tmp`, `/dev/shm`), exploiting web vulnerabilities to spawn reverse shells, or using living-off-the-land (LotL) binaries (e.g., `nc`, `bash -c`). Traditional EDR solutions can be resource-intensive, complex to deploy, or unavailable on lightweight systems. A simple, rules-based process monitor is needed to provide immediate visibility into such malicious behaviors without the overhead of a full agent.

## Features
- **Continuous Monitoring:** Periodically scans running processes to detect newly spawned threats.
- **Rule-Based Detection:** Configurable JSON ruleset to define suspicious paths, web servers, shell processes, and arguments.
- **Heuristic Evaluation:** Detects:
  - Processes executing from suspicious directories (`/tmp`, `/dev/shm`).
  - Web servers (e.g., `nginx`, `apache2`) spawning shell processes (e.g., `bash`, `sh`).
  - Command-line arguments indicative of reverse shells or malicious intent (e.g., `nc`, `dev/tcp`).
- **Low Overhead:** Uses `psutil` to efficiently track processes and avoid re-evaluating long-running benign processes.

## Architecture
The script operates as a background daemon (or run once via a flag) that:
1. Loads configuration from `rules.json`.
2. Iterates over all active processes using `psutil`.
3. Maintains a set of seen processes (identified by PID and creation time) to optimize performance.
4. Evaluates unseen processes against the loaded rules.
5. Logs any detected suspicious activity in JSON format to the console (and standard Python logging system).

## Installation
1. Ensure Python 3.7+ is installed.
2. Install the required dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Usage
Run the script continuously with the default 5-second interval:
```bash
python3 sentinel.py
```

Run a single scan and output findings as JSON:
```bash
python3 sentinel.py --once
```

Specify a custom rules file or scan interval:
```bash
python3 sentinel.py --rules my_rules.json --interval 10
```

## Security Considerations
- **Privileges:** Process Sentinel requires sufficient privileges (e.g., root/Administrator) to inspect the command lines and parent processes of all system processes. Running as a standard user will limit its visibility (`AccessDenied` errors).
- **Evasion:** Sophisticated attackers may attempt to evade detection by altering process names (e.g., using `prctl` or copying binaries to non-monitored paths), obfuscating arguments, or injecting into benign processes. Process Sentinel relies on straightforward heuristics and should be part of a defense-in-depth strategy.
- **False Positives:** Legitimate administrative scripts or application behaviors might trigger alerts. The `rules.json` should be tuned to the specific environment to minimize noise.

## Limitations
- **Point-in-Time Scanning:** Since it polls at intervals, extremely short-lived processes (running for less than the scan interval) may be missed.
- **Not a Prevention Tool:** Process Sentinel only detects and logs; it does not block or terminate malicious processes.
- **Platform Dependency:** Behavior of `psutil` and process hierarchies may differ slightly between OS platforms. The current rules are primarily Linux-focused.

## Future Improvements
- **Event-Driven Monitoring:** Integrate with eBPF (on Linux) or ETW (on Windows) for real-time process creation events rather than polling.
- **Actionable Responses:** Add optional features to automatically kill detected threats or isolate the host.
- **SIEM Integration:** Support forwarding alerts to a centralized logging system (e.g., syslog, Splunk, Elastic) natively.
- **Advanced Heuristics:** Implement parent-child lineage analysis and anomaly detection using machine learning for more robust identification.
