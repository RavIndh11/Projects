import psutil
import json
import logging
import time
import os
import argparse
from typing import Dict, List, Any

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("ProcessSentinel")

class ProcessSentinel:
    def __init__(self, rules_path: str):
        self.rules = self.load_rules(rules_path)
        self.seen_processes = set()

    def load_rules(self, rules_path: str) -> Dict[str, List[str]]:
        try:
            with open(rules_path, 'r') as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Failed to load rules from {rules_path}: {e}")
            return {
                "suspicious_paths": ["/tmp", "/dev/shm"],
                "web_server_processes": ["apache2", "nginx"],
                "shell_processes": ["sh", "bash"],
                "suspicious_args": ["-i", "nc", "dev/tcp"]
            }

    def evaluate_process(self, proc: psutil.Process) -> Dict[str, Any]:
        alerts = []
        try:
            name = proc.name()
            exe = proc.exe() or ""
            cmdline = proc.cmdline() or []
            pid = proc.pid
            ppid = proc.ppid()

            # Rule 1: Execution from suspicious paths
            if exe:
                for path in self.rules.get("suspicious_paths", []):
                    if exe.startswith(path):
                        alerts.append(f"Process executed from suspicious path: {path}")

            # Rule 2: Web server spawning shell
            if name in self.rules.get("shell_processes", []):
                try:
                    parent = psutil.Process(ppid)
                    parent_name = parent.name()
                    if parent_name in self.rules.get("web_server_processes", []):
                        alerts.append(f"Web server ({parent_name}) spawned a shell ({name})")
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass

            # Rule 3: Suspicious arguments (reverse shell indicators)
            cmd_str = " ".join(cmdline).lower()
            for arg in self.rules.get("suspicious_args", []):
                if arg in cmd_str:
                    alerts.append(f"Suspicious argument '{arg}' found in command line")

            if alerts:
                return {
                    "pid": pid,
                    "ppid": ppid,
                    "name": name,
                    "exe": exe,
                    "cmdline": cmdline,
                    "alerts": alerts
                }
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass
        return {}

    def scan_once(self):
        found_alerts = []
        for proc in psutil.process_iter(['pid', 'create_time']):
            try:
                proc_id = (proc.pid, proc.info['create_time'])
                if proc_id in self.seen_processes:
                    continue

                self.seen_processes.add(proc_id)
                alert_info = self.evaluate_process(proc)

                if alert_info:
                    logger.warning(f"Suspicious activity detected: {json.dumps(alert_info)}")
                    found_alerts.append(alert_info)
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass
        return found_alerts

    def run(self, interval: int = 5):
        logger.info(f"Starting Process Sentinel. Scanning every {interval} seconds.")
        try:
            while True:
                self.scan_once()
                time.sleep(interval)
        except KeyboardInterrupt:
            logger.info("Process Sentinel stopped by user.")

def main():
    parser = argparse.ArgumentParser(description="Process Sentinel - Lightweight EDR")
    parser.add_argument("--rules", default="rules.json", help="Path to rules.json")
    parser.add_argument("--interval", type=int, default=5, help="Scan interval in seconds")
    parser.add_argument("--once", action="store_true", help="Run scan once and exit")
    args = parser.parse_args()

    rules_path = args.rules
    if not os.path.isabs(rules_path):
        # Resolve path relative to script directory
        script_dir = os.path.dirname(os.path.abspath(__file__))
        rules_path = os.path.join(script_dir, rules_path)

    sentinel = ProcessSentinel(rules_path)

    if args.once:
        alerts = sentinel.scan_once()
        if alerts:
            print(json.dumps(alerts, indent=2))
    else:
        sentinel.run(args.interval)

if __name__ == "__main__":
    main()
