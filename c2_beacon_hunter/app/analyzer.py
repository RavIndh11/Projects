from typing import List, Dict, Tuple
from collections import defaultdict
import statistics
from .models import NetworkLog, BeaconAlert

class BeaconAnalyzer:
    def __init__(self, min_connections: int = 5, max_jitter_percent: float = 15.0, min_interval_seconds: float = 1.0):
        """
        Initialize the analyzer.
        :param min_connections: Minimum number of connections to consider for beaconing.
        :param max_jitter_percent: Maximum jitter percentage to flag as potential beacon (low jitter = more robotic).
        :param min_interval_seconds: Minimum average interval between connections.
        """
        self.min_connections = min_connections
        self.max_jitter_percent = max_jitter_percent
        self.min_interval_seconds = min_interval_seconds

    def analyze(self, logs: List[NetworkLog]) -> List[BeaconAlert]:
        alerts = []

        # Group connections by (src_ip, dst_ip, dst_port)
        grouped_logs: Dict[Tuple[str, str, int], List[NetworkLog]] = defaultdict(list)
        for log in logs:
            grouped_logs[(log.src_ip, log.dst_ip, log.dst_port)].append(log)

        for (src_ip, dst_ip, dst_port), connection_logs in grouped_logs.items():
            if len(connection_logs) < self.min_connections:
                continue

            # Sort logs by timestamp
            connection_logs.sort(key=lambda x: x.timestamp)

            # Calculate time intervals between consecutive connections
            intervals = []
            for i in range(1, len(connection_logs)):
                delta = (connection_logs[i].timestamp - connection_logs[i-1].timestamp).total_seconds()
                intervals.append(delta)

            if not intervals:
                continue

            # Calculate stats
            mean_interval = statistics.mean(intervals)

            # ⚡ Bolt: Early skip if mean_interval is below threshold.
            # Calculating standard deviation (statistics.pstdev) is computationally expensive.
            # Skipping it for traffic that doesn't meet the interval threshold
            # significantly improves analysis speed on large datasets.
            if mean_interval < self.min_interval_seconds:
                continue

            # If standard deviation is 0, jitter is 0
            if mean_interval == 0:
                jitter_percent = 0.0
            else:
                std_dev = statistics.pstdev(intervals)
                jitter_percent = (std_dev / mean_interval) * 100

            # Check if it matches beaconing profile (low jitter, sufficient frequency)
            if jitter_percent <= self.max_jitter_percent:
                # Determine severity based on jitter and connection count
                if jitter_percent < 5.0 and len(connection_logs) > 20:
                    severity = "Critical"
                elif jitter_percent < 10.0:
                    severity = "High"
                else:
                    severity = "Medium"

                alert = BeaconAlert(
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    dst_port=dst_port,
                    connection_count=len(connection_logs),
                    jitter_percent=round(jitter_percent, 2),
                    avg_interval_seconds=round(mean_interval, 2),
                    severity=severity,
                    description=f"Potential C2 beacon detected. {len(connection_logs)} connections with {round(jitter_percent, 2)}% jitter at ~{round(mean_interval, 2)}s intervals."
                )
                alerts.append(alert)

        return alerts
