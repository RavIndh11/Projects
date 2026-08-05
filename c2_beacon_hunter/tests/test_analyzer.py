import pytest
from datetime import datetime, timedelta
from app.models import NetworkLog
from app.analyzer import BeaconAnalyzer

@pytest.fixture
def analyzer():
    return BeaconAnalyzer(min_connections=5, max_jitter_percent=15.0, min_interval_seconds=1.0)

def generate_logs(src, dst, port, count, interval_sec, jitter_sec=0.0):
    logs = []
    base_time = datetime(2023, 1, 1, 12, 0, 0)
    current_time = base_time
    for i in range(count):
        # alternate adding/subtracting jitter
        jitter = jitter_sec if i % 2 == 0 else -jitter_sec
        actual_interval = interval_sec + jitter

        logs.append(NetworkLog(
            timestamp=current_time,
            src_ip=src,
            dst_ip=dst,
            dst_port=port,
            bytes_sent=100,
            bytes_received=200
        ))
        current_time += timedelta(seconds=actual_interval)
    return logs

def test_detects_perfect_beacon(analyzer):
    # 10 connections, exactly 60 seconds apart (0% jitter)
    logs = generate_logs("192.168.1.10", "10.0.0.5", 443, count=10, interval_sec=60)
    alerts = analyzer.analyze(logs)

    assert len(alerts) == 1
    assert alerts[0].src_ip == "192.168.1.10"
    assert alerts[0].dst_ip == "10.0.0.5"
    assert alerts[0].jitter_percent == 0.0
    assert alerts[0].severity == "High"  # < 10% jitter but not >20 conns

def test_detects_critical_beacon(analyzer):
    # 25 connections, exactly 60 seconds apart (0% jitter)
    logs = generate_logs("192.168.1.10", "10.0.0.5", 443, count=25, interval_sec=60)
    alerts = analyzer.analyze(logs)

    assert len(alerts) == 1
    assert alerts[0].severity == "Critical"

def test_ignores_high_jitter(analyzer):
    # 10 connections, 60s interval with 30s jitter (50% jitter, very noisy)
    logs = generate_logs("192.168.1.11", "10.0.0.6", 80, count=10, interval_sec=60, jitter_sec=30)
    alerts = analyzer.analyze(logs)

    assert len(alerts) == 0

def test_ignores_too_few_connections(analyzer):
    # Only 3 connections (min is 5)
    logs = generate_logs("192.168.1.12", "10.0.0.7", 443, count=3, interval_sec=60)
    alerts = analyzer.analyze(logs)

    assert len(alerts) == 0
