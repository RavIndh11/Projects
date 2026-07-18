import os
import pytest
import sys
from py_sast.scanner import scan_file, Vulnerability

@pytest.fixture
def vulnerable_file():
    # Return the path to the vulnerable sample
    return os.path.join(os.path.dirname(__file__), 'vulnerable_sample.py')

@pytest.fixture
def secure_file(tmp_path):
    secure_code = """
import hashlib
import subprocess

def safe_func():
    print("Hello")
    subprocess.call(['ls', '-l'])
    h = hashlib.sha256()
    """
    p = tmp_path / "secure_sample.py"
    p.write_text(secure_code)
    return str(p)

def test_eval_detected(vulnerable_file):
    vulns = scan_file(vulnerable_file)
    eval_vulns = [v for v in vulns if v.rule_id == 'SAST-001']
    assert len(eval_vulns) >= 1
    assert any("eval()" in v.description for v in eval_vulns)

def test_weak_crypto_detected(vulnerable_file):
    vulns = scan_file(vulnerable_file)
    crypto_vulns = [v for v in vulns if v.rule_id == 'SAST-002']
    assert len(crypto_vulns) >= 2
    assert any("md5" in v.description for v in crypto_vulns)
    assert any("sha1" in v.description for v in crypto_vulns)

def test_subprocess_shell_detected(vulnerable_file):
    vulns = scan_file(vulnerable_file)
    shell_vulns = [v for v in vulns if v.rule_id == 'SAST-003']
    assert len(shell_vulns) >= 1
    assert any("shell=True" in v.description for v in shell_vulns)

def test_secure_file(secure_file):
    vulns = scan_file(secure_file)
    assert len(vulns) == 0
