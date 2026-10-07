import pytest
from app.detector import calculate_shannon_entropy, analyze_content

def test_entropy_calculation():
    # Regular text, low entropy
    text = "hello world"
    entropy = calculate_shannon_entropy(text)
    assert entropy > 0
    assert entropy < 4.0

    # Highly random string, high entropy
    b64_string = "V2h5IGFyZSB5b3UgcmVhZGluZyB0aGlzIGxvbA=="
    entropy2 = calculate_shannon_entropy(b64_string)
    assert entropy2 > 3.0

def test_analyze_clean_content():
    content = "<html><body>Hello, this is a normal page.</body></html>"
    result = analyze_content(content, "index.html")
    assert not result["is_malicious"]
    assert len(result["matched_signatures"]) == 0
    assert result["threat_level"] == "Low"
    assert result["risk_score"] < 40.0

def test_analyze_malicious_content():
    content = "<?php eval(base64_decode($_POST['cmd'])); ?>"
    result = analyze_content(content, "shell.php")
    assert result["is_malicious"]
    assert "eval_payload" in result["matched_signatures"]
    assert result["risk_score"] >= 30.0

def test_analyze_system_exec():
    content = '<?php system($_GET["cmd"]); ?>'
    result = analyze_content(content, "cmd.php")
    assert result["is_malicious"]
    assert "system_exec" in result["matched_signatures"]
