from app.analyzer import calculate_entropy, analyze_content

def test_entropy_clean():
    # A simple string should have low entropy
    entropy = calculate_entropy("hello world")
    assert entropy < 4.0

def test_entropy_high():
    # A random base64 looking string should have higher entropy
    entropy = calculate_entropy("aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789+/AaBbCcDdEeFf")
    assert entropy > 4.5

def test_analyze_clean():
    is_malicious, entropy, matched_signatures, severity = analyze_content("print('hello')")
    assert not is_malicious
    assert severity == "Low"
    assert len(matched_signatures) == 0

def test_analyze_signatures():
    is_malicious, entropy, matched_signatures, severity = analyze_content("system('ls')")
    assert is_malicious
    assert "system_execution" in matched_signatures
    assert severity in ["Medium", "High", "Critical"]

def test_analyze_critical():
    # 3 signatures
    payload = "eval(base64_decode(system('cat /etc/passwd')))"
    is_malicious, entropy, matched_signatures, severity = analyze_content(payload)
    assert is_malicious
    assert severity == "Critical"
    assert len(matched_signatures) >= 3
