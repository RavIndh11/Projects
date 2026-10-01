import pytest
from app.engine import scan_file_content, calculate_shannon_entropy

def test_entropy_calculation():
    low_entropy = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    high_entropy = "aB3$k9Lp!xQw2*rZ5^tY8&mN1#cE7(uJ4)vH6-gD0+fS"

    assert calculate_shannon_entropy(low_entropy) < 2.0
    assert calculate_shannon_entropy(high_entropy) > 4.5

def test_clean_file():
    content = "<?php echo 'Hello World'; ?>"
    findings = scan_file_content(content, "test.php")
    assert len(findings) == 0

def test_php_eval_signature():
    content = "<?php eval($_POST['cmd']); ?>"
    findings = scan_file_content(content, "shell.php")
    assert len(findings) == 1
    assert findings[0].severity == "Critical"
    assert findings[0].type == "Known Signature"
    assert "eval" in findings[0].description.lower()

def test_php_system_signature():
    content = "<?php system($_GET['c']); ?>"
    findings = scan_file_content(content, "shell.php")
    assert len(findings) == 1
    assert findings[0].severity == "Critical"
    assert "System" in findings[0].description

def test_high_entropy_obfuscation():
    # Construct a string that looks like a base64 encoded payload, long enough to trigger (100+)
    import os, base64
    payload = base64.b64encode(os.urandom(200)).decode('utf-8')
    content = f"<?php $x = '{payload}'; eval(base64_decode($_POST['x'])); ?>"
    findings = scan_file_content(content, "obfuscated.php")

    types = [f.type for f in findings]
    assert "Obfuscation" in types
    assert "Known Signature" in types # should also catch the base64_decode

def test_unknown_extension_fallback():
    # Should fallback to checking PHP signatures for unknown extensions
    content = "<?php system($_GET['x']); ?>"
    findings = scan_file_content(content, "unknown_file.xyz")
    assert len(findings) > 0
    assert findings[0].severity == "Critical"
