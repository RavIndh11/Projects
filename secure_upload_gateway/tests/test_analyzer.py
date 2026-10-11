import pytest
import io
import zipfile
from app.analyzer import analyze_file
from app.models import RiskSeverity

def test_analyze_safe_text_file():
    content = b"Hello world, this is a safe file."
    result = analyze_file("test.txt", content)

    assert result.filename == "test.txt"
    assert result.actual_mime == "text/plain"
    assert result.severity == RiskSeverity.SAFE
    assert len(result.findings) == 0

def test_analyze_dangerous_extension():
    content = b"print('hello')"
    result = analyze_file("test.py", content)

    assert result.severity == RiskSeverity.HIGH
    assert len(result.findings) >= 1
    assert any(f.threat_type == "dangerous_extension" for f in result.findings)

def test_analyze_extension_spoofing():
    # Content is text/plain, but extension says .jpg
    content = b"This is not a real image"
    result = analyze_file("fake_image.jpg", content)

    assert result.severity == RiskSeverity.HIGH
    assert any(f.threat_type == "extension_spoofing" for f in result.findings)
    assert result.actual_mime == "text/plain"

def test_analyze_polyglot():
    # Simulate a file that magic identifies as an image (we'll just force it or rely on the mock/heuristic)
    # Actually, magic needs a real magic header to say it's an image.
    # Let's create a minimal valid GIF header followed by a PHP script.
    gif_header = b"GIF89a\x01\x00\x01\x00\x00\xff\x00,\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x00;"
    php_payload = b"<?php system($_GET['cmd']); ?>"
    content = gif_header + php_payload

    result = analyze_file("avatar.gif", content)

    assert result.actual_mime == "image/gif"
    assert result.severity == RiskSeverity.CRITICAL
    assert any(f.threat_type == "polyglot_suspected" for f in result.findings)

def test_analyze_zip_slip():
    # Create an in-memory zip file with a path traversal entry
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, "w") as zf:
        zf.writestr("../../../etc/passwd", b"root:x:0:0:root:/root:/bin/bash")

    content = zip_buffer.getvalue()
    result = analyze_file("malicious.zip", content)

    assert result.actual_mime in ['application/zip', 'application/x-zip-compressed']
    assert result.severity == RiskSeverity.CRITICAL
    assert any(f.threat_type == "zip_slip_vulnerability" for f in result.findings)
