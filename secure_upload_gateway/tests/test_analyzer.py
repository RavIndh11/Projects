import pytest
import zipfile
import io
from app.analyzer import SecureUploadAnalyzer

@pytest.fixture
def analyzer():
    return SecureUploadAnalyzer()

def test_clean_png(analyzer):
    content = b"\x89PNG\r\n\x1a\n" + b"fake_png_data"
    result = analyzer.analyze_file("test.png", content)
    assert result["status"] == "clean"
    assert len(result["threats"]) == 0

def test_extension_spoofing(analyzer):
    # PDF magic bytes but named as PNG
    content = b"%PDF-1.4..."
    result = analyzer.analyze_file("document.png", content)
    assert result["status"] == "malicious"
    assert result["severity"] == "high"
    assert any(t["type"] == "extension_spoofing" for t in result["threats"])

def test_polyglot_payload(analyzer):
    # Valid PNG magic bytes + embedded PHP script
    content = b"\x89PNG\r\n\x1a\n" + b"fake_data<?php system($_GET['cmd']); ?>"
    result = analyzer.analyze_file("image.png", content)
    assert result["status"] == "malicious"
    assert result["severity"] == "critical"
    assert any(t["type"] == "polyglot_payload" for t in result["threats"])

def test_zip_slip_vulnerability(analyzer):
    # Create an in-memory zip file with a path traversal filename
    memory_zip = io.BytesIO()
    with zipfile.ZipFile(memory_zip, 'w') as zf:
        zf.writestr("../../../etc/passwd", "fake_passwd_content")

    content = memory_zip.getvalue()
    result = analyzer.analyze_file("archive.zip", content)

    assert result["status"] == "malicious"
    assert result["severity"] == "critical"
    assert any(t["type"] == "zip_slip" for t in result["threats"])

def test_clean_zip(analyzer):
    memory_zip = io.BytesIO()
    with zipfile.ZipFile(memory_zip, 'w') as zf:
        zf.writestr("safe_folder/safe_file.txt", "safe_content")

    content = memory_zip.getvalue()
    result = analyzer.analyze_file("clean.zip", content)

    assert result["status"] == "clean"
    assert len(result["threats"]) == 0
