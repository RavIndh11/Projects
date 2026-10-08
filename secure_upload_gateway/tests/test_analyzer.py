import pytest
from app.analyzer import check_extension_mismatch, check_zip_slip, check_polyglot, analyze_file
import zipfile
import io

def test_extension_mismatch_safe():
    # Valid PDF with correct magic bytes
    pdf_content = b"%PDF-1.4\n1 0 obj\n<<\n/Title (Test)\n>>\nendobj\n"
    res = check_extension_mismatch("test.pdf", pdf_content)
    assert res["status"] == "safe"

def test_extension_mismatch_disallowed():
    res = check_extension_mismatch("test.exe", b"MZ\x90\x00\x03\x00\x00\x00")
    assert res["status"] == "danger"
    assert res["severity"] == "High"
    assert "Disallowed extension" in res["reason"]

def test_extension_mismatch_spoofed():
    # PDF extension, but content is an image (or other)
    # Using MZ header for executable
    res = check_extension_mismatch("fake.pdf", b"MZ\x90\x00\x03\x00\x00\x00")
    assert res["status"] == "danger"
    assert res["severity"] == "Critical"
    assert "Extension mismatch" in res["reason"]

def test_zip_slip_safe():
    res = check_zip_slip("test.txt", b"not a zip")
    assert res["status"] == "safe"
    assert res["reason"] == "Not a zip file"

    # Create valid zip in memory
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w') as zf:
        zf.writestr('safe.txt', 'hello')

    res = check_zip_slip("valid.zip", buf.getvalue())
    assert res["status"] == "safe"

def test_zip_slip_danger():
    # Create malicious zip in memory
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w') as zf:
        zf.writestr('../../../etc/passwd', 'root:x:0:0:')

    res = check_zip_slip("evil.zip", buf.getvalue())
    assert res["status"] == "danger"
    assert res["severity"] == "Critical"
    assert "Zip Slip detected" in res["reason"]

def test_polyglot_safe():
    res = check_polyglot(b"just normal text")
    assert res["status"] == "safe"

def test_polyglot_danger():
    res = check_polyglot(b"image data \xff\xd8\xff\xe0<?php system($_GET['cmd']); ?>")
    assert res["status"] == "danger"
    assert res["severity"] == "Critical"
    assert "Potential polyglot" in res["reason"]

def test_analyze_file_overall():
    # Good file
    pdf_content = b"%PDF-1.4\n1 0 obj\n<<\n/Title (Test)\n>>\nendobj\n"
    res = analyze_file("good.pdf", pdf_content)
    assert res["status"] == "safe"

    # Spoofed file
    res2 = analyze_file("bad.pdf", b"MZ\x90\x00\x03\x00\x00\x00")
    assert res2["status"] == "danger"
    assert res2["severity"] == "Critical"
