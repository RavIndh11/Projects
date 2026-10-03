import pytest
from app.validators import validate_file_extension, check_magic_bytes, check_polyglot, check_zip_slip, analyze_file
import zipfile
import io

def test_validate_file_extension():
    assert validate_file_extension("test.pdf") == ".pdf"
    assert validate_file_extension("archive.tar.gz") == ".gz"
    assert validate_file_extension("no_extension") == ""
    assert validate_file_extension("UPPERCASE.PDF") == ".pdf"

def test_check_magic_bytes():
    assert check_magic_bytes(b"%PDF-1.4\n...", ".pdf") == True
    assert check_magic_bytes(b"\x89PNG\r\n\x1a\n...", ".png") == True
    # Unknown extension returns True for now based on strictness policy
    assert check_magic_bytes(b"some random content", ".unknown") == True
    # Mismatched extension
    assert check_magic_bytes(b"MZ...", ".pdf") == False

def test_check_polyglot():
    assert check_polyglot(b"clean file content") == False
    assert check_polyglot(b"binary... <?php echo 'hacked'; ?> ...binary") == True
    assert check_polyglot(b"binary... <script>alert(1)</script> ...binary") == True
    assert check_polyglot(b"binary... <% out.println(\"hacked\"); %> ...binary") == True

def test_check_zip_slip():
    # Create a safe zip in memory
    safe_zip_io = io.BytesIO()
    with zipfile.ZipFile(safe_zip_io, 'w') as z:
        z.writestr("safe_file.txt", "content")
    assert check_zip_slip(safe_zip_io.getvalue()) == False

    # Create a malicious Zip Slip file in memory
    malicious_zip_io = io.BytesIO()
    with zipfile.ZipFile(malicious_zip_io, 'w') as z:
        z.writestr("../../../etc/passwd", "content")
    assert check_zip_slip(malicious_zip_io.getvalue()) == True

    # Not a zip file
    assert check_zip_slip(b"not a zip file") == False

def test_analyze_file_clean():
    content = b"%PDF-1.4\nClean Content"
    result = analyze_file("clean.pdf", content)
    assert result["is_safe"] == True
    assert result["severity"] == "Low"
    assert len(result["matched_rules"]) == 0

def test_analyze_file_extension_spoofing():
    content = b"Not a PDF"
    result = analyze_file("spoofed.pdf", content)
    assert result["is_safe"] == False
    assert result["severity"] == "High"
    assert "magic_bytes_mismatch" in result["matched_rules"]

def test_analyze_file_polyglot():
    content = b"%PDF-1.4\n<?php system($_GET['cmd']); ?>\nEOF"
    result = analyze_file("polyglot.pdf", content)
    assert result["is_safe"] == False
    assert result["severity"] == "Critical"
    assert "embedded_script_detected" in result["matched_rules"]

def test_analyze_file_zip_slip():
    malicious_zip_io = io.BytesIO()
    with zipfile.ZipFile(malicious_zip_io, 'w') as z:
        z.writestr("../../../etc/passwd", "content")

    result = analyze_file("malicious.zip", malicious_zip_io.getvalue())
    assert result["is_safe"] == False
    assert result["severity"] == "Critical"
    assert "zip_slip_vulnerability" in result["matched_rules"]
