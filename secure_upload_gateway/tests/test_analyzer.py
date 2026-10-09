import pytest
import io
import zipfile
from app.analyzer import analyzer

def create_in_memory_zip(files_dict):
    """Helper to create a zip file in memory for testing."""
    in_memory_zip = io.BytesIO()
    with zipfile.ZipFile(in_memory_zip, 'w', zipfile.ZIP_DEFLATED) as zf:
        for filename, content in files_dict.items():
            zf.writestr(filename, content)
    return in_memory_zip.getvalue()

def test_analyze_safe_text_file():
    content = b"This is a safe text file."
    result = analyzer.analyze("safe.txt", content)
    assert result.is_safe is True
    assert result.risk_score == 0
    assert result.file_type == "text/plain"

def test_analyze_extension_spoofing():
    # Content of a text file, but named as PDF
    content = b"This is actually a text file."
    result = analyzer.analyze("spoofed.pdf", content)
    assert result.is_safe is False
    assert result.risk_score > 0
    assert "Extension spoofing detected" in str(result.threats_found)

def test_analyze_disallowed_extension():
    content = b"#!/bin/bash\necho 'hello'"
    result = analyzer.analyze("script.sh", content)
    assert result.is_safe is False
    assert "Disallowed extension" in str(result.threats_found)

def test_analyze_zip_slip_vulnerability():
    # Create a malicious zip file with path traversal
    zip_content = create_in_memory_zip({
        "../malicious.sh": b"echo 'hacked'"
    })
    result = analyzer.analyze("malicious.zip", zip_content)
    assert result.is_safe is False
    assert "Zip Slip vulnerability detected" in str(result.threats_found)

def test_analyze_zip_with_dangerous_file():
    # Create a zip containing a dangerous extension
    zip_content = create_in_memory_zip({
        "folder/payload.exe": b"fake_exe_content"
    })
    result = analyzer.analyze("payload.zip", zip_content)
    assert result.is_safe is False
    assert "Dangerous file type found in archive" in str(result.threats_found)

def test_analyze_safe_zip():
    # Create a safe zip file
    zip_content = create_in_memory_zip({
        "safe_folder/document.txt": b"safe content"
    })
    result = analyzer.analyze("safe.zip", zip_content)
    assert result.is_safe is True
    assert result.risk_score == 0
