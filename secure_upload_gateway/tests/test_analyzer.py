import pytest
from app.analyzer import FileAnalyzer
from app.models import ThreatSeverity
import io
import zipfile

@pytest.fixture
def analyzer():
    return FileAnalyzer()

def test_safe_file(analyzer):
    content = b"This is a normal text file."
    result = analyzer.analyze("document.txt", content)

    assert result.is_safe is True
    assert result.overall_severity == ThreatSeverity.NONE
    assert len(result.findings) == 0
    assert result.extension == ".txt"

def test_extension_spoofing(analyzer):
    # A text file pretending to be a PDF
    content = b"This is just text, not a PDF."
    result = analyzer.analyze("document.pdf", content)

    assert result.is_safe is False
    assert result.overall_severity == ThreatSeverity.HIGH
    assert any("Spoofing" in f.vulnerability for f in result.findings)

def test_polyglot_php_in_image(analyzer):
    # Simulating an image with embedded PHP
    content = b"\xFF\xD8\xFF\xE0...some fake jpeg bytes... <?php system($_GET['cmd']); ?> ...more bytes..."
    result = analyzer.analyze("avatar.jpg", content)

    assert result.is_safe is False
    assert result.overall_severity == ThreatSeverity.CRITICAL
    assert any("Polyglot" in f.vulnerability for f in result.findings)

def test_disguised_executable(analyzer):
    # ELF magic bytes but with a .txt extension
    content = b"\x7FELF...some binary data..."
    result = analyzer.analyze("readme.txt", content)

    assert result.is_safe is False
    assert result.overall_severity == ThreatSeverity.CRITICAL
    assert any("Executable" in f.vulnerability for f in result.findings)

def test_zip_slip_detection(analyzer):
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, "w") as zf:
        zf.writestr("../evil.sh", b"echo 'hacked'")

    result = analyzer.analyze("archive.zip", zip_buffer.getvalue())

    assert result.is_safe is False
    assert result.overall_severity == ThreatSeverity.CRITICAL
    assert any("Zip Slip" in f.vulnerability for f in result.findings)

def test_unknown_extension(analyzer):
    content = b"some data"
    result = analyzer.analyze("file.xyz", content)

    assert result.is_safe is True  # Unknown ext is only LOW severity
    assert result.overall_severity == ThreatSeverity.LOW
    assert any("Unknown" in f.vulnerability for f in result.findings)
