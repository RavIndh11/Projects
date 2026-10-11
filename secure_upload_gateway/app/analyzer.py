import io
import zipfile
import magic
from typing import List, Dict, Any
from app.models import ScanResponse, RiskSeverity, ThreatFinding
from app.logger import get_logger

logger = get_logger(__name__)

# Known dangerous file signatures or extensions
DANGEROUS_EXTENSIONS = {'.exe', '.dll', '.sh', '.bat', '.cmd', '.php', '.jsp', '.py', '.rb'}
# Standard mime types mapped to expected extensions (simplified)
MIME_TO_EXTENSIONS = {
    'image/jpeg': {'.jpg', '.jpeg'},
    'image/png': {'.png'},
    'image/gif': {'.gif'},
    'application/pdf': {'.pdf'},
    'text/plain': {'.txt'},
    'text/html': {'.html', '.htm'},
    'application/zip': {'.zip'},
    'application/x-zip-compressed': {'.zip'}
}

def analyze_file(filename: str, content: bytes) -> ScanResponse:
    findings: List[ThreatFinding] = []
    # Use max() logic properly by assigning integer weights to severities
    severity_order = {
        RiskSeverity.SAFE: 0,
        RiskSeverity.LOW: 1,
        RiskSeverity.MED: 2,
        RiskSeverity.HIGH: 3,
        RiskSeverity.CRITICAL: 4
    }

    current_severity = RiskSeverity.SAFE

    def update_severity(new_severity):
        nonlocal current_severity
        if severity_order[new_severity] > severity_order[current_severity]:
            current_severity = new_severity

    # 1. Check File Size
    size_mb = len(content) / (1024 * 1024)
    if size_mb > 50: # Arbitrary large file limit for this example
        findings.append(ThreatFinding(
            threat_type="large_file",
            description=f"File is unusually large ({size_mb:.2f} MB)"
        ))
        update_severity(RiskSeverity.LOW)

    # 2. Extract Extension
    ext = ""
    if "." in filename:
        ext = "." + filename.split(".")[-1].lower()

    # 3. Detect Dangerous Extensions
    if ext in DANGEROUS_EXTENSIONS:
        findings.append(ThreatFinding(
            threat_type="dangerous_extension",
            description=f"File extension {ext} is considered dangerous."
        ))
        update_severity(RiskSeverity.HIGH)
        logger.warning(f"Dangerous extension detected: {ext}", extra={"scan_filename": filename})

    # 4. Use python-magic to detect actual MIME type
    try:
        actual_mime = magic.from_buffer(content, mime=True)
    except Exception as e:
        logger.error(f"Error determining MIME type: {e}")
        actual_mime = "application/octet-stream"

    # 5. Check Extension Spoofing (MIME mismatch)
    expected_exts = MIME_TO_EXTENSIONS.get(actual_mime)
    if expected_exts and ext not in expected_exts:
        findings.append(ThreatFinding(
            threat_type="extension_spoofing",
            description=f"MIME type '{actual_mime}' does not match extension '{ext}'."
        ))
        update_severity(RiskSeverity.HIGH)
        logger.warning(f"Extension spoofing detected: MIME {actual_mime} vs Ext {ext}", extra={"scan_filename": filename})
    elif not expected_exts and actual_mime != "application/octet-stream" and actual_mime != "text/plain":
         # If we have a mime type, but it's not in our map, and it's not generic, we could flag it, but let's be lenient for this simple example.
         pass


    # 6. Check for Polyglots (Very basic heuristic)
    # E.g., A file that is a valid image but also contains executable code or a script.
    # We look for common script tags or eval statements in non-text files if they are small enough
    if len(content) < 10 * 1024 * 1024: # Only scan small files for strings
        content_str = content.decode('utf-8', errors='ignore')
        if actual_mime.startswith('image/') or actual_mime == 'application/pdf':
            suspicious_strings = ['<?php', '<script', 'eval(', 'system(']
            for s in suspicious_strings:
                if s in content_str:
                    findings.append(ThreatFinding(
                        threat_type="polyglot_suspected",
                        description=f"Suspicious string '{s}' found in file with MIME type '{actual_mime}'."
                    ))
                    update_severity(RiskSeverity.CRITICAL)
                    logger.warning(f"Polyglot suspected: {s} found in {actual_mime}", extra={"scan_filename": filename})
                    break

    # 7. Check for Zip Slip if it's a zip file
    if actual_mime == 'application/zip' or actual_mime == 'application/x-zip-compressed' or ext == '.zip':
        try:
            with zipfile.ZipFile(io.BytesIO(content)) as zf:
                for zinfo in zf.infolist():
                    # Check for path traversal characters in the zip entries
                    if '..' in zinfo.filename or zinfo.filename.startswith('/'):
                        findings.append(ThreatFinding(
                            threat_type="zip_slip_vulnerability",
                            description=f"Path traversal detected in zip entry: {zinfo.filename}"
                        ))
                        update_severity(RiskSeverity.CRITICAL)
                        logger.warning(f"Zip Slip detected in {filename}: entry {zinfo.filename}", extra={"scan_filename": filename})
                        break # Only report once per zip
        except zipfile.BadZipFile:
             findings.append(ThreatFinding(
                threat_type="bad_zip_file",
                description="Failed to parse as a valid zip file."
             ))
             update_severity(RiskSeverity.LOW)
        except Exception as e:
             logger.error(f"Error during zip analysis: {e}")

    return ScanResponse(
        filename=filename,
        actual_mime=actual_mime,
        severity=current_severity,
        findings=findings
    )
