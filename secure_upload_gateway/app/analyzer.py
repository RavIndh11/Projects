import os
import magic
import zipfile
import io
import re
from typing import Dict, Any

ALLOWED_MIME_TYPES = {
    ".pdf": "application/pdf",
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".txt": "text/plain",
    ".zip": "application/zip",
}

def check_extension_mismatch(filename: str, content: bytes) -> Dict[str, Any]:
    _, ext = os.path.splitext(filename.lower())
    if ext not in ALLOWED_MIME_TYPES:
        return {"status": "danger", "reason": f"Disallowed extension: {ext}", "severity": "High"}

    # Use python-magic to determine true MIME type
    mime = magic.Magic(mime=True)
    actual_mime = mime.from_buffer(content)

    if ALLOWED_MIME_TYPES[ext] != actual_mime:
        return {"status": "danger", "reason": f"Extension mismatch: {ext} -> {actual_mime}", "severity": "Critical"}

    return {"status": "safe", "reason": "Extension matches content", "severity": "None"}

def check_zip_slip(filename: str, content: bytes) -> Dict[str, Any]:
    _, ext = os.path.splitext(filename.lower())
    if ext != ".zip":
        return {"status": "safe", "reason": "Not a zip file", "severity": "None"}

    try:
        with zipfile.ZipFile(io.BytesIO(content), 'r') as zf:
            for name in zf.namelist():
                # Check for path traversal elements
                if ".." in name or name.startswith("/") or name.startswith("\\"):
                    return {"status": "danger", "reason": "Zip Slip detected (path traversal in archive)", "severity": "Critical"}
        return {"status": "safe", "reason": "No Zip Slip vulnerabilities found", "severity": "None"}
    except zipfile.BadZipFile:
        return {"status": "danger", "reason": "Invalid or corrupt Zip file", "severity": "Medium"}
    except Exception as e:
        return {"status": "danger", "reason": f"Error parsing zip: {str(e)}", "severity": "High"}

def check_polyglot(content: bytes) -> Dict[str, Any]:
    # Basic heuristic check for polyglots: PHP or JS tags within images/PDFs
    # Very rudimentary check: look for <?php, <script>

    suspicious_patterns = [
        b"<?php",
        b"<script",
        b"javascript:"
    ]

    for pattern in suspicious_patterns:
        if pattern in content.lower():
            return {"status": "danger", "reason": f"Potential polyglot detected: embedded script tag", "severity": "Critical"}

    return {"status": "safe", "reason": "No obvious polyglot signatures", "severity": "None"}

def analyze_file(filename: str, content: bytes) -> Dict[str, Any]:
    results = {
        "filename": filename,
        "size": len(content),
        "status": "safe",
        "findings": [],
        "severity": "None"
    }

    # 1. Check extension mismatch
    ext_result = check_extension_mismatch(filename, content)
    if ext_result["status"] != "safe":
        results["status"] = "danger"
        results["findings"].append(ext_result["reason"])
        if results["severity"] != "Critical":
            results["severity"] = ext_result["severity"]

    # 2. Check Zip Slip (if zip)
    zip_result = check_zip_slip(filename, content)
    if zip_result["status"] != "safe":
        results["status"] = "danger"
        results["findings"].append(zip_result["reason"])
        if results["severity"] != "Critical":
            results["severity"] = zip_result["severity"]

    # 3. Check for polyglots
    poly_result = check_polyglot(content)
    if poly_result["status"] != "safe":
        results["status"] = "danger"
        results["findings"].append(poly_result["reason"])
        if results["severity"] != "Critical":
            results["severity"] = poly_result["severity"]

    if not results["findings"]:
        results["findings"].append("No threats detected.")

    return results
