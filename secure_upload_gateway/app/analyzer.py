import os
import zipfile
import io
import re
from typing import Dict, Any, List

class SecureUploadAnalyzer:
    def __init__(self):
        # Common magic bytes mapping for validation
        self.magic_signatures = {
            b"\x89PNG\r\n\x1a\n": "png",
            b"\xff\xd8\xff": "jpg",
            b"GIF87a": "gif",
            b"GIF89a": "gif",
            b"%PDF-": "pdf",
            b"PK\x03\x04": "zip"
        }

        # Polyglot signatures commonly found embedded in image/file uploads
        self.polyglot_signatures = [
            rb"<\?php",
            rb"<script",
            rb"<%=",
            rb"eval\(",
            rb"system\(",
            rb"exec\(",
            rb"passthru\(",
            rb"shell_exec\(",
            rb"base64_decode\(",
            rb"cmd\.exe",
            rb"/bin/sh",
            rb"/bin/bash"
        ]

    def analyze_file(self, filename: str, content: bytes) -> Dict[str, Any]:
        """Analyzes file content and returns a security report."""
        report = {
            "filename": filename,
            "status": "clean",
            "threats": [],
            "severity": "low"
        }

        # 1. Extension Spoofing Check (Magic Bytes)
        ext_threat = self._check_extension_spoofing(filename, content)
        if ext_threat:
            report["threats"].append(ext_threat)
            report["status"] = "malicious"
            report["severity"] = "high"

        # 2. Polyglot Check
        polyglot_threat = self._check_polyglot(content)
        if polyglot_threat:
            report["threats"].append(polyglot_threat)
            report["status"] = "malicious"
            report["severity"] = "critical"

        # 3. Zip Slip Check (Only if zip file)
        if filename.lower().endswith(".zip") or content.startswith(b"PK\x03\x04"):
            zip_slip_threat = self._check_zip_slip(content)
            if zip_slip_threat:
                report["threats"].append(zip_slip_threat)
                report["status"] = "malicious"
                report["severity"] = "critical"

        return report

    def _check_extension_spoofing(self, filename: str, content: bytes) -> Dict[str, str]:
        ext = filename.split(".")[-1].lower() if "." in filename else ""

        matched_ext = None
        for sig, sig_ext in self.magic_signatures.items():
            if content.startswith(sig):
                matched_ext = sig_ext
                break

        # If we have a matching signature but the extension doesn't match
        if matched_ext and ext != matched_ext and not (matched_ext == "jpg" and ext == "jpeg"):
            return {
                "type": "extension_spoofing",
                "description": f"File extension '{ext}' does not match actual file type '{matched_ext}'"
            }

        # If it's a known extension but doesn't match expected magic bytes
        if ext in self.magic_signatures.values():
            if not matched_ext and not (ext == "jpeg" and content.startswith(b"\xff\xd8\xff")):
                 return {
                    "type": "extension_spoofing",
                    "description": f"File extension '{ext}' claimed, but file signature is missing/invalid"
                }

        return {}

    def _check_polyglot(self, content: bytes) -> Dict[str, str]:
        for sig in self.polyglot_signatures:
            if re.search(sig, content, re.IGNORECASE):
                return {
                    "type": "polyglot_payload",
                    "description": f"Detected potential embedded script/payload signature"
                }
        return {}

    def _check_zip_slip(self, content: bytes) -> Dict[str, str]:
        try:
            with zipfile.ZipFile(io.BytesIO(content)) as z:
                for info in z.infolist():
                    # Check for path traversal elements in filename
                    if "../" in info.filename or "..\\" in info.filename or info.filename.startswith("/") or info.filename.startswith("\\"):
                        return {
                            "type": "zip_slip",
                            "description": f"Zip Slip vulnerability detected: directory traversal path in zip entry '{info.filename}'"
                        }
        except zipfile.BadZipFile:
            pass # Invalid zip file, ignore for zip slip

        return {}
