import io
import zipfile
import magic
import re
from typing import Dict, Any, List, Optional
from pydantic import BaseModel

class AnalysisResult(BaseModel):
    is_safe: bool
    risk_score: int
    threats_found: List[str]
    file_type: str
    details: Dict[str, Any]

class FileAnalyzer:
    def __init__(self):
        # Allowlist of extensions mapped to their expected MIME types
        self.allowed_types = {
            ".txt": "text/plain",
            ".csv": "text/csv",
            ".pdf": "application/pdf",
            ".jpg": "image/jpeg",
            ".jpeg": "image/jpeg",
            ".png": "image/png",
            ".zip": "application/zip",
            ".json": "application/json"
        }

        # High risk extensions that we generally block if embedded
        self.dangerous_extensions = re.compile(
            r'\.(exe|dll|bat|cmd|sh|php|pl|py|jsp|asp|aspx|js|vbs|msi)$',
            re.IGNORECASE
        )

    def analyze(self, file_name: str, content: bytes) -> AnalysisResult:
        threats = []
        risk_score = 0
        details = {}

        # 1. MIME Type Analysis (Extension Spoofing Check)
        mime_type = magic.from_buffer(content, mime=True)
        details["detected_mime"] = mime_type

        # Get extension
        ext_match = re.search(r'(\.[a-zA-Z0-9]+)$', file_name)
        extension = ext_match.group(1).lower() if ext_match else ""
        details["extension"] = extension

        if not extension:
            threats.append("No file extension provided")
            risk_score += 50
        elif extension not in self.allowed_types:
            threats.append(f"Disallowed extension: {extension}")
            risk_score += 100
        else:
            expected_mime = self.allowed_types[extension]
            if mime_type != expected_mime:
                threats.append(f"Extension spoofing detected: '{extension}' does not match '{mime_type}'")
                risk_score += 100

        # 2. Deep Inspection for ZIP archives (Zip Slip and Malicious content)
        if mime_type == "application/zip" or extension == ".zip":
            zip_threats = self._analyze_zip(content)
            if zip_threats:
                threats.extend(zip_threats)
                risk_score += 100

        # 3. Size check (Assuming relatively small files for this POC)
        file_size = len(content)
        details["file_size_bytes"] = file_size
        if file_size > 50 * 1024 * 1024: # 50MB
            threats.append("File exceeds maximum allowed size (50MB)")
            risk_score += 100

        is_safe = risk_score == 0

        return AnalysisResult(
            is_safe=is_safe,
            risk_score=risk_score,
            threats_found=threats,
            file_type=mime_type,
            details=details
        )

    def _analyze_zip(self, content: bytes) -> List[str]:
        threats = []
        try:
            # Process directly from memory to avoid disk I/O and path traversal
            with zipfile.ZipFile(io.BytesIO(content)) as zf:
                for info in zf.infolist():
                    filename = info.filename

                    # 2a. Zip Slip Check
                    # Check for absolute paths or path traversal sequences
                    if filename.startswith('/') or '..' in filename:
                        threats.append(f"Zip Slip vulnerability detected in path: {filename}")

                    # 2b. Dangerous Extensions in ZIP
                    if self.dangerous_extensions.search(filename):
                        threats.append(f"Dangerous file type found in archive: {filename}")
        except zipfile.BadZipFile:
            threats.append("Corrupted or malformed ZIP archive")
        except Exception as e:
            threats.append(f"Error parsing ZIP archive: {str(e)}")

        return threats

analyzer = FileAnalyzer()
