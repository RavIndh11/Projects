import magic
import zipfile
import io
import re
from pathlib import Path
from app.models import AnalysisResult, Finding, ThreatSeverity
from app.logger import logger

class FileAnalyzer:
    # Common extension to mime type mapping for basic validation
    MIME_MAP = {
        '.pdf': ['application/pdf'],
        '.jpg': ['image/jpeg'],
        '.jpeg': ['image/jpeg'],
        '.png': ['image/png'],
        '.gif': ['image/gif'],
        '.zip': ['application/zip'],
        '.txt': ['text/plain']
    }

    # Embedded scripts / executables signatures (basic regex approach for polyglots)
    PHP_REGEX = re.compile(rb'<\?php', re.IGNORECASE)
    JS_REGEX = re.compile(rb'<script', re.IGNORECASE)
    ELF_MAGIC = b'\x7FELF'
    PE_MAGIC = b'MZ'

    def analyze(self, filename: str, file_content: bytes) -> AnalysisResult:
        extension = Path(filename).suffix.lower()
        findings = []
        overall_severity = ThreatSeverity.NONE

        logger.info(f"Analyzing file", extra={"scan_filename": filename, "file_size": len(file_content)})

        # 1. Magic Bytes & Extension Spoofing
        mime_type = magic.from_buffer(file_content, mime=True)

        if extension in self.MIME_MAP:
            if mime_type not in self.MIME_MAP[extension]:
                findings.append(Finding(
                    vulnerability="Extension Spoofing",
                    severity=ThreatSeverity.HIGH,
                    description=f"File extension '{extension}' does not match detected MIME type '{mime_type}'"
                ))
                overall_severity = ThreatSeverity.HIGH
        else:
            findings.append(Finding(
                vulnerability="Unknown Extension",
                severity=ThreatSeverity.LOW,
                description=f"File extension '{extension}' is not in the recognized safe list"
            ))
            if overall_severity == ThreatSeverity.NONE:
                overall_severity = ThreatSeverity.LOW

        # 2. Embedded Scripts / Executables (Polyglots)
        # Check for PHP or JS in ostensibly non-script files (like images)
        if extension in ['.jpg', '.jpeg', '.png', '.gif', '.pdf']:
            if self.PHP_REGEX.search(file_content):
                findings.append(Finding(
                    vulnerability="Polyglot / Embedded Script",
                    severity=ThreatSeverity.CRITICAL,
                    description="PHP code detected inside a non-script file format"
                ))
                overall_severity = ThreatSeverity.CRITICAL
            elif self.JS_REGEX.search(file_content):
                findings.append(Finding(
                    vulnerability="Polyglot / Embedded Script",
                    severity=ThreatSeverity.CRITICAL,
                    description="JavaScript detected inside a non-script file format"
                ))
                overall_severity = ThreatSeverity.CRITICAL

        # Check for executables disguised as other files
        if file_content.startswith(self.ELF_MAGIC) or file_content.startswith(self.PE_MAGIC):
            if extension not in ['.exe', '.elf', '.bin']:
                findings.append(Finding(
                    vulnerability="Disguised Executable",
                    severity=ThreatSeverity.CRITICAL,
                    description="Executable magic bytes detected but extension suggests otherwise"
                ))
                overall_severity = ThreatSeverity.CRITICAL

        # 3. Zip Slip (Path Traversal in Archives)
        if mime_type == 'application/zip' or extension == '.zip':
            try:
                with zipfile.ZipFile(io.BytesIO(file_content)) as zf:
                    for zip_info in zf.infolist():
                        # Check for path traversal elements
                        if '../' in zip_info.filename or '..\\' in zip_info.filename or zip_info.filename.startswith('/'):
                            findings.append(Finding(
                                vulnerability="Zip Slip",
                                severity=ThreatSeverity.CRITICAL,
                                description=f"Path traversal characters found in archive entry: {zip_info.filename}"
                            ))
                            overall_severity = ThreatSeverity.CRITICAL
                            break # One finding is enough for the archive
            except zipfile.BadZipFile:
                findings.append(Finding(
                    vulnerability="Malformed Archive",
                    severity=ThreatSeverity.MEDIUM,
                    description="Failed to parse ZIP archive"
                ))
                if overall_severity in [ThreatSeverity.NONE, ThreatSeverity.LOW]:
                    overall_severity = ThreatSeverity.MEDIUM

        is_safe = overall_severity not in [ThreatSeverity.HIGH, ThreatSeverity.CRITICAL]

        result = AnalysisResult(
            filename=filename,
            is_safe=is_safe,
            overall_severity=overall_severity,
            findings=findings,
            mime_type=mime_type,
            extension=extension
        )

        logger.info(f"Analysis complete", extra={"scan_filename": filename, "is_safe": is_safe, "severity": overall_severity})
        return result
