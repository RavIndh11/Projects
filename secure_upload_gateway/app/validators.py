import re
import zipfile
import io
import mimetypes

# Define expected magic bytes for common file types
MAGIC_BYTES = {
    ".pdf": b"%PDF-",
    ".png": b"\x89PNG\r\n\x1a\n",
    ".jpg": b"\xff\xd8\xff",
    ".jpeg": b"\xff\xd8\xff",
    ".gif": b"GIF8",
    ".zip": b"PK\x03\x04",
}

# Regex to find common embedded scripts/polyglots
SUSPICIOUS_PATTERNS = [
    re.compile(br"<\?php", re.IGNORECASE),
    re.compile(b"<script", re.IGNORECASE),
    re.compile(b"<%"),  # ASP / JSP
]


def validate_file_extension(filename: str) -> str:
    """Extracts and normalizes file extension."""
    parts = filename.split(".")
    if len(parts) < 2:
        return ""
    return "." + parts[-1].lower()


def check_magic_bytes(content: bytes, ext: str) -> bool:
    """Verifies that the file content matches expected magic bytes for its extension."""
    if ext not in MAGIC_BYTES:
        # If we don't have a signature for it, we might accept or reject based on strictness.
        # For this gateway, we'll allow unknown types but maybe flag them in a real scenario.
        # Let's enforce strict checking for known types.
        return True

    magic = MAGIC_BYTES[ext]
    return content.startswith(magic)


def check_polyglot(content: bytes) -> bool:
    """Checks for embedded scripts in binary files."""
    for pattern in SUSPICIOUS_PATTERNS:
        if pattern.search(content):
            return True
    return False


def check_zip_slip(content: bytes) -> bool:
    """Checks for Zip Slip vulnerabilities in zip archives."""
    try:
        with zipfile.ZipFile(io.BytesIO(content)) as z:
            for info in z.infolist():
                # Check for path traversal characters
                if ".." in info.filename or info.filename.startswith("/"):
                    return True
    except zipfile.BadZipFile:
        # Not a valid zip file, can't be Zip Slip
        pass
    except Exception:
        # Other errors, assume safe or handle differently
        pass
    return False


def analyze_file(filename: str, content: bytes) -> dict:
    """Analyzes a file and returns the threat severity and matched rules."""
    ext = validate_file_extension(filename)
    results = {
        "is_safe": True,
        "severity": "Low",
        "matched_rules": [],
        "details": []
    }

    if not ext:
        results["details"].append("File has no extension.")

    # 1. Magic Bytes Check
    if not check_magic_bytes(content, ext):
        results["is_safe"] = False
        results["severity"] = "High"
        results["matched_rules"].append("magic_bytes_mismatch")
        results["details"].append(f"Content does not match extension '{ext}'. Possible spoofing.")

    # 2. Polyglot Check
    if check_polyglot(content):
        results["is_safe"] = False
        results["severity"] = "Critical"
        results["matched_rules"].append("embedded_script_detected")
        results["details"].append("Found suspicious embedded script tags (e.g., <?php, <script>).")

    # 3. Zip Slip Check
    if ext == ".zip":
        if check_zip_slip(content):
            results["is_safe"] = False
            results["severity"] = "Critical"
            results["matched_rules"].append("zip_slip_vulnerability")
            results["details"].append("Zip archive contains path traversal sequences (e.g., ../).")

    if results["is_safe"]:
         results["details"].append("No threats detected.")

    return results
