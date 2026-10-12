import io
import zipfile
import magic
from typing import Dict, Any, Tuple
import os

# Mapping of some common extensions to MIME types
EXTENSION_MIME_MAP = {
    ".pdf": ["application/pdf"],
    ".png": ["image/png"],
    ".jpg": ["image/jpeg"],
    ".jpeg": ["image/jpeg"],
    ".zip": ["application/zip"],
    ".txt": ["text/plain"],
    ".csv": ["text/csv"]
}

def analyze_file(filename: str, content: bytes) -> Dict[str, Any]:
    """
    Analyzes the uploaded file content for security risks:
    - Extension spoofing / mismatched MIME type
    - Zip slip (if it's a zip file)
    """
    results = {
        "is_safe": True,
        "threats": [],
        "mime_type": "unknown",
        "size": len(content),
    }

    # 1. Check Magic Bytes / MIME Type
    try:
        mime = magic.from_buffer(content, mime=True)
        results["mime_type"] = mime
    except Exception as e:
        results["is_safe"] = False
        results["threats"].append(f"MIME detection failed: {str(e)}")
        return results

    # 2. Check Extension Spoofing
    _, ext = os.path.splitext(filename.lower())
    if ext in EXTENSION_MIME_MAP:
        expected_mimes = EXTENSION_MIME_MAP[ext]
        if mime not in expected_mimes:
            results["is_safe"] = False
            results["threats"].append(f"Extension spoofing detected: {ext} does not match {mime}")
    else:
         # If extension is not in our known list, we might just flag or pass based on policy.
         # For this gateway, we just record the mismatch if we want strictness, but let's just log it.
         pass

    # 3. Zip Slip Analysis
    if mime == "application/zip" or ext == ".zip":
        is_safe_zip, zip_threats = analyze_zip(content)
        if not is_safe_zip:
            results["is_safe"] = False
            results["threats"].extend(zip_threats)

    return results

def analyze_zip(content: bytes) -> Tuple[bool, list[str]]:
    """
    Analyzes a zip file entirely in memory to prevent Zip Slip and path traversal.
    """
    threats = []
    is_safe = True

    try:
        with zipfile.ZipFile(io.BytesIO(content)) as zf:
            for zip_info in zf.infolist():
                filename = zip_info.filename

                # Check for absolute paths
                if filename.startswith("/") or filename.startswith("\\"):
                    is_safe = False
                    threats.append(f"Zip Slip (absolute path): {filename}")

                # Check for directory traversal
                if "../" in filename or "..\\" in filename:
                    is_safe = False
                    threats.append(f"Zip Slip (directory traversal): {filename}")
    except zipfile.BadZipFile:
        is_safe = False
        threats.append("Invalid or corrupted ZIP file")
    except Exception as e:
        is_safe = False
        threats.append(f"Error processing ZIP: {str(e)}")

    return is_safe, threats
