# Auto-YARA Generator

## Project Overview
The **Auto-YARA Generator** is a fast, lightweight Python CLI tool designed to automatically generate YARA rules by statically analyzing a given file (binary or text). It streamlines the malware analysis and threat hunting process by automatically extracting metadata and interesting strings to create a ready-to-use YARA rule.

## Problem Statement
Creating YARA rules manually for malware samples can be tedious and time-consuming. Analysts typically have to run `strings` on a binary, manually pick out interesting indicators (like URLs, IP addresses, registry keys, or suspicious API calls), calculate file hashes, and then manually format this data into a YARA rule structure.

## Proposed Solution
This tool automates the repetitive parts of YARA rule creation. It statically extracts ASCII and Unicode (UTF-16LE) strings, applies regular expressions to filter for high-value Indicators of Compromise (IoCs), extracts file hashes and magic bytes, and formats everything into syntactically valid YARA rules.

## Features
- **String Extraction:** Automatically extracts both ASCII and UTF-16LE strings from binary files.
- **Smart Filtering:** Uses regex to identify and prioritize "interesting" strings, such as:
  - URLs and IP addresses
  - Email addresses
  - Windows file paths
  - Suspicious Windows API calls (e.g., `VirtualAlloc`, `CreateRemoteThread`)
  - Registry keys
- **Metadata Generation:** Automatically calculates MD5, SHA1, and SHA256 hashes and file size.
- **Magic Bytes Detection:** Detects PE (`MZ`) and ELF (`\x7fELF`) files and automatically adds the appropriate magic byte conditions to the rule.
- **CLI Interface:** Simple and easy-to-use command-line interface.

## Installation

This tool requires Python 3.6 or higher.

1. Clone the repository.
2. Navigate to the `yara_rule_generator` directory.
3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Usage Examples

Run the tool against a suspicious file:

```bash
python -m yara_generator.cli /path/to/suspicious.exe -n SuspiciousMalwareRule -a "John Doe"
```

Save the output directly to a file:

```bash
python -m yara_generator.cli /path/to/suspicious.exe -o my_rule.yar
```

### Example Output

```yara
rule SuspiciousMalwareRule {
    meta:
        author = "AutoGenerator"
        description = "Auto-generated YARA rule for suspicious.exe"
        filename = "suspicious.exe"
        md5 = "d41d8cd98f00b204e9800998ecf8427e"
        sha1 = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        size = 1048576

    strings:
        $s0 = "http://malicious-c2.com/payload.bin" ascii wide
        $s1 = "VirtualAlloc" ascii wide
        $s2 = "C:\\\\Windows\\\\System32\\\\cmd.exe" ascii wide

    condition:
        uint16(0) == 0x5a4d and 1 of ($s*)
}
```

## Security Considerations
- **Static Analysis Only:** This tool performs static analysis. It does not execute the target files, making it safe to run against live malware samples on your analysis machine.
- **Data Privacy:** All processing is done locally. No file data, hashes, or strings are sent to any external servers or APIs.

## Limitations
- Obfuscated or packed malware will yield very few interesting strings statically. The tool does not automatically unpack binaries.
- The regex patterns for "interesting" strings are heuristic. They may occasionally capture false positives or miss highly specific, custom obfuscated strings.
- The generated rule relies on basic string matching. For highly resilient rules, an analyst should manually refine the auto-generated rule (e.g., converting strings to hex sequences or adding complex logical conditions).

## Future Improvements
- **Integration with Capstone/pefile:** Parse PE headers to extract import tables and section names automatically.
- **Hex Signature Generation:** Automatically generate wildcard hex signatures based on entry point opcodes.
- **Entropy Analysis:** Calculate file or section entropy and add it to the YARA rule metadata or conditions.
