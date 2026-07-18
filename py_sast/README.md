# Py-SAST (Python Static Application Security Testing)

## Overview
Py-SAST is a lightweight, local Static Application Security Testing (SAST) tool for Python. It parses Python source code using the built-in Abstract Syntax Tree (`ast`) module to identify common insecure coding patterns without executing the code.

## Problem Statement
Python applications often contain easily detectable vulnerabilities such as the use of `eval()`, weak cryptography (`hashlib.md5`), or command injection risks (`subprocess` with `shell=True`). Finding these issues early in the development lifecycle (e.g., via CI/CD pipelines) is critical. Traditional SAST tools can be heavy or complex to set up. Py-SAST provides a fast, dependency-light alternative for catching these low-hanging fruits.

## Features
- **AST-Based Analysis**: Analyzes code structure rather than text/regex, leading to fewer false positives.
- **Rule Set**:
    - `SAST-001`: Detects dangerous function calls (`eval()`, `exec()`).
    - `SAST-002`: Detects weak cryptographic hashing (`md5`, `sha1`).
    - `SAST-003`: Detects command injection risks (`subprocess.call`, `Popen`, `run` with `shell=True`).
- **File and Directory Scanning**: Scan a single file or recursively scan an entire directory.
- **Lightweight**: Uses standard library modules for scanning; no massive third-party dependencies required.

## Architecture
1. **Input Parsing**: The tool accepts a file or directory path.
2. **AST Generation**: For each `.py` file, it reads the source and uses `ast.parse()` to generate the Abstract Syntax Tree.
3. **Node Visiting**: A custom `ast.NodeVisitor` walks the tree and inspects specific nodes (e.g., `ast.Call`).
4. **Rule Evaluation**: Evaluates nodes against security rules.
5. **Reporting**: Outputs identified vulnerabilities with their rule ID, file path, and line number. Returns a non-zero exit code if vulnerabilities are found, making it suitable for CI/CD.

## Installation
Clone the repository and install the minimal dependencies:

```bash
git clone <your-repo-url>
cd py_sast
pip install -r requirements.txt
```

## Usage Examples

Scan a single file:
```bash
python scanner.py my_app.py
```

Scan an entire directory:
```bash
python scanner.py ./src
```

### Example Output

```
[*] Starting SAST scan on: tests/vulnerable_sample.py

[!] Found 5 potential vulnerabilities:

[SAST-001] tests/vulnerable_sample.py:5
    Reason: Use of dangerous function 'eval()' detected.

[SAST-001] tests/vulnerable_sample.py:9
    Reason: Use of dangerous function 'exec()' detected.

[SAST-002] tests/vulnerable_sample.py:13
    Reason: Use of weak cryptographic hash 'md5()' detected.

[SAST-002] tests/vulnerable_sample.py:17
    Reason: Use of weak cryptographic hash 'sha1()' detected.

[SAST-003] tests/vulnerable_sample.py:22
    Reason: Command injection risk: 'subprocess.call' called with shell=True.
```

## Security Considerations
- **Static Analysis Limits**: Static analysis cannot find all vulnerabilities (e.g., business logic flaws or runtime-only issues). It is meant to be a layer in a defense-in-depth strategy.
- **AST Parsing Security**: The `ast.parse()` function itself is generally safe and does not execute the code it parses, making it suitable for analyzing untrusted source code.

## Limitations
- The current rule set is basic and does not cover advanced vulnerabilities like complex path traversals, SQL injections (without ORM), or data flow analysis (taint tracking).
- Aliased imports (e.g., `import subprocess as sp; sp.call(..., shell=True)`) might evade some basic checks depending on how the AST is structured without full static type inference.

## Future Improvements
- **Data Flow Analysis (Taint Tracking)**: Track variables to see if user input reaches dangerous sinks.
- **Extended Rule Set**: Add checks for hardcoded credentials, insecure requests configurations (e.g., `verify=False`), and specific web framework vulnerabilities (e.g., Django, Flask).
- **Configuration File**: Allow users to enable/disable specific rules via a `.pysast.yml` configuration file.
- **Export Options**: Allow exporting results to JSON or SARIF formats for integration with CI/CD platforms like GitHub Advanced Security or GitLab CI.
