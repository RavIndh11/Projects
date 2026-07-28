# GitHub Actions Security Scanner

## Project overview
`gh_actions_scanner` is a lightweight Python static analysis tool designed to scan GitHub Actions workflow YAML files for common security misconfigurations and vulnerabilities.

## Problem statement
CI/CD pipelines are increasingly targeted in supply chain attacks. Misconfigured GitHub Actions workflows can lead to severe consequences, such as secret exfiltration, unauthorized code execution, and privilege escalation. Identifying these issues manually is error-prone and time-consuming.

## Features
- **`pull_request_target` abuse detection:** Identifies workflows that trigger on `pull_request_target`, which can be dangerous if the workflow executes untrusted code.
- **Overly permissive tokens:** Detects usage of `permissions: write-all` globally or at the job level.
- **Unpinned third-party actions:** Highlights actions referenced by mutable tags (e.g., `@v2`) instead of immutable commit SHAs.
- **Script injection risks:** Finds potentially untrusted GitHub contexts (like `${{ github.event.issue.title }}`) used directly within `run` block scripts.
- **Output Formats:** Supports both plain text and JSON output for easy integration into CI/CD pipelines.

## Architecture or workflow
The tool operates as a command-line interface (CLI) that takes a directory path as input. It recursively traverses the directory to find YAML files, parses them using `PyYAML`'s `SafeLoader`, and evaluates the workflow's structure against a set of predefined security rules. The rules are implemented as methods within the `Scanner` class, which iterate over jobs and steps to identify risky patterns.

## Installation instructions

1. Ensure you have Python 3.7+ installed.
2. Clone the repository and navigate to the project directory:
   ```bash
   cd gh_actions_scanner
   ```
3. Install the required dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Usage examples

**Basic scan (Text output):**
```bash
python -m gh_actions_scanner.cli .github/workflows/
```

**JSON output (useful for CI/CD integration):**
```bash
python -m gh_actions_scanner.cli .github/workflows/ --format json
```

## Security considerations
- This tool is a static analyzer and may produce false positives (e.g., if an unpinned action is actually an internal repository action that uses a tag, though pinning to SHA is still a best practice).
- The scanner uses `yaml.safe_load` to prevent arbitrary code execution during the parsing of potentially malicious workflow files.
- The context injection rule searches for specific known-vulnerable contexts. Custom contexts or complex shell quoting might bypass the simple regex, requiring manual review.

## Limitations
- It does not dynamically execute the workflows or analyze the code within custom actions.
- The regex used for script injection detection might not catch all edge cases or heavily obfuscated injections.
- It doesn't trace environment variables or intermediate scripts; it only looks at the immediate string in the `run` block.

## Future improvements
- Implement checks for missing `CODEOWNERS` or branch protection bypasses.
- Add support for custom, user-defined rules (e.g., via a config file).
- Integrate a capability to automatically suggest remediation (e.g., auto-pinning actions to their current SHA).
- Add functionality to detect hardcoded secrets directly in the YAML files.