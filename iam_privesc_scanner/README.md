# AWS IAM Privilege Escalation Scanner

## Overview

The AWS IAM Privilege Escalation Scanner is a lightweight, practical command-line tool designed to analyze AWS IAM policy documents (in JSON format) and identify potential privilege escalation vectors. It checks for common misconfigurations that could allow an attacker or a compromised user to gain higher privileges within an AWS account.

## Problem Statement

AWS IAM policies can be complex, and misconfigurations are common. Overly permissive policies (e.g., using `iam:*`) or specific combinations of actions (like `iam:PassRole` combined with `ec2:RunInstances`) can allow a user to escalate their privileges, potentially gaining full administrative control over the account. Manually reviewing policies for these combinations is time-consuming and error-prone.

## Features

- **Automated Scanning**: Quickly scan individual IAM policy JSON files or entire directories.
- **Known Vectors**: Detects 20+ known IAM privilege escalation vectors (based on research by Rhino Security Labs and others).
- **Wildcard Support**: Correctly handles wildcards (e.g., `iam:*` or `ec2:Run*`) when evaluating permissions.
- **Deny Overrides**: Respects `Deny` statements, which take precedence over `Allow` statements in AWS IAM.
- **JSON Output**: Supports machine-readable JSON output for easy integration into CI/CD pipelines or other security automation workflows.

## Architecture

The tool is built with a modular Python architecture:
- `core.py`: Contains the `PolicyEvaluator` class, which handles the logic of parsing policies, resolving wildcards, evaluating Allow/Deny statements, and matching against known vectors.
- `rules.py`: Defines the dictionary of known privilege escalation vectors and their required AWS actions.
- `scanner.py`: Provides the CLI interface using `argparse` to handle file/directory input and output formatting.

## Installation

```bash
# Clone the repository and navigate to the project directory
cd iam_privesc_scanner

# Install dependencies (pytest for testing)
pip install -r requirements.txt
```

## Usage

Scan a single policy file:
```bash
python scanner.py -f examples/vulnerable_passrole_ec2.json
```

Scan a directory of policies:
```bash
python scanner.py -d examples/
```

Output results in JSON format:
```bash
python scanner.py -d examples/ -o json
```

## Security Considerations

- **Local Execution**: This tool runs locally and analyzes static JSON files. It does not require AWS credentials and does not interact with the AWS API, ensuring no risk of credential exposure or unauthorized access during the scan.
- **No Sensitive Data**: Ensure the JSON policy files you scan do not contain hardcoded secrets, although standard IAM policies should not.

## Limitations

- **Resource Constraints**: Currently, the tool focuses on the `Action` and `Effect` elements of a policy. It assumes `Resource: "*"` for simplicity. A policy might allow an action but restrict it to a specific, safe resource, leading to a false positive in this scanner.
- **Condition Keys**: The tool does not currently evaluate IAM `Condition` keys (e.g., restricting access by source IP or MFA).
- **NotAction**: It does not fully support `NotAction` evaluations yet.

## Future Improvements

- Add support for evaluating `Resource` constraints to reduce false positives.
- Add support for parsing and evaluating `Condition` blocks.
- Integrate with `boto3` to allow directly fetching and scanning policies from an active AWS account.
- Add more granular reporting, showing exactly which statement triggered the finding.