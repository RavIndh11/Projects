# Dependency Confusion Checker

A lightweight command-line tool for detecting dependency confusion vulnerabilities in Python and Node.js projects.

## Problem Statement

Dependency confusion (also known as substitution attacks) occurs when a package manager (like npm or pip) attempts to download a package from a public registry instead of an intended private registry. If an internal, proprietary package name is not claimed on the public registry, an attacker can register that name and upload malicious code. When the build system or developer installs dependencies, the package manager may fetch the malicious public package due to higher version numbers or default registry prioritization.

## Overview and Solution

`dep_confusion_checker` parses your dependency files (`package.json` for Node.js, `requirements.txt` for Python) and checks the respective public registries (NPM and PyPI) for the existence of each package.

If a package exists in your dependency list but **does not exist** on the public registry, the tool flags it as potentially vulnerable to a dependency confusion attack.

## Features

- **Multi-Ecosystem Support:** Parses both `package.json` and `requirements.txt`.
- **Public Registry Verification:** Checks NPM and PyPI to see if a package is publicly registered.
- **Scope Ignoring:** Option to ignore specific NPM scopes (e.g., `@mycompany`) that are inherently safe from public squatting if the scope itself is protected.
- **JSON Output:** Supports JSON output for easy integration into CI/CD pipelines or other security automation tools.
- **False-Positive Reduction:** Network errors or rate limits default to assuming the package exists to prevent noisy false positives.

## Architecture

1. **Parsers (`parsers.py`):** Extracts raw package names from dependency files, stripping versions, environments, and extras.
2. **Registry Clients (`registry_clients.py`):** Makes HTTP requests to the public registries to check package availability.
3. **Checker Core (`checker.py`):** Coordinates the parsing and checking, managing ignore lists and categorizing results.
4. **CLI (`cli.py`):** Provides the user interface, arguments parsing, and formatted output generation.

## Installation

1. Clone the repository and navigate to the project folder:
   ```bash
   cd dep_confusion_checker
   ```
2. Install the required dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Usage

Run the tool by pointing it at a dependency file. It will auto-detect the file type based on the name.

```bash
python3 -m dep_confusion_checker path/to/package.json
python3 -m dep_confusion_checker path/to/requirements.txt
```

### Options

- **Force File Type (`-t`, `--type`):** If your file isn't named `package.json` or `requirements.txt`, you can force the type:
  ```bash
  python3 -m dep_confusion_checker my_deps.txt -t pypi
  ```
- **Ignore Scopes (`-i`, `--ignore-scopes`):** Ignore specific NPM scopes:
  ```bash
  python3 -m dep_confusion_checker package.json -i @mycompany @internal
  ```
- **JSON Output (`-j`, `--json`):** Get the results in JSON format:
  ```bash
  python3 -m dep_confusion_checker requirements.txt -j
  ```

## Security Considerations

- **Private Registries:** This tool checks *public* registries. It does not authenticate with or check your private registries.
- **Network Dependency:** The tool relies on outbound internet access to query NPM and PyPI.
- **Time-of-Check to Time-of-Use:** A package might be available on the public registry when checked, but if an attacker squats it with a very high version number, your package manager might still pull the malicious one depending on its configuration. This tool specifically checks for *unclaimed* names.

## Limitations

- Currently only supports Python (`requirements.txt`) and Node.js (`package.json`). Does not support `Pipfile`, `poetry.lock`, `yarn.lock`, or `package-lock.json` directly.
- Does not check if the *versions* on the public registry match what you expect, only if the package name is claimed.
- `requirements.txt` parsing is basic and might miss edge cases in highly complex pip configurations.

## Future Improvements

- Add support for lockfiles (`package-lock.json`, `yarn.lock`, `poetry.lock`) to analyze exactly what is being installed.
- Add support for other ecosystems (RubyGems, Maven, NuGet, Go).
- Check for typosquatting (e.g., `reqeusts` instead of `requests`).
- Verify package authors/signatures on public registries to ensure the claimed package is actually owned by the expected entity.
