import json
import re

def parse_package_json(filepath: str) -> list[str]:
    """
    Parses a package.json file and extracts package names.
    Extracts from 'dependencies', 'devDependencies', 'peerDependencies', and 'optionalDependencies'.
    """
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            data = json.load(f)
    except FileNotFoundError:
        print(f"Error: File not found: {filepath}")
        return []
    except json.JSONDecodeError:
        print(f"Error: Invalid JSON format in: {filepath}")
        return []

    packages = set()
    dep_sections = ['dependencies', 'devDependencies', 'peerDependencies', 'optionalDependencies']

    for section in dep_sections:
        if section in data and isinstance(data[section], dict):
            packages.update(data[section].keys())

    return list(packages)

def parse_requirements_txt(filepath: str) -> list[str]:
    """
    Parses a requirements.txt file and extracts package names.
    Ignores comments, empty lines, and options (e.g., -r, --find-links).
    Strips off version specifiers.
    """
    packages = set()

    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            lines = f.readlines()
    except FileNotFoundError:
        print(f"Error: File not found: {filepath}")
        return []

    for line in lines:
        line = line.strip()
        # Ignore comments and empty lines
        if not line or line.startswith('#'):
            continue

        # Ignore common pip options (e.g., -r, -i, --extra-index-url)
        if line.startswith('-'):
            continue

        # Strip inline comments
        if ' #' in line:
            line = line.split(' #')[0].strip()

        # Match the package name before any version specifier, environment marker, or extras
        # Regex explanation:
        # ^([a-zA-Z0-9_\-\.]+) : capture the package name
        # (?:\[.*\])?          : optionally skip extras [foo,bar]
        # (?:[=<>!~].*)?       : optionally skip version specifiers ==1.0, >=2.0, etc.
        # (?:;.*)?             : optionally skip environment markers ; python_version < "3.8"
        match = re.match(r'^([a-zA-Z0-9_\-\.]+)', line)
        if match:
            package_name = match.group(1)
            # Filter out things that are just paths or dots that passed the loose regex
            if len(package_name) > 0 and package_name != '.':
                 packages.add(package_name)

    return list(packages)
