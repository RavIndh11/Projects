import pytest
import json
import os
from dep_confusion_checker.parsers import parse_package_json, parse_requirements_txt

def test_parse_package_json(tmp_path):
    # Create a dummy package.json
    data = {
        "dependencies": {
            "requests": "^2.25.1",
            "internal-pkg-a": "1.0.0"
        },
        "devDependencies": {
            "pytest": "6.2.4"
        },
        "scripts": {
            "test": "echo \"Error: no test specified\" && exit 1"
        }
    }
    filepath = tmp_path / "package.json"
    with open(filepath, 'w') as f:
        json.dump(data, f)

    packages = parse_package_json(str(filepath))
    assert set(packages) == {"requests", "internal-pkg-a", "pytest"}

def test_parse_requirements_txt(tmp_path):
    # Create a dummy requirements.txt
    content = """
# This is a comment
requests==2.25.1
Django>=3.2.0 # Inline comment
internal-pkg-b
pytest[extras]>=6.0.0; python_version < '3.8'
-r other_reqs.txt
--extra-index-url https://test.pypi.org/simple/
"""
    filepath = tmp_path / "requirements.txt"
    with open(filepath, 'w') as f:
        f.write(content)

    packages = parse_requirements_txt(str(filepath))
    assert set(packages) == {"requests", "Django", "internal-pkg-b", "pytest"}

def test_parse_package_json_not_found():
    assert parse_package_json("nonexistent.json") == []

def test_parse_requirements_txt_not_found():
    assert parse_requirements_txt("nonexistent.txt") == []
