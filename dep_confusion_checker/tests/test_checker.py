import pytest
from unittest.mock import patch
from dep_confusion_checker.checker import DependencyChecker

@patch('dep_confusion_checker.checker.parse_package_json')
@patch('dep_confusion_checker.checker.check_npm_package')
def test_checker_npm(mock_check_npm, mock_parse_npm):
    # Setup mocks
    mock_parse_npm.return_value = ["react", "internal-ui-lib"]
    def mock_npm_check(pkg):
        if pkg == "react":
            return True
        elif pkg == "internal-ui-lib":
            return False
    mock_check_npm.side_effect = mock_npm_check

    checker = DependencyChecker()
    results = checker.check_file("dummy.json", "npm")

    assert "react" in results["safe"]
    assert "internal-ui-lib" in results["vulnerable"]
    assert len(results["ignored"]) == 0

@patch('dep_confusion_checker.checker.parse_requirements_txt')
@patch('dep_confusion_checker.checker.check_pypi_package')
def test_checker_pypi(mock_check_pypi, mock_parse_pypi):
    # Setup mocks
    mock_parse_pypi.return_value = ["requests", "internal-api-client"]
    def mock_pypi_check(pkg):
        if pkg == "requests":
            return True
        elif pkg == "internal-api-client":
            return False
    mock_check_pypi.side_effect = mock_pypi_check

    checker = DependencyChecker()
    results = checker.check_file("dummy.txt", "pypi")

    assert "requests" in results["safe"]
    assert "internal-api-client" in results["vulnerable"]
    assert len(results["ignored"]) == 0

@patch('dep_confusion_checker.checker.parse_package_json')
@patch('dep_confusion_checker.checker.check_npm_package')
def test_checker_ignore_scopes(mock_check_npm, mock_parse_npm):
    mock_parse_npm.return_value = ["react", "@mycompany/internal-lib", "other-internal-lib"]

    def mock_npm_check(pkg):
        if pkg == "react":
            return True
        return False

    mock_check_npm.side_effect = mock_npm_check

    checker = DependencyChecker(ignore_scopes=["@mycompany"])
    results = checker.check_file("dummy.json", "npm")

    assert "react" in results["safe"]
    assert "other-internal-lib" in results["vulnerable"]
    assert "@mycompany/internal-lib" in results["ignored"]

def test_checker_invalid_type():
    checker = DependencyChecker()
    with pytest.raises(ValueError):
        checker.check_file("dummy", "invalid_type")
