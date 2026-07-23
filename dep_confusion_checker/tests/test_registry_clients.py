import pytest
from unittest.mock import patch, Mock
import requests
from dep_confusion_checker.registry_clients import check_npm_package, check_pypi_package

@patch('dep_confusion_checker.registry_clients.requests.get')
def test_check_npm_package_exists(mock_get):
    mock_response = Mock()
    mock_response.status_code = 200
    mock_get.return_value = mock_response

    assert check_npm_package("requests") == True
    mock_get.assert_called_once_with("https://registry.npmjs.org/requests", timeout=5)

@patch('dep_confusion_checker.registry_clients.requests.get')
def test_check_npm_package_not_exists(mock_get):
    mock_response = Mock()
    mock_response.status_code = 404
    mock_get.return_value = mock_response

    assert check_npm_package("this-package-should-not-exist-12345") == False
    mock_get.assert_called_once_with("https://registry.npmjs.org/this-package-should-not-exist-12345", timeout=5)

@patch('dep_confusion_checker.registry_clients.requests.get')
def test_check_npm_package_error(mock_get):
    mock_get.side_effect = requests.RequestException("Network error")

    # Should assume True on error to avoid false positives
    assert check_npm_package("requests") == True

@patch('dep_confusion_checker.registry_clients.requests.get')
def test_check_pypi_package_exists(mock_get):
    mock_response = Mock()
    mock_response.status_code = 200
    mock_get.return_value = mock_response

    assert check_pypi_package("requests") == True
    mock_get.assert_called_once_with("https://pypi.org/pypi/requests/json", timeout=5)

@patch('dep_confusion_checker.registry_clients.requests.get')
def test_check_pypi_package_not_exists(mock_get):
    mock_response = Mock()
    mock_response.status_code = 404
    mock_get.return_value = mock_response

    assert check_pypi_package("this-package-should-not-exist-12345") == False
    mock_get.assert_called_once_with("https://pypi.org/pypi/this-package-should-not-exist-12345/json", timeout=5)

@patch('dep_confusion_checker.registry_clients.requests.get')
def test_check_pypi_package_error(mock_get):
    mock_get.side_effect = requests.RequestException("Network error")

    # Should assume True on error to avoid false positives
    assert check_pypi_package("requests") == True
