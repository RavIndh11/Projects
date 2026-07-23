import requests

# Set a timeout for HTTP requests
TIMEOUT = 5

def check_npm_package(package_name: str) -> bool:
    """
    Checks if an NPM package exists on the public registry.
    Returns True if it exists (HTTP 200), False if it does not (HTTP 404),
    and assumes it exists (True) on other errors to avoid false positives.
    """
    url = f"https://registry.npmjs.org/{package_name}"
    try:
        response = requests.get(url, timeout=TIMEOUT)
        if response.status_code == 200:
            return True
        elif response.status_code == 404:
            return False
        else:
            # For 403, 500, etc., assume it exists to prevent false positives
            return True
    except requests.RequestException as e:
        print(f"Warning: Error checking NPM package '{package_name}': {e}")
        return True

def check_pypi_package(package_name: str) -> bool:
    """
    Checks if a PyPI package exists on the public registry.
    Returns True if it exists (HTTP 200), False if it does not (HTTP 404),
    and assumes it exists (True) on other errors to avoid false positives.
    """
    url = f"https://pypi.org/pypi/{package_name}/json"
    try:
        response = requests.get(url, timeout=TIMEOUT)
        if response.status_code == 200:
            return True
        elif response.status_code == 404:
            return False
        else:
             # For 403, 500, etc., assume it exists to prevent false positives
            return True
    except requests.RequestException as e:
         print(f"Warning: Error checking PyPI package '{package_name}': {e}")
         return True
