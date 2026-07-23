from typing import List, Dict, Optional
from .parsers import parse_package_json, parse_requirements_txt
from .registry_clients import check_npm_package, check_pypi_package

class DependencyChecker:
    def __init__(self, ignore_scopes: Optional[List[str]] = None):
        """
        Initialize the checker.
        ignore_scopes: A list of NPM scopes (e.g., '@mycompany') to ignore.
        """
        self.ignore_scopes = ignore_scopes or []

    def _should_ignore(self, package_name: str) -> bool:
        """
        Check if a package should be ignored based on its scope.
        """
        for scope in self.ignore_scopes:
            if package_name.startswith(scope + '/'):
                return True
        return False

    def check_file(self, filepath: str, file_type: str) -> Dict[str, List[str]]:
        """
        Checks a dependency file for potentially vulnerable packages.

        Args:
            filepath: Path to the dependency file.
            file_type: 'npm' for package.json, 'pypi' for requirements.txt.

        Returns:
            A dictionary containing 'vulnerable' (not found on public registry)
            and 'safe' (found on public registry) package names.
        """
        results = {
            "vulnerable": [],
            "safe": [],
            "ignored": []
        }

        if file_type == 'npm':
            packages = parse_package_json(filepath)
            check_func = check_npm_package
        elif file_type == 'pypi':
            packages = parse_requirements_txt(filepath)
            check_func = check_pypi_package
        else:
            raise ValueError("Unsupported file type. Use 'npm' or 'pypi'.")

        for pkg in packages:
            if self._should_ignore(pkg):
                results["ignored"].append(pkg)
                continue

            exists = check_func(pkg)
            if exists:
                results["safe"].append(pkg)
            else:
                results["vulnerable"].append(pkg)

        return results
