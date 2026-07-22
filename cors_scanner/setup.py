from setuptools import setup, find_packages

setup(
    name="cors_scanner",
    version="0.1.0",
    packages=find_packages(),
    install_requires=[
        "requests>=2.25.1",
    ],
    entry_points={
        "console_scripts": [
            "cors-scanner=cors_scanner.cli:main",
        ],
    },
)
