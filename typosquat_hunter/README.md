# Typosquat Hunter

## Project overview
Typosquat Hunter is a Python-based cybersecurity CLI tool designed to identify registered typosquatted domains targeting a given base domain. It generates potential variations of a domain and concurrently queries DNS records to see if any of these variations have been registered.

## Problem statement
Adversaries frequently register domain names that are visually similar to legitimate domains (typosquatting) to conduct phishing attacks, distribute malware, or intercept sensitive communications. Security teams need an automated way to detect these lookalike domains so they can monitor them or initiate takedown requests.

## Features
- Generates domain permutations using multiple strategies:
  - Omission (removing a character)
  - Repetition (duplicating a character)
  - Transposition (swapping adjacent characters)
  - Substitution (replacing a character with a keyboard-adjacent key)
- Concurrently resolves DNS queries for high performance.
- Checks both `A` records (web servers) and `MX` records (email servers).
- Supports text and JSON output for easy integration into SOC pipelines.

## Architecture or workflow
1. The tool takes a base domain (e.g., `example.com`) as input.
2. It splits the domain from its Top-Level Domain (TLD) and applies four permutation algorithms to the base name.
3. It appends the TLD back to each permutation to create a list of target domains.
4. Using a `ThreadPoolExecutor`, it concurrently queries the `A` and `MX` DNS records for every target domain.
5. Finally, it filters the results to show only those domains that successfully resolve and prints the output in the desired format.

## Installation instructions
1. Clone the repository.
2. Navigate to the project directory:
   ```bash
   cd typosquat_hunter
   ```
3. Install the dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Usage examples
Run the CLI tool and check a domain:
```bash
python3 -m typosquat_hunter.cli example.com
```

Adjust the concurrency level for faster scanning:
```bash
python3 -m typosquat_hunter.cli example.com -c 20
```

Output results in JSON format:
```bash
python3 -m typosquat_hunter.cli example.com -o json
```

## Security considerations
- The tool interacts with public DNS servers. Large numbers of queries might trigger rate-limiting by your ISP or DNS provider.
- Output from this tool indicates that a domain exists, but does not confirm malicious intent. Further manual investigation is required before taking action.

## Limitations
- Substitution permutations currently only account for a standard QWERTY keyboard layout.
- Homograph attacks (using similar characters from different alphabets) are not supported in this version.
- Extremely long domain names will generate a massive number of permutations, potentially taking a long time to scan and consuming significant bandwidth.

## Future improvements
- Implement support for internationalized domain names (IDN) and homograph attack detection.
- Add support for querying additional DNS record types (e.g., `NS`, `TXT`).
- Integrate WHOIS lookups to determine domain registration dates and registrar information.
- Allow scanning across multiple TLDs (e.g., `.net`, `.org`, `.io` instead of just the original TLD).
