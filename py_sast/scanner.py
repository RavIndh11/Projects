import ast
import argparse
import sys
import os
from dataclasses import dataclass
from typing import List

@dataclass
class Vulnerability:
    file_path: str
    line_number: int
    rule_id: str
    description: str

class SecurityVisitor(ast.NodeVisitor):
    def __init__(self, file_path: str):
        self.file_path = file_path
        self.vulnerabilities: List[Vulnerability] = []

    def add_vuln(self, node: ast.AST, rule_id: str, description: str):
        self.vulnerabilities.append(
            Vulnerability(
                file_path=self.file_path,
                line_number=getattr(node, 'lineno', 0),
                rule_id=rule_id,
                description=description
            )
        )

    def visit_Call(self, node: ast.Call):
        # Check for eval() or exec()
        if isinstance(node.func, ast.Name):
            if node.func.id in ['eval', 'exec']:
                self.add_vuln(node, 'SAST-001', f"Use of dangerous function '{node.func.id}()' detected.")

        # Check for weak crypto (e.g., hashlib.md5)
        if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
            if node.func.value.id == 'hashlib' and node.func.attr in ['md5', 'sha1']:
                 self.add_vuln(node, 'SAST-002', f"Use of weak cryptographic hash '{node.func.attr}()' detected.")

        # Check for subprocess.call/Popen with shell=True
        if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
            if node.func.value.id == 'subprocess' and node.func.attr in ['call', 'Popen', 'run']:
                for kw in node.keywords:
                    if kw.arg == 'shell' and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                        self.add_vuln(node, 'SAST-003', f"Command injection risk: 'subprocess.{node.func.attr}' called with shell=True.")

        self.generic_visit(node)

def scan_file(file_path: str) -> List[Vulnerability]:
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            source = f.read()

        tree = ast.parse(source, filename=file_path)
        visitor = SecurityVisitor(file_path)
        visitor.visit(tree)
        return visitor.vulnerabilities
    except SyntaxError as e:
        print(f"[-] Syntax error parsing {file_path}: {e}", file=sys.stderr)
        return []
    except Exception as e:
         print(f"[-] Error scanning {file_path}: {e}", file=sys.stderr)
         return []

def scan_directory(dir_path: str) -> List[Vulnerability]:
    all_vulns = []
    for root, _, files in os.walk(dir_path):
        for file in files:
            if file.endswith('.py'):
                file_path = os.path.join(root, file)
                vulns = scan_file(file_path)
                all_vulns.extend(vulns)
    return all_vulns

def main():
    parser = argparse.ArgumentParser(description="Python Static Application Security Testing (SAST) Tool")
    parser.add_argument("target", help="File or directory to scan")

    args = parser.parse_args()
    target = args.target

    if not os.path.exists(target):
         print(f"[-] Target path '{target}' does not exist.", file=sys.stderr)
         sys.exit(1)

    print(f"[*] Starting SAST scan on: {target}")

    if os.path.isfile(target):
        vulns = scan_file(target)
    elif os.path.isdir(target):
        vulns = scan_directory(target)
    else:
        print(f"[-] Invalid target type.", file=sys.stderr)
        sys.exit(1)

    if vulns:
        print(f"\n[!] Found {len(vulns)} potential vulnerabilities:\n")
        for v in vulns:
            print(f"[{v.rule_id}] {v.file_path}:{v.line_number}")
            print(f"    Reason: {v.description}\n")
        sys.exit(1) # Exit with error code if vulns found
    else:
        print("\n[+] No vulnerabilities found. Good job!")
        sys.exit(0)

if __name__ == "__main__":
    main()
