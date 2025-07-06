import os
import ast
import sys
from typing import List, Tuple
from .crypto_usage_visitor import CryptoUsageVisitor
from .quantum_analyzer import analyze_quantum_vulnerabilities, VulnerabilityLevel

CRYPTO_IMPORTS = {
    "rsa",
    "Crypto.PublicKey",
    "Crypto.PublicKey.RSA",
    "Crypto.PublicKey.ECC", 
    "Crypto.PublicKey.DSA",
    "Crypto.Cipher",
    "Crypto.Hash",
    "cryptography",
    "hashlib",
    "ecdsa",
    "pycryptodome",
}

# Custom exception for invalid paths
class InvalidPathError(Exception):
    pass

def scan_path(path: str) -> List[Tuple[str, int, str]]:
    if not os.path.exists(path):
        raise InvalidPathError(f"Invalid path: {path}. Please provide a valid file or directory.")

    matches = []

    if os.path.isfile(path):
        _scan_file(matches, path)
    elif os.path.isdir(path):
        for root, _, files in os.walk(path):
            for file_name in files:
                file_path = os.path.join(root, file_name)
                _scan_file(matches, file_path)

    return matches

def _scan_file(matches: List[Tuple[str, int, str]], file_path: str) -> None:
    if not file_path.endswith(".py"):
        return  # skip non-Python files

    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as file_stream:
            source = file_stream.read()
            tree = ast.parse(source, filename=file_path)

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if _is_crypto_import(alias.name):
                        matches.append((file_path, node.lineno, f"import: {alias.name}"))

            elif isinstance(node, ast.ImportFrom):
                module = node.module
                if module and _is_crypto_import(module):
                    imported_names = ", ".join(alias.name for alias in node.names)
                    matches.append((file_path, node.lineno, f"import: from {module} import {imported_names}"))

        visitor = CryptoUsageVisitor()
        visitor.visit(tree)
        for lineno, desc in visitor.matches:
            matches.append((file_path, lineno, f"usage: {desc}"))
        
        # Analyze for quantum vulnerabilities
        vulnerabilities = analyze_quantum_vulnerabilities(tree)
        for vuln in vulnerabilities:
            severity_icon = {
                VulnerabilityLevel.LOW: "🔸",
                VulnerabilityLevel.MEDIUM: "🔶", 
                VulnerabilityLevel.HIGH: "🔺",
                VulnerabilityLevel.CRITICAL: "🚨"
            }.get(vuln.level, "⚠️")
            
            vuln_desc = f"quantum-vulnerable: {severity_icon} {vuln.description} | Suggestion: {vuln.suggestion}"
            matches.append((file_path, vuln.line_no, vuln_desc))

    except SyntaxError as e:
        matches.append((file_path, e.lineno or 0, f"⚠️ Skipped (SyntaxError): {e.msg}"))

def _is_crypto_import(module_name: str) -> bool:
    return any(module_name.startswith(crypto) for crypto in CRYPTO_IMPORTS)

def scan_file_or_directory(path: str) -> List[Tuple[str, int, str]]:
    try:
        matches = scan_path(path)
    except InvalidPathError as e:
        print(f"❌ {e}")
        sys.exit(1)
    return matches
