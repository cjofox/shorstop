# scanner.py
import os
from typing import List, Tuple

def scan_path(path: str) -> List[Tuple[str, int, str]]:
    print(f"Scanning path: {path}")
    
    if not os.path.exists(path):
        print(f"\n❌ Invalid path: {path}. Please provide a valid file or directory.")
        return []
        
    matches = []
    
    if os.path.isfile(path):
        _scan_file(matches, path)
        return matches
    elif os.path.isdir(path):
        for root, _, files in os.walk(path):
            for file_name in files:
                file_path = os.path.join(root, file_name)
                _scan_file(matches, file_path)
        return matches
    
    return []

def _scan_file(matches, file_path):
    if file_path.endswith((".py", ".js", ".cs", ".java")):
        with open(file_path, errors="ignore") as file_stream:
            for line_number, line in enumerate(file_stream, 1):
                if any(keyword in line for keyword in ["import rsa", "Crypto.PublicKey", "System.Security.Cryptography"]):
                    matches.append((file_path, line_number, line.strip()))
