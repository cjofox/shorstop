"""
Quantum vulnerability analysis for cryptographic implementations.

This module provides functionality to detect cryptographic patterns that are
vulnerable to quantum computing attacks and suggests quantum-resistant alternatives.
"""

import ast
from typing import List, Tuple, Optional, Dict, Any
from enum import Enum

class VulnerabilityLevel(Enum):
    """Severity levels for quantum vulnerabilities."""
    LOW = "LOW"
    MEDIUM = "MEDIUM" 
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

class QuantumVulnerability:
    """Represents a quantum computing vulnerability in cryptographic code."""
    
    def __init__(self, line_no: int, description: str, level: VulnerabilityLevel, 
                 suggestion: str, algorithm: str):
        self.line_no = line_no
        self.description = description
        self.level = level
        self.suggestion = suggestion
        self.algorithm = algorithm

class QuantumCryptoAnalyzer(ast.NodeVisitor):
    """AST visitor that analyzes cryptographic usage for quantum vulnerabilities."""
    
    def __init__(self):
        self.vulnerabilities: List[QuantumVulnerability] = []
        
    def visit_Call(self, node: ast.Call):
        """Analyze function calls for quantum-vulnerable crypto patterns."""
        if isinstance(node.func, ast.Attribute):
            value = node.func.value
            if isinstance(value, ast.Name):
                # Check RSA key generation
                if value.id == "RSA" and node.func.attr == "generate":
                    self._analyze_rsa_generation(node)
                # Check ECC usage
                elif value.id == "ECC" and node.func.attr in ["generate", "construct"]:
                    self._analyze_ecc_usage(node)
                # Check DSA usage (always vulnerable to quantum attacks)
                elif value.id == "DSA":
                    self._analyze_dsa_usage(node)
                # Check AES usage
                elif value.id == "AES" and node.func.attr == "new":
                    self._analyze_aes_usage(node)
                    
        # Check for symmetric crypto with insufficient key lengths
        self._analyze_symmetric_crypto(node)
        
        # Check for hash function usage
        self._analyze_hash_functions(node)
        
        self.generic_visit(node)
    
    def _analyze_rsa_generation(self, node: ast.Call):
        """Analyze RSA key generation for quantum vulnerabilities."""
        key_size = self._extract_key_size(node)
        
        if key_size is None:
            # Cannot determine key size, flag as potential issue
            vuln = QuantumVulnerability(
                line_no=node.lineno,
                description="RSA key generation with undetermined key size",
                level=VulnerabilityLevel.MEDIUM,
                suggestion="Use RSA keys ≥3072 bits or consider post-quantum alternatives like Kyber/Dilithium",
                algorithm="RSA"
            )
            self.vulnerabilities.append(vuln)
        elif key_size < 3072:
            # Quantum vulnerable RSA key size
            level = VulnerabilityLevel.CRITICAL if key_size <= 1024 else VulnerabilityLevel.HIGH
            vuln = QuantumVulnerability(
                line_no=node.lineno,
                description=f"RSA {key_size}-bit key is vulnerable to quantum attacks",
                level=level,
                suggestion="Use RSA keys ≥3072 bits or migrate to post-quantum algorithms (Kyber, Dilithium)",
                algorithm="RSA"
            )
            self.vulnerabilities.append(vuln)
        elif key_size < 4096:
            # Borderline case - may be vulnerable to future quantum computers
            vuln = QuantumVulnerability(
                line_no=node.lineno,
                description=f"RSA {key_size}-bit key may be vulnerable to advanced quantum attacks",
                level=VulnerabilityLevel.MEDIUM,
                suggestion="Consider RSA ≥4096 bits or post-quantum alternatives for long-term security",
                algorithm="RSA"
            )
            self.vulnerabilities.append(vuln)
    
    def _analyze_ecc_usage(self, node: ast.Call):
        """Analyze ECC usage for quantum vulnerabilities."""
        curve = self._extract_ecc_curve(node)
        
        # All traditional ECC curves are vulnerable to quantum attacks
        vuln = QuantumVulnerability(
            line_no=node.lineno,
            description=f"ECC curve '{curve or 'unspecified'}' is vulnerable to quantum attacks",
            level=VulnerabilityLevel.HIGH,
            suggestion="Migrate to post-quantum key exchange (Kyber) and signatures (Dilithium, Falcon)",
            algorithm="ECC"
        )
        self.vulnerabilities.append(vuln)
    
    def _analyze_dsa_usage(self, node: ast.Call):
        """Analyze DSA usage - always vulnerable to quantum attacks."""
        vuln = QuantumVulnerability(
            line_no=node.lineno,
            description="DSA signatures are vulnerable to quantum attacks",
            level=VulnerabilityLevel.HIGH,
            suggestion="Replace with post-quantum signature schemes (Dilithium, Falcon, SPHINCS+)",
            algorithm="DSA"
        )
        self.vulnerabilities.append(vuln)
    
    def _analyze_aes_usage(self, node: ast.Call):
        """Analyze AES usage for quantum vulnerabilities."""
        # Check if key length is specified in the first argument (key)
        if node.args and len(node.args) > 0:
            # Try to infer key size from key length
            key_arg = node.args[0]
            if isinstance(key_arg, ast.Constant) and isinstance(key_arg.value, (str, bytes)):
                key_len = len(key_arg.value) * 8  # Convert bytes to bits
                if key_len < 256:
                    level = VulnerabilityLevel.HIGH if key_len <= 128 else VulnerabilityLevel.MEDIUM
                    vuln = QuantumVulnerability(
                        line_no=node.lineno,
                        description=f"AES {key_len}-bit key may be weakened by quantum attacks",
                        level=level,
                        suggestion="Use AES-256 for quantum resistance",
                        algorithm="AES"
                    )
                    self.vulnerabilities.append(vuln)
    
    def _analyze_hash_functions(self, node: ast.Call):
        """Analyze hash function usage for quantum vulnerabilities."""
        if isinstance(node.func, ast.Attribute):
            # Check for hashlib.md5(), hashlib.sha1(), etc.
            if isinstance(node.func.value, ast.Name) and node.func.value.id == "hashlib":
                func_name = node.func.attr.lower()
                if func_name in ["md5", "sha1"]:
                    vuln = QuantumVulnerability(
                        line_no=node.lineno,
                        description=f"Hash function {func_name.upper()} is cryptographically weak",
                        level=VulnerabilityLevel.HIGH,
                        suggestion="Use SHA-256, SHA-3, or other quantum-resistant hash functions",
                        algorithm=func_name.upper()
                    )
                    self.vulnerabilities.append(vuln)
    
    def _analyze_symmetric_crypto(self, node: ast.Call):
        """Analyze symmetric cryptography for quantum vulnerabilities."""
        if isinstance(node.func, ast.Attribute):
            func_name = node.func.attr.lower()
            
            # Check for other symmetric algorithms that might need attention
            if any(alg in func_name for alg in ["des", "3des", "blowfish", "rc4"]):
                vuln = QuantumVulnerability(
                    line_no=node.lineno,
                    description=f"Legacy algorithm {func_name.upper()} is cryptographically weak",
                    level=VulnerabilityLevel.CRITICAL,
                    suggestion="Replace with AES-256 or post-quantum symmetric algorithms",
                    algorithm=func_name.upper()
                )
                self.vulnerabilities.append(vuln)
    
    def _extract_key_size(self, node: ast.Call) -> Optional[int]:
        """Extract RSA key size from function call arguments."""
        if node.args and len(node.args) > 0:
            arg = node.args[0]
            if isinstance(arg, ast.Constant):
                return arg.value
            elif isinstance(arg, ast.Num):  # Python < 3.8 compatibility
                return arg.n
        return None
    
    def _extract_ecc_curve(self, node: ast.Call) -> Optional[str]:
        """Extract ECC curve name from function call arguments."""
        for arg in node.args:
            if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                return arg.value
            elif isinstance(arg, ast.Str):  # Python < 3.8 compatibility
                return arg.s
        
        # Check keyword arguments
        for keyword in node.keywords:
            if keyword.arg == "curve":
                if isinstance(keyword.value, ast.Constant):
                    return keyword.value.value
                elif isinstance(keyword.value, ast.Str):
                    return keyword.value.s
        
        return None
    
    def _extract_symmetric_key_size(self, node: ast.Call) -> Optional[int]:
        """Extract symmetric key size from function arguments."""
        # Look for key size indicators in arguments
        for arg in node.args:
            if isinstance(arg, ast.Constant) and isinstance(arg.value, int):
                # Common AES key sizes
                if arg.value in [128, 192, 256]:
                    return arg.value
        
        # Check keyword arguments for key_size, keysize, etc.
        for keyword in node.keywords:
            if keyword.arg in ["key_size", "keysize", "key_length"]:
                if isinstance(keyword.value, ast.Constant):
                    return keyword.value.value
                elif isinstance(keyword.value, ast.Num):
                    return keyword.value.n
        
        return None

def analyze_quantum_vulnerabilities(tree: ast.AST) -> List[QuantumVulnerability]:
    """Analyze an AST for quantum computing vulnerabilities."""
    analyzer = QuantumCryptoAnalyzer()
    analyzer.visit(tree)
    return analyzer.vulnerabilities