import os
import unittest
from src.shorstop.scanner import scan_path
from src.shorstop.quantum_analyzer import analyze_quantum_vulnerabilities, VulnerabilityLevel
import ast

class TestQuantumAnalyzer(unittest.TestCase):
    def setUp(self):
        self.test_dir = os.path.dirname(__file__)

    def test_detects_weak_rsa_keys(self):
        """Test detection of RSA keys vulnerable to quantum attacks."""
        test_code = """
from Crypto.PublicKey import RSA
key1024 = RSA.generate(1024)  # Critical vulnerability
key2048 = RSA.generate(2048)  # High vulnerability  
key3072 = RSA.generate(3072)  # Medium vulnerability
key4096 = RSA.generate(4096)  # Should be safe
"""
        tree = ast.parse(test_code)
        vulnerabilities = analyze_quantum_vulnerabilities(tree)
        
        # Should find 3 vulnerabilities (1024, 2048, 3072 bit keys)
        self.assertEqual(len(vulnerabilities), 3)
        
        # Check severity levels
        levels = [v.level for v in vulnerabilities]
        self.assertIn(VulnerabilityLevel.CRITICAL, levels)  # 1024-bit
        self.assertIn(VulnerabilityLevel.HIGH, levels)      # 2048-bit
        self.assertIn(VulnerabilityLevel.MEDIUM, levels)    # 3072-bit

    def test_detects_ecc_vulnerabilities(self):
        """Test detection of ECC vulnerabilities."""
        test_code = """
from Crypto.PublicKey import ECC
key = ECC.generate(curve='P-256')
"""
        tree = ast.parse(test_code)
        vulnerabilities = analyze_quantum_vulnerabilities(tree)
        
        self.assertEqual(len(vulnerabilities), 1)
        self.assertEqual(vulnerabilities[0].level, VulnerabilityLevel.HIGH)
        self.assertIn("ECC", vulnerabilities[0].description)

    def test_detects_dsa_vulnerabilities(self):
        """Test detection of DSA vulnerabilities."""
        test_code = """
from Crypto.PublicKey import DSA
key = DSA.generate(2048)
"""
        tree = ast.parse(test_code)
        vulnerabilities = analyze_quantum_vulnerabilities(tree)
        
        self.assertEqual(len(vulnerabilities), 1)
        self.assertEqual(vulnerabilities[0].level, VulnerabilityLevel.HIGH)
        self.assertIn("DSA", vulnerabilities[0].description)

    def test_detects_weak_hash_functions(self):
        """Test detection of weak hash functions."""
        test_code = """
import hashlib
md5_hash = hashlib.md5(b'data')
sha1_hash = hashlib.sha1(b'data')
sha256_hash = hashlib.sha256(b'data')  # This should be safe
"""
        tree = ast.parse(test_code)
        vulnerabilities = analyze_quantum_vulnerabilities(tree)
        
        # Should find 2 vulnerabilities (MD5 and SHA1)
        self.assertEqual(len(vulnerabilities), 2)
        
        algorithms = [v.algorithm for v in vulnerabilities]
        self.assertIn("MD5", algorithms)
        self.assertIn("SHA1", algorithms)

    def test_detects_aes_key_sizes(self):
        """Test detection of AES with insufficient key sizes."""
        test_code = """
from Crypto.Cipher import AES
# 128-bit key (16 bytes)
weak_aes = AES.new(b'1234567890123456', AES.MODE_ECB)
# 256-bit key (32 bytes) - should be safe
strong_aes = AES.new(b'12345678901234567890123456789012', AES.MODE_ECB)
"""
        tree = ast.parse(test_code)
        vulnerabilities = analyze_quantum_vulnerabilities(tree)
        
        # Should find 1 vulnerability (128-bit AES)
        self.assertEqual(len(vulnerabilities), 1)
        self.assertIn("AES", vulnerabilities[0].description)
        self.assertIn("128-bit", vulnerabilities[0].description)

    def test_integration_with_scanner(self):
        """Test that quantum analysis integrates properly with the scanner."""
        test_code = "from Crypto.PublicKey import RSA\nkey = RSA.generate(2048)\n"
        test_file = os.path.join(self.test_dir, "temp_quantum_test.py")
        
        with open(test_file, "w") as f:
            f.write(test_code)
        
        try:
            matches = scan_path(test_file)
            
            # Should have import, usage, and quantum vulnerability
            self.assertTrue(len(matches) >= 3)
            
            # Check for quantum vulnerability in results
            quantum_matches = [m for m in matches if "quantum-vulnerable" in m[2]]
            self.assertTrue(len(quantum_matches) >= 1)
            
            # Verify the quantum vulnerability includes severity indicator
            quantum_desc = quantum_matches[0][2]
            self.assertTrue(any(icon in quantum_desc for icon in ["🚨", "🔺", "🔶", "🔸"]))
            
        finally:
            if os.path.exists(test_file):
                os.remove(test_file)

if __name__ == '__main__':
    unittest.main()