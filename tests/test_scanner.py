#test_scanner.py
import os
import unittest
from src.shorstop.scanner import scan_path

class TestShorstopScanner(unittest.TestCase):
    def setUp(self):
        self.test_dir = os.path.dirname(__file__)
        self.sample_file = os.path.join(self.test_dir, "..", "samples", "weak_rsa_example.py")

    def test_detects_weak_rsa_usage(self):
        matches = scan_path(self.sample_file)
        self.assertTrue(matches, "Expected crypto-related imports to be detected.")
        self.assertTrue(any("Crypto.PublicKey" in line for _, _, line in matches))

    def test_nonexistent_path(self):
        matches = scan_path("nonexistent_path.py")
        self.assertEqual(matches, [])

if __name__ == '__main__':
    unittest.main()