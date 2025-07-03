import os
import unittest
from src.shorstop.scanner import InvalidPathError, scan_path

class TestScanner(unittest.TestCase):
    def setUp(self):
        self.test_dir = os.path.dirname(__file__)
        self.sample_file = os.path.join(self.test_dir, "..", "samples", "weak_rsa_example.py")

    def test_detects_weak_rsa_usage(self):
        matches = scan_path(self.sample_file)
        self.assertTrue(matches, "Expected crypto-related imports to be detected.")
        self.assertTrue(any("import:" in line and "Crypto.PublicKey" in line for _, _, line in matches))

    def test_nonexistent_path(self):
        with self.assertRaises(InvalidPathError):
            scan_path("nonexistent_path.py")

    def test_detects_crypto_usage(self):
        test_code = "from Crypto.PublicKey import RSA\nkey = RSA.generate(2048)\n"
        test_file = os.path.join(self.test_dir, "temp_test_crypto_usage.py")
        with open(test_file, "w") as f:
            f.write(test_code)

        try:
            matches = scan_path(test_file)
            self.assertTrue(any("usage: RSA.generate" in m[2] for m in matches))
        finally:
            os.remove(test_file)

if __name__ == '__main__':
    unittest.main()