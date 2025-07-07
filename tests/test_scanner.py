import os
import unittest
import tempfile
import shutil
import sys
from unittest.mock import patch, mock_open
from src.shorstop.scanner import (
    InvalidPathError, 
    scan_path, 
    scan_file_or_directory,
    _scan_file,
    _is_crypto_import,
    CRYPTO_IMPORTS
)

class TestScanner(unittest.TestCase):
    def setUp(self):
        # Create a temporary directory for test files
        self.temp_dir = tempfile.mkdtemp()
        
    def tearDown(self):
        # Clean up temporary directory
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)

    def _create_test_file(self, filename, content):
        """Helper method to create test files"""
        filepath = os.path.join(self.temp_dir, filename)
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(content)
        return filepath

    # Tests for _is_crypto_import function
    def test_is_crypto_import_positive_cases(self):
        """Test that crypto import detection works for all supported modules"""
        for crypto_module in CRYPTO_IMPORTS:
            self.assertTrue(_is_crypto_import(crypto_module))
            # Test with submodules
            self.assertTrue(_is_crypto_import(f"{crypto_module}.submodule"))

    def test_is_crypto_import_edge_cases(self):
        """Test edge cases for crypto import detection"""
        self.assertFalse(_is_crypto_import(""))  # Empty string
        self.assertFalse(_is_crypto_import("rs"))  # Partial match
        self.assertFalse(_is_crypto_import("RSA"))  # Case sensitivity
        self.assertTrue(_is_crypto_import("rsa.key"))  # Submodule

    # Tests for scan_path function
    def test_scan_path_nonexistent_file(self):
        """Test that InvalidPathError is raised for non-existent paths"""
        with self.assertRaises(InvalidPathError) as context:
            scan_path("nonexistent_file.py")
        self.assertIn("Invalid path", str(context.exception))

    def test_scan_path_empty_file(self):
        """Test scanning an empty Python file"""
        empty_file = self._create_test_file("empty.py", "")
        matches = scan_path(empty_file)
        self.assertEqual(matches, [])

    def test_scan_path_non_python_file(self):
        """Test that non-Python files are skipped"""
        txt_file = self._create_test_file("test.txt", "some content")
        matches = scan_path(txt_file)
        self.assertEqual(matches, [])

    def test_scan_path_directory_with_mixed_files(self):
        """Test scanning a directory with Python and non-Python files"""
        # Create Python file with crypto import
        self._create_test_file("crypto_file.py", "import rsa\n")
        # Create non-Python file
        self._create_test_file("readme.txt", "This is a readme")
        # Create Python file without crypto
        self._create_test_file("normal_file.py", "import os\n")
        
        matches = scan_path(self.temp_dir)
        # Should only find matches in crypto_file.py
        crypto_matches = [m for m in matches if "crypto_file.py" in m[0]]
        self.assertEqual(len(crypto_matches), 1)
        self.assertIn("import: rsa", crypto_matches[0][2])

    def test_scan_path_nested_directories(self):
        """Test scanning nested directories"""
        # Create nested structure
        nested_file = self._create_test_file("subdir/nested/crypto.py", 
                                           "from Crypto.PublicKey import RSA\n")
        
        matches = scan_path(self.temp_dir)
        self.assertTrue(any("crypto.py" in m[0] for m in matches))
        self.assertTrue(any("import: from Crypto.PublicKey import RSA" in m[2] for m in matches))

    # Tests for different import patterns
    def test_direct_imports(self):
        """Test detection of direct crypto imports"""
        test_cases = [
            ("import rsa", "import: rsa"),
            ("import rsa, os", "import: rsa"),
            ("import rsa as crypto_lib", "import: rsa"),
        ]
        
        for code, expected in test_cases:
            with self.subTest(code=code):
                test_file = self._create_test_file("test_direct.py", code)
                matches = scan_path(test_file)
                self.assertTrue(any(expected in m[2] for m in matches))

    def test_from_imports(self):
        """Test detection of 'from' crypto imports"""
        test_cases = [
            ("from Crypto.PublicKey import RSA", "import: from Crypto.PublicKey import RSA"),
            ("from Crypto.PublicKey import RSA, DSA", "import: from Crypto.PublicKey import RSA, DSA"),
            ("from Crypto.PublicKey.RSA import generate", "import: from Crypto.PublicKey.RSA import generate"),
            ("from Crypto.PublicKey.ECC import generate", "import: from Crypto.PublicKey.ECC import generate"),
        ]
        
        for code, expected in test_cases:
            with self.subTest(code=code):
                test_file = self._create_test_file("test_from.py", code)
                matches = scan_path(test_file)
                self.assertTrue(any(expected in m[2] for m in matches))

    def test_crypto_usage_detection(self):
        """Test detection of crypto function calls"""
        test_cases = [
            ("RSA.generate(2048)", "usage: RSA.generate"),
            ("DSA.generate(1024)", "usage: DSA.generate"),
            ("ECC.generate(curve='P-256')", "usage: ECC.generate"),
            ("key = RSA.importKey(data)", "usage: RSA.importKey"),
        ]
        
        for code, expected in test_cases:
            with self.subTest(code=code):
                full_code = f"from Crypto.PublicKey import RSA, DSA, ECC\n{code}\n"
                test_file = self._create_test_file("test_usage.py", full_code)
                matches = scan_path(test_file)
                self.assertTrue(any(expected in m[2] for m in matches))

    def test_line_numbers_accuracy(self):
        """Test that line numbers are reported accurately"""
        code = """# Line 1: Comment
import os  # Line 2: Non-crypto import
import rsa  # Line 3: Crypto import
from Crypto.PublicKey import RSA  # Line 4: Crypto from import

def main():  # Line 6
    key = RSA.generate(2048)  # Line 7: Crypto usage
"""
        test_file = self._create_test_file("test_lines.py", code)
        matches = scan_path(test_file)
        
        # Check line numbers
        import_rsa_match = next(m for m in matches if "import: rsa" in m[2])
        self.assertEqual(import_rsa_match[1], 3)
        
        from_import_match = next(m for m in matches if "import: from Crypto.PublicKey import RSA" in m[2])
        self.assertEqual(from_import_match[1], 4)
        
        usage_match = next(m for m in matches if "usage: RSA.generate" in m[2])
        self.assertEqual(usage_match[1], 7)

    # Tests for error handling
    def test_syntax_error_handling(self):
        """Test handling of files with syntax errors"""
        invalid_code = "def invalid_function(\n    # Missing closing parenthesis"
        test_file = self._create_test_file("syntax_error.py", invalid_code)
        
        matches = scan_path(test_file)
        self.assertTrue(any("⚠️ Skipped (SyntaxError)" in m[2] for m in matches))

    def test_encoding_error_handling(self):
        """Test handling of files with encoding issues"""
        # Create a file with unusual content that might cause encoding issues
        test_file = os.path.join(self.temp_dir, "encoding_test.py")
        with open(test_file, "wb") as f:
            f.write(b"import rsa\n# \xff\xfe invalid utf-8")
        
        # Should not crash, might skip or handle gracefully
        matches = scan_path(test_file)
        # The important thing is that it doesn't crash



    # Tests for scan_file_or_directory function
    def test_scan_file_or_directory_valid_path(self):
        """Test scan_file_or_directory with valid path"""
        test_file = self._create_test_file("valid.py", "import rsa\n")
        matches = scan_file_or_directory(test_file)
        self.assertTrue(any("import: rsa" in m[2] for m in matches))

    # Tests for edge cases and complex scenarios
    def test_multiple_imports_same_line(self):
        """Test multiple imports on the same line"""
        code = "import rsa, os, sys"
        test_file = self._create_test_file("multi_import.py", code)
        matches = scan_path(test_file)
        # Should detect rsa but not os or sys
        rsa_matches = [m for m in matches if "rsa" in m[2]]
        self.assertEqual(len(rsa_matches), 1)

    def test_aliased_imports(self):
        """Test imports with aliases"""
        code = "import rsa as crypto_lib\ncrypto_lib.generate(2048)"
        test_file = self._create_test_file("aliased.py", code)
        matches = scan_path(test_file)
        # Should detect the import but might not detect usage (depending on implementation)
        self.assertTrue(any("import: rsa" in m[2] for m in matches))

    def test_complex_nested_calls(self):
        """Test complex nested crypto calls"""
        code = """
from Crypto.PublicKey import RSA, DSA
key1 = RSA.generate(2048)
key2 = DSA.generate(1024)
nested = RSA.importKey(RSA.generate(1024).exportKey())
"""
        test_file = self._create_test_file("complex.py", code)
        matches = scan_path(test_file)
        
        # Should detect all crypto usages
        usage_matches = [m for m in matches if "usage:" in m[2]]
        self.assertGreaterEqual(len(usage_matches), 3)  # At least 3 usages

    def test_comments_and_strings_ignored(self):
        """Test that crypto keywords in comments and strings are ignored"""
        code = '''
# This comment mentions RSA.generate but should be ignored
print("This string mentions Crypto.PublicKey but should be ignored")
"""
Docstring mentioning rsa should also be ignored
"""
import rsa  # This should be detected
'''
        test_file = self._create_test_file("comments.py", code)
        matches = scan_path(test_file)
        
        # Should only detect the actual import, not the comments/strings
        import_matches = [m for m in matches if "import:" in m[2]]
        self.assertEqual(len(import_matches), 1)
        self.assertIn("import: rsa", import_matches[0][2])

    def test_class_and_function_definitions(self):
        """Test that crypto keywords in class/function names are handled correctly"""
        code = """
import rsa

class RSAHandler:
    def generate_rsa_key(self):
        return rsa.generate(2048)  # This should be detected as usage

def rsa_utility():
    pass
"""
        test_file = self._create_test_file("definitions.py", code)
        matches = scan_path(test_file)
        
        # Should detect import and might detect usage depending on visitor implementation
        self.assertTrue(any("import: rsa" in m[2] for m in matches))

    def test_large_file_performance(self):
        """Test performance with a large file"""
        # Create a large file with many imports and usages
        lines = ["import rsa"] + ["# Comment line"] * 1000 + ["key = RSA.generate(2048)"]
        code = "\n".join(lines)
        test_file = self._create_test_file("large.py", code)
        
        # Should complete without timing out
        matches = scan_path(test_file)
        self.assertTrue(any("import: rsa" in m[2] for m in matches))

    def test_unicode_file_content(self):
        """Test files with unicode content"""
        code = """# -*- coding: utf-8 -*-
# File with unicode: café, naïve, résumé
import rsa
# More unicode: 你好, мир, שלום
key = rsa.generate(2048)
"""
        test_file = self._create_test_file("unicode.py", code)
        matches = scan_path(test_file)
        self.assertTrue(any("import: rsa" in m[2] for m in matches))

    # Integration tests
    def test_sample_crypto_code_detection(self):
        """Test detection in a comprehensive sample with various crypto patterns"""
        sample_code = '''
from Crypto.PublicKey import RSA, DSA
from Crypto.PublicKey.ECC import generate as ecc_gen
import rsa

def main():
    # Generate RSA key
    rsa_key = RSA.generate(2048)
    
    # Generate DSA key
    dsa_key = DSA.generate(1024)
    
    # Generate ECC key
    ecc_key = ecc_gen(curve='P-256')
    
    # Import existing key
    imported = RSA.importKey(rsa_key.exportKey())
    
    return rsa_key, dsa_key, ecc_key, imported
'''
        test_file = self._create_test_file("comprehensive_sample.py", sample_code)
        matches = scan_path(test_file)
        
        # Should detect imports
        self.assertTrue(any("import: from Crypto.PublicKey import RSA, DSA" in m[2] for m in matches))
        self.assertTrue(any("import: from Crypto.PublicKey.ECC import generate" in m[2] for m in matches))
        self.assertTrue(any("import: rsa" in m[2] for m in matches))
        
        # Should detect usages
        self.assertTrue(any("usage: RSA.generate" in m[2] for m in matches))
        self.assertTrue(any("usage: DSA.generate" in m[2] for m in matches))
        self.assertTrue(any("usage: RSA.importKey" in m[2] for m in matches))

    def test_constants_validation(self):
        """Test that CRYPTO_IMPORTS constant contains expected values"""
        expected_imports = {"rsa", "Crypto.PublicKey", "Crypto.PublicKey.RSA", "Crypto.PublicKey.ECC"}
        self.assertEqual(CRYPTO_IMPORTS, expected_imports)

    def test_return_type_consistency(self):
        """Test that all functions return consistent tuple format"""
        test_file = self._create_test_file("return_test.py", "import rsa\nkey = RSA.generate(2048)")
        matches = scan_path(test_file)
        
        for match in matches:
            self.assertIsInstance(match, tuple)
            self.assertEqual(len(match), 3)
            self.assertIsInstance(match[0], str)  # file_path
            self.assertIsInstance(match[1], int)  # line_number
            self.assertIsInstance(match[2], str)  # description

if __name__ == '__main__':
    # Custom test runner to show docstrings instead of method names
    import unittest
    
    class DocstringTestResult(unittest.TextTestResult):
        def getDescription(self, test):
            doc = test._testMethodDoc
            if doc:
                return doc.strip()
            return str(test)
    
    class DocstringTestRunner(unittest.TextTestRunner):
        def _makeResult(self):
            return DocstringTestResult(self.stream, self.descriptions, self.verbosity)
    
    # Run tests with custom runner
    unittest.main(testRunner=DocstringTestRunner(verbosity=2))