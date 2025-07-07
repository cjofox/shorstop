# Additional quantum vulnerability test cases

from Crypto.PublicKey import RSA, DSA, ECC
from Crypto.Cipher import AES
import hashlib

def test_various_vulnerabilities():
    # Critical RSA vulnerability - 1024 bit
    weak_rsa = RSA.generate(1024)
    
    # Medium RSA vulnerability - 3072 bit (borderline)
    medium_rsa = RSA.generate(3072)
    
    # ECC vulnerability - all ECC is quantum vulnerable
    ecc_key = ECC.generate(curve='P-256')
    
    # DSA vulnerability - always quantum vulnerable
    dsa_key = DSA.generate(2048)
    
    # AES with insufficient key size
    weak_aes = AES.new(b'1234567890123456', AES.MODE_ECB)  # 128-bit
    
    # Weak hash functions
    md5_hash = hashlib.md5(b'data').hexdigest()
    sha1_hash = hashlib.sha1(b'data').hexdigest()
    
    return weak_rsa, medium_rsa, ecc_key, dsa_key