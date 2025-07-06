# shorstop
CLI tool to scan code and keys for cryptographic algorithms vulnerable to quantum computing

Shorstop identifies cryptographic implementations that could be vulnerable to attacks from quantum computers and provides recommendations for quantum-resistant alternatives.

## Features

- **Quantum Vulnerability Detection**: Identifies crypto algorithms vulnerable to quantum attacks
- **Severity Classification**: Risk levels from Low 🔸 to Critical 🚨
- **Smart Parameter Analysis**: Analyzes key sizes, curves, and algorithm parameters
- **Actionable Recommendations**: Suggests specific quantum-resistant alternatives
- **Comprehensive Coverage**: Supports RSA, ECC, DSA, AES, hash functions, and more

## Supported Vulnerabilities

- **RSA keys** with insufficient bit length (<3072 bits)
- **ECC curves** (all traditional curves are quantum-vulnerable)
- **DSA signatures** (always quantum-vulnerable)
- **Weak symmetric encryption** (AES <256 bits, legacy algorithms)
- **Broken hash functions** (MD5, SHA1)

## Installation

```bash
git clone https://github.com/cjofox/shorstop.git
cd shorstop
```

## Usage

Scan a single file:
```bash
python -m src.shorstop.cli path/to/file.py
```

Scan a directory:
```bash
python -m src.shorstop.cli path/to/directory/
```

Save results to file:
```bash
python -m src.shorstop.cli path/to/scan/ -o results.txt
```

## Example Output

```
🚨 Potential quantum-vulnerable crypto usage found:

📄 samples/weak_rsa_example.py (3 matches)
  • Line 3: import: from Crypto.PublicKey import RSA
  • Line 6: quantum-vulnerable: 🔺 RSA 2048-bit key is vulnerable to quantum attacks | Suggestion: Use RSA keys ≥3072 bits or migrate to post-quantum algorithms (Kyber, Dilithium)
  • Line 6: usage: RSA.generate(2048)

📊 Summary: 1 file, 3 matches
```

## Quantum Security Best Practices

See [QUANTUM_SECURITY.md](QUANTUM_SECURITY.md) for detailed guidance on:
- Understanding quantum threats to cryptography
- Migration strategies to quantum-resistant algorithms
- Implementation examples and timelines
- NIST post-quantum cryptography standards

## Language Support

Currently supports Python source code analysis. Other languages will be supported in future releases.

## Contributing

Contributions are welcome! Please feel free to submit issues and pull requests.
