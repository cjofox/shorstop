# cli.py
import argparse
from scanner import scan_path

def main():
    parser = argparse.ArgumentParser(
        description="🔍 Shorstop - Scan for quantum-vulnerable crypto in codebases."
    )
    parser.add_argument(
        "path", type=str, help="Path to the project directory to scan."
    )
    args = parser.parse_args()

    matches = scan_path(args.path)
    _report(matches)    

def _report(matches):
    if matches:
        print("\n🚨 Potential quantum-vulnerable crypto usage found:")
        for file_path, line_number, line in matches:
            print(f"{file_path}:{line_number}: {line}")
    else:
        print("\n✅ No crypto-related imports detected.")

if __name__ == "__main__":
    main()
