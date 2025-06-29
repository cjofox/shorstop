import argparse
import sys
from src.shorstop.scanner import scan_path, InvalidPathError

def main():
    parser = argparse.ArgumentParser(
        description="🔍 Shorstop - Scan for quantum-vulnerable crypto in Python codebases."
    )
    parser.add_argument(
        "path", type=str, help="Path to the file or directory to scan."
    )
    args = parser.parse_args()

    try:
        matches = scan_path(args.path)
    except InvalidPathError as e:
        print(f"❌ {e}")
        sys.exit(1)

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
