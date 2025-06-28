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

    scan_path(args.path)

if __name__ == "__main__":
    main()
