import argparse

from .scanner import scan_file_or_directory
from .report import report

def main():
    parser = argparse.ArgumentParser(
        description="🔍 Shorstop - Scan for quantum-vulnerable crypto in Python codebases."
    )
    parser.add_argument(
        "path", type=str, help="Path to the file or directory to scan."
    )
    parser.add_argument(
        "-o", "--output", type=str, default="", help="Output file path to write results to."
    )
    args = parser.parse_args()

    matches = scan_file_or_directory(args.path)

    report(matches, args.output)

if __name__ == "__main__":
    main()
