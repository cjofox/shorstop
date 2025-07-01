import argparse
import sys
from typing import List, Tuple
from src.shorstop.formatter import format_matches
from .scanner import scan_path, InvalidPathError

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

    _report(matches, args.output)

def scan_file_or_directory(path: str):
    try:
        matches = scan_path(path)
    except InvalidPathError as e:
        print(f"❌ {e}")
        sys.exit(1)
    return matches

def _report(matches: List[Tuple[str, int, str]], output_file: str = ""):
    if not matches:
        print("✅ No crypto-related imports detected.")
        return
    
    output = format_matches(matches)
    if  output_file and output_file != "":
        with open(output_file, "w", encoding="utf-8") as file_stream:
            file_stream.write(output)
        print(f"✅ Results written to {output_file}")
    else:
        print()
        print(format_matches(matches))
    
if __name__ == "__main__":
    main()
