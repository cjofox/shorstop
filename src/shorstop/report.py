from .formatter import format_matches
from typing import List, Tuple

def report(matches: List[Tuple[str, int, str]], output_file: str = ""):
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