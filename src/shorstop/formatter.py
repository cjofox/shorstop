from collections import defaultdict
from typing import List, Tuple

def format_matches(matches: List[Tuple[str, int, str]]) -> str:
    grouped = defaultdict(list)
    for file_path, line_number, code in matches:
        grouped[file_path].append((line_number, code))

    lines = []
    lines.append("🚨 Potential quantum-vulnerable crypto usage found:")
    for file_path, entries in grouped.items():
        lines.append(f"\n📄 {file_path} ({len(entries)} match{'es' if len(entries) != 1 else ''})")
        for line_number, code in sorted(entries):
            lines.append(f"  • Line {line_number}: {code}")

    total_files = len(grouped)
    total_matches = sum(len(entries) for entries in grouped.values())
    lines.append(f"\n📊 Summary: {total_files} file{'s' if total_files != 1 else ''}, {total_matches} match{'es' if total_matches != 1 else ''}")
    return "\n".join(lines)
