import ast
from typing import List, Tuple

class CryptoUsageVisitor(ast.NodeVisitor):
    def __init__(self):
        self.matches: List[Tuple[int, str]] = []

    def visit_Call(self, node: ast.Call):
        if isinstance(node.func, ast.Attribute):
            value = node.func.value
            if isinstance(value, ast.Name) and value.id in {"RSA", "DSA", "ECC"}:
                # Extract additional details for better reporting
                details = f"{value.id}.{node.func.attr}"
                if value.id == "RSA" and node.func.attr == "generate" and node.args:
                    # Try to extract key size for RSA
                    arg = node.args[0]
                    if isinstance(arg, ast.Constant):
                        details += f"({arg.value})"
                    elif isinstance(arg, ast.Num):  # Python < 3.8 compatibility
                        details += f"({arg.n})"
                self.matches.append((node.lineno, details))
        self.generic_visit(node)
