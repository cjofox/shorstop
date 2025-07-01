import ast
from typing import List, Tuple

class CryptoUsageVisitor(ast.NodeVisitor):
    def __init__(self):
        self.matches: List[Tuple[int, str]] = []

    def visit_Call(self, node: ast.Call):
        if isinstance(node.func, ast.Attribute):
            value = node.func.value
            if isinstance(value, ast.Name) and value.id in {"RSA", "DSA", "ECC"}:
                self.matches.append((node.lineno, f"{value.id}.{node.func.attr}"))
        self.generic_visit(node)
