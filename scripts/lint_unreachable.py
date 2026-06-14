#!/usr/bin/env python
"""
Fail the build on unreachable code — any statement that follows a
return / raise / break / continue in the same block.

pyflakes does not catch this, and a mechanical edit (e.g. a regex sweep
that inserts a `return` above an existing trailing call) silently created
exactly this bug once — a GDPR audit-log call left dangling after a
`return`.  This makes that class of drift a hard CI failure instead of a
thing an ad-hoc scan happens to find later.

Zero false positives by construction: it only flags a statement that is
provably after a terminating statement in the same suite. It does not
flag unused parameters, unused imports, or anything pyflakes/vulture
already (or wrongly) handle.

Usage:  python scripts/lint_unreachable.py pipeline
Exit 0 when clean, 1 when any unreachable statement is found.
"""

import ast
import sys
from pathlib import Path

_TERMINATORS = (ast.Return, ast.Raise, ast.Break, ast.Continue)


def _check_suite(body: list[ast.stmt], path: Path, findings: list[str]) -> None:
    """Flag the first statement after a terminator in a single suite."""
    for i, stmt in enumerate(body[:-1]):
        if isinstance(stmt, _TERMINATORS):
            nxt = body[i + 1]
            findings.append(
                f"{path}:{nxt.lineno}: unreachable code after "
                f"{type(stmt).__name__.lower()} (line {stmt.lineno})"
            )
            break  # one report per suite is enough


def _walk(node: ast.AST, path: Path, findings: list[str]) -> None:
    # Every node that owns a statement suite gets checked, recursively.
    for field in ("body", "orelse", "finalbody"):
        suite = getattr(node, field, None)
        if isinstance(suite, list) and suite and isinstance(suite[0], ast.stmt):
            _check_suite(suite, path, findings)
    for child in ast.iter_child_nodes(node):
        _walk(child, path, findings)


def main(roots: list[str]) -> int:
    findings: list[str] = []
    for root in roots:
        for py in Path(root).rglob("*.py"):
            try:
                tree = ast.parse(py.read_text(encoding="utf-8"))
            except SyntaxError as exc:
                findings.append(f"{py}: syntax error: {exc}")
                continue
            _walk(tree, py, findings)

    if findings:
        print("Unreachable code detected:")
        for f in sorted(findings):
            print(f"  {f}")
        return 1
    print(f"No unreachable code in: {', '.join(roots)}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:] or ["pipeline"]))
