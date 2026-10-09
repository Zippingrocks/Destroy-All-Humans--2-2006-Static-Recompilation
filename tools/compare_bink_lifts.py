"""Compare DAH1/DAH2 generated Bink functions after address normalization."""
from __future__ import annotations

import argparse
import difflib
import re
from pathlib import Path


def function(path: Path, name: str) -> list[str]:
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    start = next(i for i, line in enumerate(lines) if line == f"void {name}(void)")
    depth = 0
    body: list[str] = []
    for line in lines[start:]:
        depth += line.count("{") - line.count("}")
        body.append(line)
        if depth == 0 and len(body) > 1:
            break
    return body


def normalize(lines: list[str]) -> list[str]:
    result: list[str] = []
    skip = 0
    for line in lines:
        if skip:
            skip += line.count("{") - line.count("}")
            if skip == 0:
                continue
            continue
        if any(marker in line for marker in (
            "dah2_bink_", "DAH2_TEST_WINDOW_HIDDEN", "DAH2_PARITY_TRACE",
            "[BINK-", "[PARITY-BINK-DECODER]",
        )):
            if "{" in line:
                skip = line.count("{") - line.count("}")
            continue
        line = re.sub(r"sub_[0-9A-Fa-f]{8}", "sub_ADDR", line)
        line = re.sub(r"loc_[0-9A-Fa-f]{8}", "loc_ADDR", line)
        line = re.sub(r"0x[0-9A-Fa-f]+u?", "HEX", line)
        line = re.sub(r"/\*.*?\*/", "", line)
        line = " ".join(line.split())
        if line:
            result.append(line)
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("dah1", type=Path)
    parser.add_argument("dah2", type=Path)
    parser.add_argument("--dah1-function", required=True)
    parser.add_argument("--dah2-function", required=True)
    args = parser.parse_args()
    first = normalize(function(args.dah1, args.dah1_function))
    second = normalize(function(args.dah2, args.dah2_function))
    print(f"normalized lines: DAH1={len(first)} DAH2={len(second)}")
    for line in difflib.unified_diff(first, second, fromfile="DAH1", tofile="DAH2", n=3):
        print(line)


if __name__ == "__main__":
    main()