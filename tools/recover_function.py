"""Print an apply_patch patch for one verified original function extent.

Usage: python tools/recover_function.py START END
END is exclusive and must be checked against the retail XBE disassembly.
Optional third argument: generated source path to receive a missing function.
New functions also require explicit dispatch registration by the caller.
Does not edit the generated sources or overwrite unrelated manual changes.
"""
import json
import re
import sys
from pathlib import Path

root = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(root / "xboxrecomp"))
from tools.recomp import config
from tools.recomp.translator import FunctionTranslator

start, end = (int(value, 16) for value in sys.argv[1:3])
xbe = root / "game_files/default.xbe"
config.configure_from_xbe(str(xbe))
entries = json.loads((root / "xboxrecomp/tools/disasm/output/functions.json").read_text())
database = {}
for entry in entries:
    address = int(entry["start"], 16)
    entry["end"] = int(entry["end"], 16)
    database[address] = entry
new_target = Path(sys.argv[3]) if len(sys.argv) > 3 else None
if (start not in database and not new_target) or not start < end:
    raise ValueError("Unknown entry or invalid extent")
info = dict(database.get(start, {}), end=end, size=end-start)
database[start] = info
translator = FunctionTranslator(xbe.read_bytes(), database)
code = translator.translate_function(start, info)
name = f"sub_{start:08X}"
new_body = code[code.index(f"void {name}(void)"):].strip()
matches = []
for path in (root / "src/recomp/gen").glob("recomp_*.c"):
    source = path.read_text()
    match = re.search(rf"^void {name}\(void\)\n\{{.*?^\}}", source, re.M | re.S)
    if match:
        matches.append((path, match.group(0)))
if new_target:
    if matches:
        raise ValueError("Function already exists; recover it without a third argument")
    path = (root / new_target).resolve()
    if path.parent != (root / 'src/recomp/gen').resolve() or not path.is_file():
        raise ValueError("New target must be an existing generated source in this workspace")
    print("*** Begin Patch")
    print(f"*** Update File: {path}")
    print("@@")
    print(' #include "recomp_funcs.h"')
    print("+\n" + "\n".join("+" + line for line in new_body.splitlines()))
    print("*** End Patch")
    sys.exit(0)
if len(matches) != 1:
    raise ValueError(f"Expected one definition, got {len(matches)}")
path, old_body = matches[0]
print("*** Begin Patch")
print(f"*** Update File: {path}")
print("@@")
print("\n".join("-" + line for line in old_body.splitlines()))
print("\n".join("+" + line for line in new_body.splitlines()))
print("*** End Patch")
