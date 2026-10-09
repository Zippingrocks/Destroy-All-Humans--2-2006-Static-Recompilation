"""Bounded fail-closed metadata/translation regression; never regenerate the project.

Only the manifested retail functions are translated in memory. No game,
renderer, emulator, or UI is launched. The default pipeline stays opt-in.
"""
import copy
import hashlib
import json
from pathlib import Path
import re
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "xboxrecomp"))
from tools.recomp import config
from tools.recomp.function_extents import apply_function_extents
from tools.recomp.translator import BatchTranslator, FunctionTranslator

XBE = ROOT / "game_files/default.xbe"
MANIFEST_PATH = ROOT / "seeds/verified_function_extents.json"
MANIFEST = json.loads(MANIFEST_PATH.read_text())
IMAGE = XBE.read_bytes()
config.configure_from_xbe(str(XBE))
DATABASE = {}
for entry in json.loads((ROOT / "xboxrecomp/tools/disasm/output/functions.json").read_text()):
    address = int(entry["start"], 16)
    DATABASE[address] = dict(entry, end=int(entry["end"], 16))
STARTS = (0x12FFB0, 0x179240, 0x1AB6A0, 0x1AE2F0, 0x11A340, 0x110790)
FIELDS = {"end", "size", "num_instructions"}


class VerifiedExtentsTests(unittest.TestCase):
    def apply(self, manifest, database=None, image=IMAGE):
        database = database if database is not None else copy.deepcopy(DATABASE)
        with tempfile.TemporaryDirectory(prefix="dah2-extent-manifest-") as temporary:
            path = Path(temporary) / "manifest.json"
            path.write_text(json.dumps(manifest))
            return apply_function_extents(image, database, path)

    def rejected(self, manifest, image=IMAGE, message=None):
        database = copy.deepcopy(DATABASE)
        before = copy.deepcopy(database)
        with self.assertRaisesRegex(ValueError, message or "function extents"):
            self.apply(manifest, database, image)
        self.assertEqual(database, before, "A failed manifest changed metadata")

    def test_omitted_manifest_is_exact_noop(self):
        database = copy.deepcopy(DATABASE)
        before = copy.deepcopy(database)
        self.assertEqual(apply_function_extents(IMAGE, database, None), ())
        self.assertEqual(database, before)

    def test_only_three_fields_change_and_interior_symbol_survives(self):
        database = copy.deepcopy(DATABASE)
        self.assertEqual(self.apply(MANIFEST, database), STARTS)
        self.assertEqual(database.keys(), DATABASE.keys())
        for address, before in DATABASE.items():
            if address not in STARTS:
                self.assertEqual(database[address], before)
            else:
                self.assertEqual({k: v for k, v in database[address].items() if k not in FIELDS},
                                 {k: v for k, v in before.items() if k not in FIELDS})
        self.assertEqual(database[0x130001], DATABASE[0x130001])
        self.assertEqual((database[STARTS[0]]["end"], database[STARTS[0]]["size"],
                          database[STARTS[0]]["num_instructions"]), (0x1301DA, 554, 164))
        self.assertEqual((database[STARTS[1]]["end"], database[STARTS[1]]["size"],
                          database[STARTS[1]]["num_instructions"]), (0x1799C2, 1922, 496))
        self.assertEqual((database[STARTS[2]]["end"], database[STARTS[2]]["size"],
                          database[STARTS[2]]["num_instructions"]), (0x1AB75A, 186, 54))

    def test_binary_and_range_hashes_fail_closed(self):
        bad = copy.deepcopy(MANIFEST); bad["xbe_sha256"] = "0" * 64
        self.rejected(bad, message="XBE SHA256 mismatch")
        bad = copy.deepcopy(MANIFEST); bad["functions"][1]["sha256"] = "0" * 64
        self.rejected(bad, message="range SHA256 mismatch")
        image = bytearray(IMAGE); image[-1] ^= 1
        self.rejected(MANIFEST, bytes(image), message="XBE SHA256 mismatch")

    def test_schema_addresses_counts_duplicates_and_missing_starts(self):
        mutations = [
            lambda d: d.update(schema="unknown"),
            lambda d: d.update(functions=[]),
            lambda d: d["functions"].append(copy.deepcopy(d["functions"][0])),
            lambda d: d["functions"][1].update(start="0xFFFFFFFF"),
            lambda d: d["functions"][1].update(start=True),
            lambda d: d["functions"][1].update(end=d["functions"][1]["start"]),
            lambda d: d["functions"][1].update(end="0xFFFFFFFF"),
            lambda d: d["functions"][1].update(num_instructions=495),
            lambda d: d["functions"][1].update(num_instructions=True),
            lambda d: d["functions"][1].update(sha256="not-a-digest"),
        ]
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                bad = copy.deepcopy(MANIFEST); mutation(bad); self.rejected(bad)

    def test_mid_instruction_and_padding_are_not_valid_ends(self):
        for end in (0x1799C1, 0x1799C3):
            with self.subTest(end=end):
                bad = copy.deepcopy(MANIFEST); entry = bad["functions"][1]
                start = int(entry["start"], 16)
                section = next(s for s in config._SECTIONS if s.va <= start < s.va+s.raw_size)
                offset = section.raw_addr + start-section.va
                entry.update(end=f"0x{end:08X}", sha256=hashlib.sha256(
                    IMAGE[offset:offset+end-start]).hexdigest())
                if end == 0x1799C3:
                    entry["num_instructions"] = 497
                self.rejected(bad, message="boundary mismatch")

    def test_bodies_exactly_match_verified_runtime_repairs(self):
        database = copy.deepcopy(DATABASE)
        self.apply(MANIFEST, database)
        translator = FunctionTranslator(IMAGE, database)
        for start, source in ((0x12FFB0, "recomp_0008.c"), (0x179240, "recomp_0010.c"),
                              (0x1AB6A0, "recomp_0011.c"), (0x1AE2F0, "recomp_0011.c"),
                              (0x11A340, "recomp_0007.c"), (0x110790, "recomp_0007.c")):
            with self.subTest(start=f"0x{start:08X}"):
                name = f"sub_{start:08X}"
                code = translator.translate_function(start, database[start])
                body = code[code.index(f"void {name}(void)"):].strip()
                pattern = re.compile(rf"^void {name}\(void\)\n\{{.*?^\}}", re.M | re.S)
                preferred = ROOT / "src/recomp/gen" / source
                candidates = [preferred] + [p for p in sorted(preferred.parent.glob("recomp_*.c")) if p != preferred]
                actual = next((match.group() for path in candidates if path.is_file()
                               if (match := pattern.search(path.read_text()))), None)
                self.assertIsNotNone(actual, f"Missing generated definition: {name}")
                self.assertEqual(body, actual)
                labels = set(re.findall(r"^(loc_[0-9A-F]{8}):", body, re.M))
                self.assertTrue(set(re.findall(r"goto (loc_[0-9A-F]{8})", body)) <= labels)
                expected_return = {0x12FFB0: "ret", 0x179240: "ret 8", 0x1AB6A0: "ret 4", 0x1AE2F0: "ret 8", 0x11A340: "ret", 0x110790: "ret 8"}[start]
                self.assertIn(f"return; /* {expected_return} */", body)
                if start == 0x12FFB0:
                    self.assertNotIn("sub_00130001();", body)
                elif start == 0x179240:
                    self.assertIn("loc_001799B6:", body)
                    self.assertIn("esp = esp + 0x84;", body)
                elif start == 0x1AB6A0:
                    self.assertIn("loc_001AB755:", body)
                    self.assertEqual(body.count("sub_001AA8F0();"), 2)
                    self.assertIn("POP32(esp, edi);", body)
                    self.assertIn("POP32(esp, esi);", body)
                elif start == 0x1AE2F0:
                    self.assertIn("loc_001AE482:", body)
                    self.assertIn("esp = esp + 0x1C;", body)
                    self.assertIn("sub_002654F0();", body)
                elif start == 0x11A340:
                    self.assertIn("loc_0011A3AB:", body)
                    self.assertNotIn("sub_0011A355();", body)
                    self.assertNotIn("sub_0011A382();", body)
                    self.assertEqual(body.count("POP32(esp,"), 4)
                else:
                    self.assertIn("loc_001108E9:", body)
                    self.assertNotIn("sub_001108E9();", body)
                    self.assertNotIn("sub_00110887();", body)
                    self.assertEqual(body.count("POP32(esp,"), 4)

    def test_batch_hook_is_opt_in_and_precedes_discovery(self):
        with tempfile.TemporaryDirectory(prefix="dah2-extent-batch-") as temporary:
            functions = Path(temporary) / "functions.json"
            entries = [copy.deepcopy(DATABASE[a]) for a in (*STARTS, 0x130001)]
            for entry in entries:
                entry["end"] = f"0x{entry['end']:08X}"
            functions.write_text(json.dumps(entries))
            with patch.object(FunctionTranslator, "discover_static_indirect_targets"), \
                 patch.object(FunctionTranslator, "discover_cfg_ownership"):
                normal = BatchTranslator(str(XBE), str(functions), seh_prolog=0, seh_epilog=0)
                self.assertEqual(normal.applied_function_extents, ())
                self.assertEqual(normal.func_db[STARTS[0]]["end"], DATABASE[STARTS[0]]["end"])
                repaired = BatchTranslator(str(XBE), str(functions), seh_prolog=0, seh_epilog=0,
                                           function_extents_path=MANIFEST_PATH)
                self.assertEqual(repaired.applied_function_extents, STARTS)
                self.assertEqual(repaired.translator.func_db[STARTS[0]]["end"], 0x1301DA)
                self.assertEqual(repaired.translator.lifter.func_db[STARTS[1]]["end"], 0x1799C2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
