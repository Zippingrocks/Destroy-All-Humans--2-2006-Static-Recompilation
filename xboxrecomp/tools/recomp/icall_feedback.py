#!/usr/bin/env python3
"""
Indirect-branch target feedback: merge runtime observations into a persisted
database, and feed them back as function-detection seeds.

Static analysis cannot see where a vtable call goes. Running the title can.
This closes that loop, the same way Microsoft's own recompiler does with
VirtualDispatchTraceFiles (recorded indirect-branch target sets) and
UpdateEnlightenments (a persisted analysis database the compiler rewrites on
every build). See docs/technical/ms-fusion-codegen-teardown.md.

Workflow:

  1. Build the title with RECOMP_ICALL_FEEDBACK defined, run it, and call
     recomp_icall_feedback_dump("icall.txt") from atexit and your crash handler.
  2. python -m tools.recomp.icall_feedback merge icall.txt
  3. python -m tools.disasm --seed-functions tools/recomp/output/icall_targets.json
  4. Re-run the recompiler. Targets that were unresolved stubs are now real
     functions. Repeat -- each pass reaches further into the title, so it
     converges rather than being one-shot.

The database is *cumulative*. A target observed in an earlier run is never
dropped because a later run did not reach it; that is the whole point of
persisting it, and it is why step 4 converges. Delete the file to start over.

The database is written in the format tools/disasm --seed-functions already
accepts (a list of {"start": "0x..."}), so it needs no conversion step. Extra
keys are ignored by that loader.
"""

import argparse
import json
import os
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.abspath(os.path.join(SCRIPT_DIR, "..", ".."))

DEFAULT_DB = os.path.join(SCRIPT_DIR, "output", "icall_targets.json")
FUNCTIONS_PATH = os.path.join(REPO_ROOT, "tools", "disasm", "output",
                              "functions.json")

SEEN_RESOLVED = 1
SEEN_UNRESOLVED = 2

FLAG_NAMES = {
    SEEN_RESOLVED: "resolved",
    SEEN_UNRESOLVED: "unresolved",
    SEEN_RESOLVED | SEEN_UNRESOLVED: "both",
}


def parse_dump(path):
    """Parse one runtime dump into {va: flags}.

    Tolerates truncation: the dump is written from a process that may be dying,
    so a short final line is expected rather than exceptional. That is also why
    the runtime writes text instead of JSON.
    """
    out = {}
    with open(path) as f:
        for lineno, line in enumerate(f, 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split()
            if len(parts) != 2:
                continue  # truncated tail
            try:
                va = int(parts[0], 16)
                flags = int(parts[1], 10)
            except ValueError:
                continue  # truncated tail
            if not flags:
                continue
            out[va] = out.get(va, 0) | flags
    return out


def load_db(path):
    """Load the cumulative database as {va: flags}."""
    if not os.path.exists(path):
        return {}
    with open(path) as f:
        data = json.load(f)
    out = {}
    for entry in data:
        if isinstance(entry, dict) and "start" in entry:
            out[int(entry["start"], 16)] = entry.get("flags", SEEN_RESOLVED)
        elif isinstance(entry, int):
            out[entry] = SEEN_RESOLVED
    return out


def save_db(path, targets):
    """Write the database in --seed-functions format."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    data = [
        {
            "start": "0x%08X" % va,
            "flags": flags,
            "seen": FLAG_NAMES.get(flags, str(flags)),
            "source": "icall-feedback",
        }
        for va, flags in sorted(targets.items())
    ]
    with open(path, "w") as f:
        json.dump(data, f, indent=1)
        f.write("\n")


def load_function_starts(path=None):
    """Known function start VAs, or None if the database has not been built.

    Defaults to the in-repo disasm output, but a real per-title project puts it
    somewhere else (Halo: build/disasm/functions.json), so this is overridable.
    Cross-referencing against another title's function database would silently
    report every target as a gap.
    """
    path = path or FUNCTIONS_PATH
    if not os.path.exists(path):
        return None
    with open(path) as f:
        return {int(fn["start"], 16) for fn in json.load(f)}


def cmd_merge(args):
    db = load_db(args.db)
    before = dict(db)

    observed = {}
    for path in args.dumps:
        if not os.path.exists(path):
            print("  ! missing dump: %s" % path, file=sys.stderr)
            continue
        d = parse_dump(path)
        print("  %-40s %6d targets" % (os.path.basename(path), len(d)))
        for va, flags in d.items():
            observed[va] = observed.get(va, 0) | flags

    if not observed:
        print("no observations to merge", file=sys.stderr)
        return 1

    for va, flags in observed.items():
        db[va] = db.get(va, 0) | flags

    new = sorted(set(db) - set(before))
    promoted = sorted(va for va in before if before[va] != db[va])

    save_db(args.db, db)

    print()
    print("database : %s" % args.db)
    print("  targets total  : %d  (+%d new this merge)" % (len(db), len(new)))
    print("  flags changed  : %d existing targets" % len(promoted))
    unresolved = sorted(va for va, f in db.items() if f & SEEN_UNRESOLVED)
    print("  ever-unresolved: %d" % len(unresolved))

    starts = load_function_starts(args.functions)
    if starts is None:
        print("\n  (no functions.json -- skipping cross-reference;"
              " pass --functions)")
    else:
        missing = [va for va in unresolved if va not in starts]
        print("\n  of those, NOT a known function start: %d" % len(missing))
        for va in missing[:20]:
            print("     0x%08X" % va)
        if len(missing) > 20:
            print("     ... and %d more" % (len(missing) - 20))
        print("\n  These are the real gaps. Seed them:")
        print("    python -m tools.disasm ... --seed-functions %s" % args.db)
        print("  Then classify what the detector still cannot place:")
        print("    python tools/recomp/analyze_unresolved.py")
    return 0


def cmd_seeds(args):
    """Write a filtered seed file from the database.

    Measurement and action are deliberately separate. The database records
    everything the title actually branched to, because throwing away an
    observation is unrecoverable. What is safe to hand the function detector is
    a narrower question, and getting it wrong is expensive: a seeded address
    that is not really a function start produces a bogus function whose
    translation is wrong, and that is worse than the no-op stub it replaced.

    The alignment filter exists because of a measured regression on Halo 2276.
    Seeding all 25 observed unresolved targets made the title crash *earlier*
    (segfault before the render_cameras.c:458 assert it used to reach, 6
    CreateTexture calls instead of 12). 21 of them were 16-aligned, which is
    what MSVC emits for a real function start; 4 were not. An unaligned
    indirect target is far more likely to be a garbage vtable read that
    happened to land inside .text than a function the detector missed -- the
    RECOMP_ICALL range check is trying to catch exactly that class and cannot,
    because the garbage is in range.
    """
    db = load_db(args.db)
    if not db:
        print("empty or missing database: %s" % args.db, file=sys.stderr)
        return 1

    # Deliberately NOT filtered against the current functions.json. Seeds are an
    # input to the pass that rewrites functions.json from scratch, so dropping
    # "already known" targets is circular: on the next run they are only known
    # *because* they were seeded, and an indirect-only target is one the detector
    # cannot re-derive on its own. A seed file must be a standalone statement of
    # what to seed, idempotent across runs.
    kept, dropped = {}, []
    for va, flags in sorted(db.items()):
        if args.align and (va % args.align):
            dropped.append((va, "not %d-aligned" % args.align))
            continue
        kept[va] = flags

    save_db(args.out, kept)
    print("seeds written : %s" % args.out)
    print("  from database: %d targets" % len(db))
    print("  kept         : %d" % len(kept))
    print("  dropped      : %d" % len(dropped))
    for va, why in dropped:
        print("     0x%08X  %s" % (va, why))
    return 0


def cmd_report(args):
    db = load_db(args.db)
    if not db:
        print("empty or missing database: %s" % args.db, file=sys.stderr)
        return 1
    counts = {}
    for flags in db.values():
        counts[flags] = counts.get(flags, 0) + 1
    print("database : %s" % args.db)
    print("  targets  : %d" % len(db))
    for flags in sorted(counts):
        print("    %-11s %6d" % (FLAG_NAMES.get(flags, str(flags)), counts[flags]))

    starts = load_function_starts(args.functions)
    if starts is None:
        print("  (no functions.json -- no cross-reference; pass --functions)")
        return 0
    known = sum(1 for va in db if va in starts)
    print("  known function starts   : %d" % known)
    print("  NOT function starts     : %d" % (len(db) - known))
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="tools.recomp.icall_feedback",
        description=__doc__.split("\n\n")[1].strip(),
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--db", default=DEFAULT_DB,
                    help="cumulative database path (default: %(default)s)")
    ap.add_argument("--functions", default=None, metavar="JSON",
                    help="functions.json to cross-reference against. Defaults to "
                         "the in-repo disasm output; a per-title project keeps its "
                         "own (Halo: build/disasm/functions.json).")
    sub = ap.add_subparsers(dest="cmd", required=True)

    m = sub.add_parser("merge", help="merge runtime dumps into the database")
    m.add_argument("dumps", nargs="+", help="files written by "
                                           "recomp_icall_feedback_dump()")
    m.set_defaults(func=cmd_merge)

    s = sub.add_parser("seeds", help="write a filtered seed file from the database")
    s.add_argument("--out", required=True, metavar="JSON",
                   help="seed file to write (feed to tools.disasm "
                        "--seed-functions)")
    s.add_argument("--align", type=int, default=16, metavar="N",
                   help="drop targets not N-byte aligned; 0 disables. Default "
                        "%(default)s, which is what MSVC emits for a function "
                        "start. See cmd_seeds for why this defaults on.")
    s.set_defaults(func=cmd_seeds)

    r = sub.add_parser("report", help="summarise the database")
    r.set_defaults(func=cmd_report)

    args = ap.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
