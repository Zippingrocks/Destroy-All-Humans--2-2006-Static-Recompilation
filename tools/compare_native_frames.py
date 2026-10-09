"""Strict RGB comparison: no resizing, alignment, cropping, or tolerance."""
import argparse
import hashlib
import json
from pathlib import Path

import numpy as np
from PIL import Image


def compare(reference, candidate):
    left = np.asarray(reference.convert('RGB'), dtype=np.uint8)
    right = np.asarray(candidate.convert('RGB'), dtype=np.uint8)
    result = dict(schema=1, channels='RGB', referenceSize=list(reference.size),
                  candidateSize=list(candidate.size), sameDimensions=left.shape == right.shape,
                  exactPixels=False, timingVerified=False,
                  referenceSha256=hashlib.sha256(left.tobytes()).hexdigest(),
                  candidateSha256=hashlib.sha256(right.tobytes()).hexdigest(),
                  note='Pixel equality alone does not establish matching game state, animation phase, or timing.')
    if left.shape != right.shape:
        return result, None
    delta = np.abs(left.astype(np.int16) - right.astype(np.int16))
    different = np.any(delta != 0, axis=2)
    y, x = np.nonzero(different)
    result.update(exactPixels=not bool(different.any()), differentPixels=int(different.sum()),
                  totalPixels=int(different.size), differentPercent=float(100 * different.mean()),
                  meanAbsoluteChannelError=float(delta.mean()), maxChannelError=int(delta.max()),
                  differenceBounds=[int(x.min()), int(y.min()), int(x.max()) + 1, int(y.max()) + 1] if x.size else None)
    # Absolute RGB differences are shown at their actual 0..255 magnitudes.
    return result, Image.fromarray(delta.astype(np.uint8))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('reference', type=Path)
    parser.add_argument('candidate', type=Path)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--diff', type=Path)
    args = parser.parse_args()
    if args.out.exists() or (args.diff and args.diff.exists()):
        raise FileExistsError('Comparison outputs must be new files')
    with Image.open(args.reference) as left, Image.open(args.candidate) as right:
        result, difference = compare(left, right)
    result.update(reference=str(args.reference.resolve()), candidate=str(args.candidate.resolve()))
    with args.out.open('x', encoding='utf-8') as stream:
        json.dump(result, stream, indent=2)
        stream.write('\n')
    if args.diff and difference is not None:
        difference.save(args.diff)
    print(json.dumps(result))
    return 0 if result['exactPixels'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
