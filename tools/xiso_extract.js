const fs = require('fs');
const path = require('path');

const SECTOR = 2048;
const MAGIC = Buffer.from('MICROSOFT*XBOX*MEDIA', 'ascii');
const BASES = [0x00000000, 0x0000FD90, 0x00030600, 0x0FD90000, 0x18300000];

function readAt(fd, offset, size) {
  const out = Buffer.alloc(size);
  const got = fs.readSync(fd, out, 0, size, offset);
  return out.subarray(0, got);
}

function findBase(fd) {
  for (const base of BASES) {
    const probe = readAt(fd, base + 32 * SECTOR, MAGIC.length);
    if (probe.equals(MAGIC)) return base;
  }
  throw new Error('No XDVDFS game partition found');
}

function readDirectory(fd, imageBase, sector, size) {
  const data = readAt(fd, imageBase + sector * SECTOR, size);
  const entries = [];
  for (let base = 0; base < data.length; base += SECTOR) {
    const end = Math.min(base + SECTOR, data.length);
    let off = base;
    while (off + 14 <= end) {
      const left = data.readUInt16LE(off);
      const right = data.readUInt16LE(off + 2);
      const entrySector = data.readUInt32LE(off + 4);
      const entrySize = data.readUInt32LE(off + 8);
      const attributes = data[off + 12];
      const nameLength = data[off + 13];
      if ((left === 0xffff && right === 0xffff) || nameLength === 0 || off + 14 + nameLength > end) break;
      const name = data.toString('ascii', off + 14, off + 14 + nameLength);
      entries.push({ name, sector: entrySector, size: entrySize, isDirectory: !!(attributes & 0x10) });
      off += (14 + nameLength + 3) & ~3;
    }
  }
  return entries;
}

function main() {
  const [isoPath, wantedName, outputPath] = process.argv.slice(2);
  if (!isoPath || !wantedName || !outputPath) {
    console.error('Usage: node tools/xiso_extract.js <image.iso> <root-file> <output>');
    process.exit(2);
  }
  const fd = fs.openSync(isoPath, 'r');
  try {
    const imageBase = findBase(fd);
    const descriptor = readAt(fd, imageBase + 32 * SECTOR, SECTOR);
    const rootSector = descriptor.readUInt32LE(0x14);
    const rootSize = descriptor.readUInt32LE(0x18);
    const entry = readDirectory(fd, imageBase, rootSector, rootSize)
      .find((item) => !item.isDirectory && item.name.toLowerCase() === wantedName.toLowerCase());
    if (!entry) throw new Error(`Root file not found: ${wantedName}`);
    fs.mkdirSync(path.dirname(path.resolve(outputPath)), { recursive: true });
    const out = fs.openSync(outputPath, 'w');
    try {
      let remaining = entry.size;
      let inputOffset = imageBase + entry.sector * SECTOR;
      const chunk = Buffer.alloc(Math.min(1024 * 1024, entry.size));
      while (remaining > 0) {
        const amount = Math.min(chunk.length, remaining);
        const got = fs.readSync(fd, chunk, 0, amount, inputOffset);
        if (!got) throw new Error(`Image ended while extracting ${entry.name}`);
        fs.writeSync(out, chunk, 0, got);
        remaining -= got;
        inputOffset += got;
      }
    } finally {
      fs.closeSync(out);
    }
    console.log(`partition=0x${imageBase.toString(16)} ${entry.name} -> ${outputPath} (${entry.size} bytes)`);
  } finally {
    fs.closeSync(fd);
  }
}

main();
