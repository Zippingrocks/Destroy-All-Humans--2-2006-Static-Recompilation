"""Remove every breakpoint tools/xemu_firsthit.py / xemu_bt.py may have left on an OWNED private xemu."""
import sys, time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
from xemu_bt import Rsp, INPUT_SITE, function_index
port = int(sys.argv[1])
g = Rsp(port); g.cmd("qSupported:multiprocess+;swbreak+"); g.interrupt(); time.sleep(0.3); g.buf = b""
starts = [x for x in function_index() if 0x11000 <= x < 0x225CA0] + [0x1A7920]
for ad in starts: g.send("z0,%x,1" % ad)
for ad in starts: g.recv(10)
for ad in starts + [INPUT_SITE]: g.send("z1,%x,1" % ad)
for ad in starts + [INPUT_SITE]: g.recv(10)
g.send("c"); time.sleep(0.3); g.s.close(); print("cleared", len(starts))
