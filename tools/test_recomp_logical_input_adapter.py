"""Pin the hidden recomp logical-pad adapter to the retail XInput boundary."""
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
source = (ROOT / "src/recomp_manual.c").read_text(encoding="utf-8")
block = re.search(r"/\* DAH2_INPUT_REPLAY_BEGIN.*?/\* DAH2_INPUT_REPLAY_END \*/", source, re.S)
assert block, "logical input adapter block missing"
code = block.group()

assert 'strcmp(hidden, "1") == 0' in code
assert 'getenv("DAH2_INPUT_SCRIPT")' in code
for symbol in (
    "sub_002961C2",  # XInputOpen
    "sub_00296218",  # XInputClose
    "sub_00296224",  # XInputGetState
    "sub_00296297",  # XInputSetState
    "sub_00296353",  # XGetDevices
    "sub_00296375",  # XGetDeviceChanges
):
    assert f"void {symbol}(void)" in code
assert "DAH2_INPUT_HANDLE_BASE + port" in code
assert "g_dah2_input_reported = 1" in code
assert "MEM32(inserted_out) = inserted" in code
assert "MEM32(removed_out) = 0" in code
assert "vibration suppressed" in code
assert "dah2_scripted_xinput_get_state();" in code
assert "esp += 12u;    /* ret 8 */" in code
assert "memcpy(manual_mem8(output), state, sizeof(state))" in code
assert "XInputGetState(" not in code and "GetAsyncKeyState(" not in code
assert "SwitchDesktop" not in code and "SetThreadDesktop" not in code

for address, symbol in (
    ("0x002961C2", "sub_002961C2"),
    ("0x00296218", "sub_00296218"),
    ("0x00296224", "sub_00296224"),
    ("0x00296297", "sub_00296297"),
    ("0x00296353", "sub_00296353"),
    ("0x00296375", "sub_00296375"),
):
    dispatch = f"if (xbox_va == {address}) return {symbol};"
    assert source.count(dispatch) == 1

script = ROOT / "tools/dah2_title_skip_input.txt"
rows = []
for raw in script.read_text(encoding="utf-8").splitlines():
    line = raw.strip()
    if not line or line.startswith("#"):
        continue
    fields = line.split()
    assert len(fields) in (9, 15)
    values = [int(value, 16 if index == 2 else 10) for index, value in enumerate(fields)]
    rows.append(values)
assert rows == [[0, 1, 0x10, 0, 0, 0, 0, 0, 0]]

# The first two retail polls must match the xemu adapter: Start, then neutral.
def payload(poll: int) -> bytes:
    result = bytearray(18)
    for start, duration, buttons, *_ in rows:
        if start <= poll < start + duration:
            result[0] |= buttons & 0xFF
            result[1] |= buttons >> 8
    return bytes(result)

assert payload(0).hex() == "1000" + "00" * 16
assert payload(1).hex() == "00" * 18
print("PASS: hidden recomp lifecycle and one-poll Start schedule match the DAH1/xemu retail boundary")
