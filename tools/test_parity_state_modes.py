"""Compile the real state/history initializers; no game or UI is launched."""
from pathlib import Path
import os
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
state = (ROOT / "src/parity_state.c").read_text(encoding="utf-8")
gpu = (ROOT / "xboxrecomp/src/nv2a/nv2a_pgraph_d3d11.c").read_text(encoding="utf-8")
init = re.search(r"static BOOL CALLBACK state_initialize\(.*?^\}", state, re.M | re.S).group()
history = re.search(r"static int pgraph_method_hist_enabled\(.*?^\}", gpu, re.M | re.S).group()
source = '#include <windows.h>\n#include <stdlib.h>\nstatic int state_enabled;\n' + init + '\n' + history + r'''
int main(int argc,char **argv) {
    if(argc!=3) return 2;
    state_initialize(NULL,NULL,NULL);
    return state_enabled!=atoi(argv[1]) || pgraph_method_hist_enabled()!=atoi(argv[2]);
}
'''
flags = ("DAH2_PARITY_STATE_MEMORY", "DAH2_PARITY_TIMING_MEMORY", "DAH2_METHOD_HIST")
cases = [({}, 0, 0), ({flags[0]: "1"}, 1, 1), ({flags[1]: "1"}, 1, 0),
         ({flags[2]: "1"}, 0, 1), ({flags[0]: "0", flags[1]: "1"}, 1, 0),
         ({flags[0]: "1", flags[1]: "0"}, 1, 1),
         ({flags[1]: "1", flags[2]: "1"}, 1, 1)]
for flag in flags:
    for invalid in ("0", "true", "01", "11", ""):
        cases.append(({flag: invalid}, 0, 0))
with tempfile.TemporaryDirectory(prefix="dah2_state_modes_") as temporary:
    directory = Path(temporary)
    (directory / "test.c").write_text(source)
    vcvars = Path("C:/Program Files/Microsoft Visual Studio/2022/Community/VC/Auxiliary/Build/vcvars64.bat")
    command = f'call "{vcvars}" >nul && cl /nologo /W4 /TC test.c /Fe:test.exe'
    subprocess.run('cmd.exe /d /s /c "' + command + '"', cwd=directory,
                   capture_output=True, check=True, creationflags=subprocess.CREATE_NO_WINDOW)
    for changes, wanted_state, wanted_history in cases:
        environment = os.environ.copy()
        for flag in flags:
            environment.pop(flag, None)
        environment.update(changes)
        result = subprocess.run([str(directory / "test.exe"), str(wanted_state), str(wanted_history)],
            env=environment, capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW)
        assert result.returncode == 0, (changes, wanted_state, wanted_history, result.returncode)
print(f"PASS: {len(cases)} native mode cases; timing-only state does not enable method history")
