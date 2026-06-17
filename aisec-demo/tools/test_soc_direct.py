import subprocess, sys, time
from pathlib import Path

log = Path("data/pids/soc-direct.log").open("wb")
print("[host] starting soc-agent ...")
p = subprocess.Popen(
    [sys.executable, "-m", "aisec.agents.soc"],
    stdout=log,
    stderr=subprocess.STDOUT,
    cwd=Path.cwd(),
)
print(f"[host] pid={p.pid}, waiting 8s ...")
time.sleep(8)
print(f"[host] poll -> {p.poll()}")
try:
    log.close()
except Exception:
    pass
print("[host] log content:")
print(Path("data/pids/soc-direct.log").read_text(errors="ignore")[:2000])
