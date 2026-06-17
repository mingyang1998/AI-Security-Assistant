import subprocess, sys, time

print("[parent] starting child ...")
p = subprocess.Popen(
    [sys.executable, "-c", "import time; print('[child] hello'); time.sleep(2); print('[child] bye')"],
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
)
print(f"[parent] child pid={p.pid}")
try:
    out, err = p.communicate(timeout=5)
    print("[parent] CHILD OUT:", out.decode())
    print("[parent] CHILD ERR:", err.decode())
    print("[parent] rc =", p.returncode)
except subprocess.TimeoutExpired:
    print("[parent] TIMEOUT - killing child")
    p.kill()
    out, err = p.communicate()
    print("[parent] CHILD OUT:", out.decode())
    print("[parent] CHILD ERR:", err.decode())
