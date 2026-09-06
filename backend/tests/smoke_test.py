import sys
import time

import httpx

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8000"
client = httpx.Client(base_url=BASE, timeout=30)

r = client.get("/api/health")
assert r.status_code == 200 and r.json()["database"], r.text
print("health OK:", r.json())

content = b"%PDF-1.4\n% dummy document for async smoke test\n"
files = {"file": ("dummy.pdf", content, "application/pdf")}
r = client.post("/api/scans", files=files)
assert r.status_code == 202, r.text
scan = r.json()
sid = scan["id"]
print("queued scan:", {k: scan[k] for k in ("id", "status", "verdict")})
assert scan["status"] == "queued", scan
assert scan["file"]["sha256"]

deadline = time.time() + 60
detail = None
while time.time() < deadline:
    r = client.get(f"/api/scans/{sid}")
    detail = r.json()
    if detail["status"] in ("completed", "failed"):
        break
    time.sleep(0.5)
assert detail["status"] == "completed", detail
print(
    "final:",
    {k: detail[k] for k in ("status", "verdict", "action", "risk_score")},
)
assert any(f["source"] == "sandbox" for f in detail["findings"]), detail["findings"]
print("sandbox finding OK:", [f["source"] for f in detail["findings"]])

r = client.get("/api/scans?limit=10")
assert r.status_code == 200 and isinstance(r.json(), list), r.text
print(f"list OK ({len(r.json())} scans)")

print("SMOKE TEST PASSED")
