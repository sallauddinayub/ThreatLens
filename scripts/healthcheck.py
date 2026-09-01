"""
Quick sanity check that the platform (and optionally the demo app) is up.
Run with: python scripts/healthcheck.py
"""
import sys
import urllib.request

CHECKS = [
    ("Platform", "http://localhost:5000/health"),
    ("Demo app (optional)", "http://localhost:8081/"),
]


def check(name: str, url: str) -> bool:
    try:
        with urllib.request.urlopen(url, timeout=3) as resp:
            ok = resp.status == 200
            print(f"{'OK  ' if ok else 'FAIL'}  {name:<20} {url}  (HTTP {resp.status})")
            return ok
    except Exception as exc:  # noqa: BLE001
        print(f"FAIL  {name:<20} {url}  ({exc})")
        return False


if __name__ == "__main__":
    results = [check(name, url) for name, url in CHECKS]
    # The demo app is optional, so only the first check (the platform itself) is required.
    if results[0]:
        print("\nPlatform is up.")
        sys.exit(0)
    else:
        print("\nPlatform is not reachable yet — check the terminal window for errors.")
        sys.exit(1)
