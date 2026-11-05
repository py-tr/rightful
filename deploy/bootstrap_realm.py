"""Create the fictional realm on the deployed Keycloak and write the generated client secrets to a root-only file."""
import json
import os
import sys

from devenv import keycloak_local as kl


def main():
    out = sys.argv[1]
    env = kl.bootstrap(os.environ.get("KC_URL", "http://127.0.0.1:8089"), smtp=True)
    import secrets
    data = {k: env[k] for k in ("broker", "ciba", "reconciler", "console", "users")}
    data["run_key_master"] = secrets.token_hex(32)       # per-task edge keys are derived from it (broker/runkey.py)
    with open(out, "w", encoding="utf-8") as f:
        json.dump(data, f)
    os.chmod(out, 0o600)
    print("realm ready; secrets written to", out)


if __name__ == "__main__":
    main()
