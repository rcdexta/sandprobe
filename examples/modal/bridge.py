"""Bridge between `sandprobe run exec` and one Modal sandbox you create for it (docs/providers/modal.md).

  bridge.py create <setup> <state.json>   create your own sandbox from a named setup; record its create-returned ID
  bridge.py sh <state.json>               open sh in that sandbox, as the setup's agent user; pipe stdin/stdout, pass the exit code
  bridge.py rm <state.json>               terminate that sandbox by its recorded ID and confirm nothing with its tag runs

Rules: your own sandbox in your own workspace only, CPU only, a 15-minute timeout as a spend backstop, terminated by
the ID create returned. The token stays with Modal's SDK; nothing here reads or prints it.
"""
import json
import os
import secrets
import sys
import threading
import time

import modal

APP = "sandprobe"
BASE = "python:3.12-slim-bookworm"  # the image the fixes below were proven on
AGENT = ["setpriv", "--reuid=1000", "--regid=1000", "--init-groups", "--inh-caps=-all", "--ambient-caps=-all", "--no-new-privs"]

# Each setup is one round of the fix loop: the fixes applied so far, by `sandprobe fix` action ID.
SETUPS = {
    # Modal's defaults. Root, network open.
    "round-0": dict(user=False, block=False, clean_env=False, protect_home=False),
    # run-as-user and block-network: the agent runs as an unprivileged user; the sandbox has no network.
    "round-1": dict(user=True, block=True, clean_env=False, protect_home=False),
    # Plus clean-env and protect-home: a minimal environment, and a HOME the agent can't change (work goes in /work).
    "round-2": dict(user=True, block=True, clean_env=True, protect_home=True),
}


def image(cfg):
    img = modal.Image.from_registry(BASE)
    if cfg["user"]:
        img = img.run_commands("command -v setpriv", "useradd -m -u 1000 -s /bin/bash agent")
    if cfg["protect_home"]:
        img = img.run_commands("chown -R root:root /home/agent", "chmod 0755 /home/agent",
                               "mkdir -p /work", "chown agent:agent /work")
    return img


def create(name, state):
    cfg = SETUPS[name]
    tag = secrets.token_hex(12)
    app = modal.App.lookup(APP, create_if_missing=True)
    sb = modal.Sandbox.create("sleep", "infinity", app=app, image=image(cfg), timeout=900, cpu=1.0,
                              block_network=cfg["block"])
    sb.set_tags({"sandprobe-bridge": tag})
    rec = {"id": sb.object_id, "setup": name, "tag": tag, "created": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
    fd = os.open(state, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(rec, f)
    print(f"created {rec['id']} ({name})", file=sys.stderr)


def sh(state):
    rec = json.load(open(state))
    cfg = SETUPS[rec["setup"]]
    sb = modal.Sandbox.from_id(rec["id"])
    if not cfg["user"]:
        argv, env = ["sh"], None
    elif cfg["clean_env"]:
        argv, env = AGENT + ["--reset-env", "sh"], None
    else:
        argv, env = AGENT + ["sh"], {"HOME": "/home/agent", "USER": "agent", "LOGNAME": "agent"}
    p = sb.exec(*argv, env=env, text=False, workdir="/work" if cfg["protect_home"] else None)

    def pump_in():
        while True:
            chunk = sys.stdin.buffer.read1(65536)
            if not chunk:
                break
            p.stdin.write(chunk)
            p.stdin.drain()
        p.stdin.write_eof()
        p.stdin.drain()

    def pump(src, dst):
        for chunk in src:
            dst.write(chunk if isinstance(chunk, bytes) else chunk.encode())
            dst.flush()

    threads = [threading.Thread(target=pump_in, daemon=True),
               threading.Thread(target=pump, args=(p.stderr, sys.stderr.buffer), daemon=True)]
    for t in threads:
        t.start()
    pump(p.stdout, sys.stdout.buffer)
    code = p.wait()
    threads[1].join(timeout=5)
    sys.exit(code if isinstance(code, int) else 1)


def rm(state):
    rec = json.load(open(state))
    sb = modal.Sandbox.from_id(rec["id"])
    sb.terminate()
    for _ in range(60):
        if sb.poll() is not None:
            break
        time.sleep(1)
    app = modal.App.lookup(APP)
    left = [s.object_id for s in modal.Sandbox.list(app_id=app.app_id, tags={"sandprobe-bridge": rec["tag"]})]
    if left:
        print(f"NOT CONFIRMED: still listed with this run's tag: {left}", file=sys.stderr)
        sys.exit(7)
    os.remove(state)
    print(f"terminated {rec['id']}: finished, and nothing running with its tag", file=sys.stderr)


if __name__ == "__main__":
    verb = sys.argv[1] if len(sys.argv) > 1 else ""
    if verb == "create" and len(sys.argv) == 4:
        create(sys.argv[2], sys.argv[3])
    elif verb == "sh" and len(sys.argv) == 3:
        sh(sys.argv[2])
    elif verb == "rm" and len(sys.argv) == 3:
        rm(sys.argv[2])
    else:
        sys.exit("usage: bridge.py create <setup> <state> | sh <state> | rm <state>")
