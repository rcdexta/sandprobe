"""Bridge between `sandprobe run exec` and one Modal sandbox you create for it (docs/providers/modal.md, FIX-10).

  bridge.py create <setup> <state.json>   create your own sandbox from a named setup; record the ID create returned
  bridge.py sh <state.json>               open sh in that sandbox, as the setup's agent user; pipe stdin/stdout, pass the exit code
  bridge.py rm <state.json>               terminate that sandbox and confirm nothing with its tag still runs

Rules: your own sandbox in your own workspace only, CPU only, a 15-minute timeout as a spend backstop. The app name and
tag key are fixed here, never read from the state. sh and rm act only on the one live sandbox of that app carrying the
recorded tag, and only when its ID is the recorded one; anything else refuses and touches nothing. The token stays
with Modal's SDK: nothing here reads or prints it, or prints an SDK error's text. Needs modal 1.5.5 or later.

Exit codes: 0 done; 1 failed, with anything created terminated and confirmed; 2 usage, or refused before touching
anything; 7 a sandbox may still run (its ID is printed, and it ends at its timeout).
"""
import json
import os
import re
import secrets
import signal
import stat
import sys
import threading
import time

import modal

APP = "sandprobe"
TAG_KEY = "sandprobe-bridge"
TIMEOUT = 900  # seconds: the spend backstop
WAIT = 60  # seconds to confirm a terminate
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

STATE_MAX = 4096
FORMS = {"id": re.compile(r"sb-[A-Za-z0-9]{1,64}"), "tag": re.compile(r"[0-9a-f]{24}"),
         "created": re.compile(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ"), "setup": re.compile("|".join(SETUPS))}

_sleep = time.sleep  # the tests make waiting instant


class Refused(Exception):
    """Something isn't as recorded: nothing was touched."""


class Interrupted(BaseException):
    """SIGTERM or SIGHUP while a created sandbox has no confirmed record yet."""


def stop(code, message):
    print(message, file=sys.stderr)
    sys.exit(code)


def image(cfg):
    img = modal.Image.from_registry(BASE)
    if cfg["user"]:
        img = img.run_commands("command -v setpriv", "useradd -m -u 1000 -s /bin/bash agent")
    if cfg["protect_home"]:
        img = img.run_commands("chown -R root:root /home/agent", "chmod 0755 /home/agent",
                               "mkdir -p /work", "chown agent:agent /work")
    return img


def private(fd):
    """A regular file of this user's own, with one link and no group or other bits."""
    st = os.fstat(fd)
    return (stat.S_ISREG(st.st_mode) and st.st_uid == os.getuid() and st.st_nlink == 1
            and stat.S_IMODE(st.st_mode) & 0o077 == 0)


def fsync_dir(path):
    d = os.open(os.path.dirname(os.path.abspath(path)), os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(d)
    finally:
        os.close(d)


def read_state(path):
    """The state, only as a private file in exactly its form (FIX-10), or Refused."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError as e:
        raise Refused(f"the state file can't be opened as a plain file ({type(e).__name__})")
    try:
        if not private(fd) or os.fstat(fd).st_size > STATE_MAX:
            raise Refused("the state file isn't a private regular file of yours, with one link, under 4 KiB")
        data = os.read(fd, STATE_MAX + 1)
    finally:
        os.close(fd)

    def no_duplicates(pairs):
        keys = [k for k, _ in pairs]
        if len(keys) != len(set(keys)):
            raise Refused("the state file repeats a field")
        return dict(pairs)

    try:
        rec = json.loads(data, object_pairs_hook=no_duplicates)
    except ValueError:
        raise Refused("the state file isn't one JSON object")
    if not isinstance(rec, dict) or set(rec) != set(FORMS) or not all(
            isinstance(rec[k], str) and FORMS[k].fullmatch(rec[k]) for k in FORMS):
        raise Refused("the state file doesn't hold exactly id, setup, tag and created, each in its form")
    return rec


def owned(rec):
    """The one live sandbox of the fixed app carrying the recorded tag, whose ID is the recorded one, or Refused."""
    try:
        app = modal.App.lookup(APP)
        found = list(modal.Sandbox.list(app_id=app.app_id, tags={TAG_KEY: rec["tag"]}))
    except Exception as e:
        raise Refused(f"couldn't list the {APP} app's sandboxes ({type(e).__name__})")
    if not found:
        raise Refused(f"no live sandbox in the {APP} app carries this state's tag: it may have ended at its timeout")
    if len(found) != 1:
        raise Refused(f"{len(found)} live sandboxes carry this state's tag; expected exactly one")
    if found[0].object_id != rec["id"]:
        raise Refused("the sandbox carrying this state's tag isn't the one the state records")
    return found[0]


def terminated(sb):
    """Terminate through this object, and confirm it finished."""
    try:
        sb.terminate()
        for _ in range(WAIT):
            if sb.poll() is not None:
                return True
            _sleep(1)
    except Exception:
        return False
    return False


def create(name, state):
    if name not in SETUPS:
        stop(2, "usage: the setup is one of " + ", ".join(SETUPS))
    cfg = SETUPS[name]
    tag = secrets.token_hex(12)
    # Reserve the state path first, so a path in the way stops this before anything is created.
    try:
        fd = os.open(state, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    except OSError as e:
        stop(2, f"refused: the state path is in the way or can't be made ({type(e).__name__}); nothing was created")
    reserved = os.fstat(fd)

    def unreserve():
        try:
            st = os.lstat(state)
            if (st.st_dev, st.st_ino) == (reserved.st_dev, reserved.st_ino):
                os.unlink(state)
        except OSError:
            pass

    if not private(fd):
        os.close(fd)
        unreserve()
        stop(2, "refused: the state path didn't make a private regular file; nothing was created")

    def interrupted(signum, frame):
        raise Interrupted()

    for s in (signal.SIGTERM, signal.SIGHUP):
        signal.signal(s, interrupted)
    sb = None
    try:
        app = modal.App.lookup(APP, create_if_missing=True)
        sb = modal.Sandbox.create("sleep", "infinity", app=app, image=image(cfg), timeout=TIMEOUT, cpu=1.0,
                                  block_network=cfg["block"], tags={TAG_KEY: tag})
        rec = {"id": sb.object_id, "setup": name, "tag": tag,
               "created": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
        data = json.dumps(rec).encode()
        if os.write(fd, data) != len(data):
            raise OSError("short write")
        os.fsync(fd)
        os.close(fd)
        fd = None
        fsync_dir(state)
        owned(rec)  # sh and rm will find it exactly so
    except BaseException as e:
        for s in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
            signal.signal(s, signal.SIG_IGN)
        if fd is not None:
            os.close(fd)
        why = type(e).__name__
        if sb is None:
            unreserve()
            stop(1, f"create failed ({why}) before it returned a sandbox: if Modal made one anyway, it ends at its "
                    f"{TIMEOUT // 60}-minute timeout")
        if terminated(sb):  # through the object create returned, never a lookup
            unreserve()
            stop(1, f"create failed ({why}) after making sandbox {sb.object_id}: terminated it and confirmed it finished")
        stop(7, f"NOT CONFIRMED: create failed ({why}) after making sandbox {sb.object_id}, and its termination isn't "
                f"confirmed; it ends at its {TIMEOUT // 60}-minute timeout. Check it in Modal by that ID.")
    print(f"created {rec['id']} ({name})", file=sys.stderr)


def sh(state):
    try:
        rec = read_state(state)
        sb = owned(rec)
    except Refused as e:
        stop(2, f"refused: {e}; nothing was touched")
    cfg = SETUPS[rec["setup"]]
    if not cfg["user"]:
        argv, env = ["sh"], None
    elif cfg["clean_env"]:
        argv, env = AGENT + ["--reset-env", "sh"], None
    else:
        argv, env = AGENT + ["sh"], {"HOME": "/home/agent", "USER": "agent", "LOGNAME": "agent"}
    try:
        p = sb.exec(*argv, env=env, text=False, workdir="/work" if cfg["protect_home"] else None)
    except Exception as e:
        stop(1, f"exec failed ({type(e).__name__})")

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
    try:
        rec = read_state(state)
        sb = owned(rec)
    except Refused as e:
        hint = ""
        if "may have ended" in str(e):
            hint = "; once Modal shows that sandbox finished, remove the state file yourself"
        stop(2, f"refused: {e}; nothing was touched{hint}")
    if not terminated(sb):
        stop(7, f"NOT CONFIRMED: sandbox {rec['id']} may still run; it ends at its {TIMEOUT // 60}-minute timeout")
    try:
        app = modal.App.lookup(APP)
        left = [s.object_id for s in modal.Sandbox.list(app_id=app.app_id, tags={TAG_KEY: rec["tag"]})]
    except Exception as e:
        stop(7, f"NOT CONFIRMED: terminated {rec['id']}, but couldn't list what still runs ({type(e).__name__})")
    if left:
        stop(7, f"NOT CONFIRMED: still listed with this run's tag: {left}")
    os.unlink(state)
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
        stop(2, "usage: bridge.py create <setup> <state> | sh <state> | rm <state>")
