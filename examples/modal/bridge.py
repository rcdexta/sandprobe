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
import logging
import os
import re
import secrets
import select
import signal
import stat
import sys
import threading
import time
import warnings


# Nothing an SDK raises, logs or warns reaches the terminal as text: only fixed lines and an exception's type
# (FIX-10, AGENTS rule 3). These hooks catch what the boundary in main can't: threads, unraisable errors, warnings
# and the SDK's own logging.
def _say(line):
    try:
        sys.stderr.write(line + "\n")
        sys.stderr.flush()
    except Exception:
        pass


def _uncaught(kind, value, tb):
    _say(f"bridge: failed ({kind.__name__})")


def _thread_uncaught(args):
    if args.exc_type is not SystemExit:
        _say(f"bridge: a worker failed ({args.exc_type.__name__})")


def _unraisable(u):
    _say(f"bridge: an error was ignored ({type(u.exc_value).__name__})")


def _warning(message, category, filename, lineno, file=None, line=None):
    _say(f"bridge: warning ({category.__name__})")


sys.excepthook, threading.excepthook, sys.unraisablehook = _uncaught, _thread_uncaught, _unraisable
warnings.showwarning = _warning
logging.disable(logging.CRITICAL)

import modal  # noqa: E402  (after the hooks, so its import can't print either)

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
    p = sb.exec(*argv, env=env, text=False, workdir="/work" if cfg["protect_home"] else None)
    sys.exit(session(p))


STDIN_JOIN, OUTPUT_JOIN = 2.0, 5.0  # seconds each pump may take to finish once the remote process has ended


def session(p):
    """FIX-10's ordered exit path: the remote's exit, then every pump stopped and joined, then one read of the failure
    slot, then the exit code. The remote's own code passes through only when no pump failed and none timed out."""
    stop = threading.Event()  # set once the remote process has ended: the stdin pump starts no new call after it
    lock = threading.Lock()
    slot = {"failed": None, "closed": False}

    def record(e):
        with lock:
            if not slot["closed"] and slot["failed"] is None:
                slot["failed"] = type(e).__name__

    def pump_in():
        # fd 0 through select and os.read, never a buffered stream, so the loop wakes every 0.1 s and holds no
        # stream lock. A closed or invalid descriptor reads as end of input; /dev/null and a regular file end at EOF.
        try:
            while not stop.is_set():
                try:
                    ready, _, _ = select.select([0], [], [], 0.1)
                    chunk = os.read(0, 65536) if ready else None
                except (OSError, ValueError):
                    chunk = b""
                if chunk is None:
                    continue
                if stop.is_set():  # the remote has ended: it gets no more input
                    return
                if not chunk:
                    p.stdin.write_eof()
                    p.stdin.drain()
                    return
                p.stdin.write(chunk)
                p.stdin.drain()
        except BaseException as e:
            record(e)

    def pump_out(src, fd):
        # straight to the descriptor with os.write, never a buffered stream, so no thread holds a stream lock
        try:
            for chunk in src:
                data = chunk if isinstance(chunk, bytes) else chunk.encode()
                while data:
                    data = data[os.write(fd, data):]
        except BaseException as e:
            record(e)

    pumps = [(threading.Thread(target=pump_in, daemon=True), STDIN_JOIN),
             (threading.Thread(target=pump_out, args=(p.stdout, 1), daemon=True), OUTPUT_JOIN),
             (threading.Thread(target=pump_out, args=(p.stderr, 2), daemon=True), OUTPUT_JOIN)]
    for t, _ in pumps:
        t.start()
    code, waited = None, None
    try:
        code = p.wait()  # 1. the remote process ends, or waiting for it fails
    except BaseException as e:
        waited = type(e).__name__
    stop.set()  # 2. every pump told to stop, then each joined within its bound
    late = False
    for t, bound in pumps:
        t.join(timeout=bound)
        late = late or t.is_alive()
    with lock:  # 3. the slot read once; nothing writes it after this
        slot["closed"] = True
        failed = slot["failed"]
    if waited:
        line, exit_code = f"the session with the sandbox failed ({waited})", 1
    elif failed:
        line, exit_code = f"the session with the sandbox failed ({failed})", 1
    elif late:
        line, exit_code = "the session with the sandbox failed (a pump didn't finish in time)", 1
    else:
        line, exit_code = None, code if isinstance(code, int) else 1
    if line:
        _say(line)
    for f in (sys.stdout, sys.stderr):  # 4. flush, then exit
        try:
            f.flush()
        except Exception:
            pass
    if late:
        os._exit(exit_code)  # a pump still runs: leave without finalizing around it
    return exit_code


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


# The exit code when a verb fails past its own handling: sh 1; rm 7, since the sandbox may still run; create 1 (it
# handles every failure after create itself).
FAILED = {"create": 1, "sh": 1, "rm": 7}


def main(argv):
    verb = argv[1] if len(argv) > 1 else ""
    fn, n = {"create": (create, 4), "sh": (sh, 3), "rm": (rm, 3)}.get(verb, (None, 0))
    if fn is None or len(argv) != n:
        stop(2, "usage: bridge.py create <setup> <state> | sh <state> | rm <state>")
    try:
        fn(*argv[2:])
    except SystemExit:
        raise
    except KeyboardInterrupt:
        stop(FAILED[verb], f"{verb} interrupted")
    except BaseException as e:  # one boundary for the whole verb: exec, pumps, wait, list, terminate, poll
        if verb == "rm":
            stop(7, f"NOT CONFIRMED: rm failed ({type(e).__name__}); the sandbox may still run until its timeout")
        stop(FAILED[verb], f"{verb} failed ({type(e).__name__})")


if __name__ == "__main__":
    main(sys.argv)
