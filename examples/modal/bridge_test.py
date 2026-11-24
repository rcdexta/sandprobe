"""FIX-10: bridge.py against a fake modal module. No network, no Modal account: the real SDK is never imported.

Run with: python3 -I -B examples/modal/bridge_test.py (cmd/sandprobe's TestModalBridge does).
"""
import importlib.util
import io
import json
import logging
import os
import stat
import subprocess
import sys
import tempfile
import threading
import time
import types
import unittest
import warnings

SENTINEL = "SENTINEL_SDK_SECRET"


class FakeWorld:
    def __init__(self):
        self.apps = {}  # name -> app_id
        self.sandboxes = []  # live FakeSandbox
        self.calls = []  # ("exec"|"terminate"|"create", sandbox id)
        self.fail_create = None  # an exception create raises before returning
        self.terminate_confirms = True
        self.fail = set()  # where the fake SDK raises SENTINEL (FIX-10's sanitizing tests)
        self.shape = None  # a function given each new FakeProcess, to change its timing (the looped scenarios)


def boom(where):
    if where in world.fail:
        raise RuntimeError(SENTINEL + " at " + where)


world = FakeWorld()


class FakeApp:
    def __init__(self, app_id):
        self.app_id = app_id

    @staticmethod
    def lookup(name, create_if_missing=False):
        if name not in world.apps:
            if not create_if_missing:
                raise LookupError("no such app")
            world.apps[name] = "ap-" + name
        return FakeApp(world.apps[name])


class FakeStream:
    def __init__(self, where, chunks):
        self.where, self.chunks = where, chunks

    def __iter__(self):
        for c in self.chunks:
            boom(self.where)
            yield c
        boom(self.where)


class FakeProcess:
    """Like a remote sh running a script: it ends once its input ends, or once delivering input failed."""

    def __init__(self):
        self.ended_input = threading.Event()

        def stdin_call(where, ends=False):
            def call(*args):
                try:
                    boom(where)
                except BaseException:
                    self.ended_input.set()
                    raise
                if ends:
                    self.ended_input.set()
            return call
        self.stdin = types.SimpleNamespace(write=stdin_call("stdin_write"), drain=stdin_call("drain"),
                                           write_eof=stdin_call("write_eof", ends=True))
        self.stdout = FakeStream("stdout", [b"probe output\n"])
        self.stderr = FakeStream("stderr", [b"probe note\n"])

    def wait(self):
        self.ended_input.wait(10)
        boom("wait")
        return 0


class FakeSandbox:
    def __init__(self, object_id, app_id, tags):
        self.object_id, self.app_id, self.tags, self.done = object_id, app_id, dict(tags or {}), False

    @staticmethod
    def create(*args, app=None, tags=None, **kw):
        if world.fail_create:
            raise world.fail_create
        sb = FakeSandbox("sb-new%d" % len(world.sandboxes), app.app_id, tags)
        world.sandboxes.append(sb)
        world.calls.append(("create", sb.object_id))
        return sb

    @staticmethod
    def from_id(sandbox_id):
        world.calls.append(("from_id", sandbox_id))  # recorded, so a broad except can't hide it
        raise AssertionError("resolved a sandbox by ID alone: " + sandbox_id)

    @staticmethod
    def list(app_id=None, tags=None):
        boom("list")
        if any(sb.done for sb in world.sandboxes):
            boom("list_after_terminate")
        for sb in world.sandboxes:
            if not sb.done and sb.app_id == app_id and all(sb.tags.get(k) == v for k, v in (tags or {}).items()):
                yield sb

    def exec(self, *argv, **kw):
        world.calls.append(("exec", self.object_id))
        proc = FakeProcess()
        if world.shape:
            world.shape(proc)
            return proc
        if "warn" in world.fail:
            warnings.warn(SENTINEL + " in a warning")
        if "log" in world.fail:
            logging.getLogger("modal-client").error(SENTINEL + " in a log line")
        if "unraisable" in world.fail:
            Unraisable()
        if "thread" in world.fail:  # a thread of the SDK's own, which no pump guards
            t = threading.Thread(target=lambda: boom("thread"))
            t.start()
            t.join()
        return proc

    def terminate(self):
        world.calls.append(("terminate", self.object_id))
        boom("terminate")
        if world.terminate_confirms:
            self.done = True

    def poll(self):
        boom("poll")
        return 0 if self.done else None


class Unraisable:
    def __del__(self):
        raise RuntimeError(SENTINEL + " in __del__")


fake = types.ModuleType("modal")
fake.App, fake.Sandbox = FakeApp, FakeSandbox
fake.Image = types.SimpleNamespace(from_registry=lambda base: types.SimpleNamespace(run_commands=lambda *a: None))
sys.modules["modal"] = fake  # before bridge.py loads: its `import modal` is this, never the SDK

here = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location("bridge", os.path.join(here, "bridge.py"))
bridge = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bridge)
assert bridge.modal is fake
bridge._sleep = lambda seconds: None


class Err(io.StringIO):
    """stderr as text, with the byte buffer sh pumps the sandbox's stderr into."""

    def __init__(self):
        super().__init__()
        self.buffer = io.BytesIO()


def exit_code(fn, *args):
    try:
        fn(*args)
    except SystemExit as e:
        return e.code
    return 0


class Bridge(unittest.TestCase):
    def setUp(self):
        global world
        world.__init__()
        self.dir = tempfile.mkdtemp()
        self.state = os.path.join(self.dir, "r0.state")
        self.stderr, sys.stderr = sys.stderr, Err()

    def tearDown(self):
        sys.stderr = self.stderr

    def made(self):
        self.assertEqual(exit_code(bridge.create, "round-0", self.state), 0)
        with open(self.state) as f:
            return json.load(f)

    def rewrite(self, rec):
        os.chmod(self.state, 0o600)
        with open(self.state, "w") as f:
            json.dump(rec, f)

    def touched(self):
        return [c for c in world.calls if c[0] in ("exec", "terminate", "from_id")]

    def test_create_sh_rm(self):
        rec = self.made()
        self.assertEqual(stat.S_IMODE(os.stat(self.state).st_mode), 0o600)
        self.assertEqual(set(rec), {"id", "setup", "tag", "created"})
        self.assertEqual(world.sandboxes[0].tags, {bridge.TAG_KEY: rec["tag"]})  # tagged in the create request
        saved = [os.dup(fd) for fd in (0, 1, 2)]  # sh pumps fds 0, 1 and 2 themselves: point them away from the runner
        null, sink = os.open(os.devnull, os.O_RDONLY), tempfile.TemporaryFile()
        try:
            os.dup2(null, 0)
            os.dup2(sink.fileno(), 1)
            os.dup2(sink.fileno(), 2)
            self.assertEqual(exit_code(bridge.sh, self.state), 0)
        finally:
            for fd, old in zip((0, 1, 2), saved):
                os.dup2(old, fd)
                os.close(old)
            os.close(null)
        sink.seek(0)
        self.assertIn(b"probe output", sink.read())
        self.assertEqual(exit_code(bridge.rm, self.state), 0)
        self.assertFalse(os.path.exists(self.state))
        self.assertEqual(self.touched(), [("exec", rec["id"]), ("terminate", rec["id"])])

    def refuses(self, rec_change=None, world_change=None):
        rec = self.made()
        world.calls.clear()
        if rec_change:
            rec_change(rec)
            self.rewrite(rec)
        if world_change:
            world_change(rec)
        for verb in (bridge.sh, bridge.rm):
            self.assertEqual(exit_code(verb, self.state), 2, sys.stderr.getvalue())
        self.assertEqual(self.touched(), [], "a refusal touched a sandbox")

    def test_id_substituted(self):
        other = FakeSandbox("sb-someoneelse", "ap-other", {})
        world.sandboxes.append(other)
        self.refuses(rec_change=lambda rec: rec.update(id="sb-someoneelse"))

    def test_tag_mismatch(self):
        self.refuses(rec_change=lambda rec: rec.update(tag="0" * 24))

    def test_other_app(self):
        def move(rec):
            world.sandboxes[0].app_id = "ap-another"
        self.refuses(world_change=move)

    def test_ambiguous(self):
        self.refuses(world_change=lambda rec: world.sandboxes.append(
            FakeSandbox("sb-twin", world.apps[bridge.APP], {bridge.TAG_KEY: rec["tag"]})))

    def test_ended(self):
        def end(rec):
            world.sandboxes[0].done = True
        self.refuses(world_change=end)
        self.assertIn("may have ended at its timeout", sys.stderr.getvalue())
        self.assertTrue(os.path.exists(self.state))

    def test_state_forms(self):
        for bad in ({"id": "x"}, {"extra": "1"}):
            with self.subTest(bad=bad):
                self.setUp()
                self.refuses(rec_change=lambda rec: rec.update(bad))
        self.setUp()
        rec = self.made()
        with open(self.state, "w") as f:  # a repeated field, as JSON allows
            f.write('{"id": "%s", "id": "%s", "setup": "round-0", "tag": "%s", "created": "%s"}'
                    % (rec["id"], rec["id"], rec["tag"], rec["created"]))
        os.chmod(self.state, 0o600)
        world.calls.clear()
        self.assertEqual(exit_code(bridge.sh, self.state), 2)
        self.assertEqual(self.touched(), [])

    def test_state_file_kinds(self):
        rec = self.made()
        world.calls.clear()
        link = os.path.join(self.dir, "link.state")
        os.symlink(self.state, link)
        os.chmod(self.state, 0o640)
        loose = self.state
        fifo = os.path.join(self.dir, "fifo.state")
        os.mkfifo(fifo, 0o600)
        hard = os.path.join(self.dir, "hard.state")
        for path in (link, loose, fifo, self.dir):
            for verb in (bridge.sh, bridge.rm):
                self.assertEqual(exit_code(verb, path), 2, path)
        os.chmod(self.state, 0o600)
        os.link(self.state, hard)
        for verb in (bridge.sh, bridge.rm):
            self.assertEqual(exit_code(verb, hard), 2)
        self.assertEqual(self.touched(), [])

    def test_state_path_in_the_way(self):
        open(self.state, "w").close()
        self.assertEqual(exit_code(bridge.create, "round-0", self.state), 2)
        self.assertEqual(world.calls, [], "created a sandbox with its state path in the way")

    def test_failure_after_create_terminates(self):
        real = bridge.owned
        bridge.owned = lambda rec: (_ for _ in ()).throw(KeyboardInterrupt())
        try:
            self.assertEqual(exit_code(bridge.create, "round-0", self.state), 1)
        finally:
            bridge.owned = real
        self.assertEqual(world.calls, [("create", "sb-new0"), ("terminate", "sb-new0")])
        self.assertFalse(os.path.exists(self.state))

    def test_state_write_fails_terminates(self):
        real = bridge.os.fsync
        calls = {"n": 0}

        def failing(fd):
            calls["n"] += 1
            raise OSError("disk full")
        bridge.os.fsync = failing
        try:
            self.assertEqual(exit_code(bridge.create, "round-0", self.state), 1)
        finally:
            bridge.os.fsync = real
        self.assertEqual(world.calls, [("create", "sb-new0"), ("terminate", "sb-new0")])
        self.assertFalse(os.path.exists(self.state))

    def test_unconfirmed_termination_exits_7(self):
        world.terminate_confirms = False
        real = bridge.owned
        bridge.owned = lambda rec: (_ for _ in ()).throw(RuntimeError("listing failed"))
        try:
            self.assertEqual(exit_code(bridge.create, "round-0", self.state), 7)
        finally:
            bridge.owned = real
        self.assertIn("sb-new0", sys.stderr.getvalue())
        self.assertNotIn("listing failed", sys.stderr.getvalue())  # an error's type, never its text

    def test_create_fails_before_returning(self):
        world.fail_create = RuntimeError("secret detail")
        self.assertEqual(exit_code(bridge.create, "round-0", self.state), 1)
        self.assertFalse(os.path.exists(self.state))
        self.assertNotIn("secret detail", sys.stderr.getvalue())


def late(seconds, where):
    """A call that waits, then fails with SDK text."""
    def call(*args):
        time.sleep(seconds)
        raise RuntimeError(SENTINEL + " late at " + where)
    return call


def shapes():
    """The looped scenarios: name -> (how the parent gives stdin, the exit code FIX-10 documents, the fake's shape)."""
    def remote_exits_now(code=0):
        def shape(proc):
            proc.wait = lambda: code
        return shape

    def eof_late(proc):  # security review's reproduction: wait returns at once, write_eof fails after it
        began = threading.Event()
        fail = late(0.3, "write_eof")
        proc.stdin.write_eof = lambda: (began.set(), fail())
        proc.wait = lambda: (began.wait(5), 0)[1]

    def drain_late(proc):
        began = threading.Event()
        fail = late(0.3, "drain")
        proc.stdin.drain = lambda: (began.set(), fail())
        proc.wait = lambda: (began.wait(5), 0)[1]

    def write_late_running(proc):  # the write fails while the remote still runs
        proc.stdin.write = late(0.2, "write")
        proc.wait = lambda: (time.sleep(0.8), 0)[1]

    def write_fails_mid_pump(proc):
        n = {"writes": 0}

        def write(b):
            n["writes"] += 1
            if n["writes"] > 3:
                raise RuntimeError(SENTINEL + " mid-pump")
        proc.stdin.write = write
        proc.wait = lambda: (time.sleep(0.8), 0)[1]

    def exit_then_input(proc):  # the remote ends first; input that comes later is never sent, so its code stands
        done = threading.Event()

        def write(b):
            if done.is_set():
                raise RuntimeError(SENTINEL + " write after exit")
        proc.stdin.write = write
        proc.wait = lambda: (done.set(), 3)[1]

    def big_file(proc):  # still pumping a large file when the remote ends
        proc.stdin.write = lambda b: time.sleep(0.001)
        proc.wait = lambda: (time.sleep(0.2), 0)[1]

    def stdout_late(proc):  # stdout fails after the remote ended
        ended = threading.Event()

        def out():
            yield b"probe output\n"
            ended.wait(5)
            time.sleep(0.1)
            raise RuntimeError(SENTINEL + " stdout after wait")
        proc.stdout = out()
        proc.wait = lambda: (ended.set(), 0)[1]

    def stdout_hangs(proc):  # a pump that never ends: the join's bound, then exit 1
        proc.stdout = iter(lambda: time.sleep(3600), b"never")
        proc.wait = lambda: 0

    return {
        "exit_open_stdin": ("open", 0, remote_exits_now()),
        "exit_code_passes": ("open", 3, remote_exits_now(3)),
        "stdin_closed": ("closed", 0, None),
        "stdin_devnull": ("devnull", 0, None),
        "big_file": ("file", 0, big_file),
        "write_fails_mid_pump": ("file", 1, write_fails_mid_pump),
        "eof_late": ("devnull", 1, eof_late),
        "drain_late": ("data", 1, drain_late),
        "write_late_running": ("data", 1, write_late_running),
        "exit_then_input": ("late_data", 3, exit_then_input),
        "stdout_late": ("devnull", 1, stdout_late),
        "stdout_hangs": ("devnull", 1, stdout_hangs),
    }


def child(verb, fails):
    """One child process: create through the fake, then fail at fails (or take a looped shape) and run verb."""
    state = os.path.join(tempfile.mkdtemp(), "s.state")
    shape = None
    if fails and fails[0].startswith("shape:"):
        name = fails[0][len("shape:"):]
        how, _, shape = shapes()[name]
        if how == "closed":
            os.close(0)
        if name == "stdout_hangs":
            bridge.OUTPUT_JOIN = 1.0
        fails = []
    if "thread" in fails:
        world.fail.add("thread")
    try:
        bridge.create("round-0", state)
    except SystemExit as e:
        if e.code:
            raise
    world.fail |= set(fails)
    world.shape = shape
    bridge.main(["bridge.py", verb, state])


LOOPS = int(os.environ.get("BRIDGE_LOOPS", "50"))  # each looped scenario's runs, to catch a race


class Sanitized(unittest.TestCase):
    """FIX-10, AGENTS rule 3: whatever the SDK raises, warns or logs, only fixed text and a type reach the terminal,
    under python -X dev, with the documented exit code."""

    def run_child(self, verb, *fails, stdin_mode="data"):
        args = [sys.executable, "-I", "-B", "-X", "dev", os.path.abspath(__file__), "--child", verb, *fails]
        keep = None
        if stdin_mode in ("open", "late_data"):
            r, w = os.pipe()
            proc = subprocess.Popen(args, stdin=r, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            os.close(r)
            keep = w
            if stdin_mode == "late_data":
                threading.Timer(0.5, lambda: (os.write(w, b"echo later\n"))).start()
            try:
                out, err = proc.communicate(timeout=60)
            finally:
                os.close(keep)
            code = proc.returncode
        else:
            stdin = {"data": subprocess.PIPE, "devnull": subprocess.DEVNULL, "closed": subprocess.DEVNULL}.get(stdin_mode)
            if stdin_mode == "file":
                f = tempfile.TemporaryFile()
                f.write(b"x" * (8 << 20))
                f.seek(0)
                stdin = f
            p = subprocess.run(args, input=b"echo hi\n" if stdin == subprocess.PIPE else None,
                               stdin=None if stdin == subprocess.PIPE else stdin, capture_output=True, timeout=60)
            out, err, code = p.stdout, p.stderr, p.returncode
        text = out.decode(errors="replace") + err.decode(errors="replace")
        self.assertNotIn(SENTINEL, text, f"{verb} {fails}: SDK text reached the terminal:\n{text}")
        self.assertNotIn("Traceback", text, f"{verb} {fails}: a traceback:\n{text}")
        self.assertNotIn("Fatal Python error", text, f"{verb} {fails}: a runtime diagnostic:\n{text}")
        return code, text

    def loop(self, n, verb, fails, want, stdin_mode="data"):
        from concurrent.futures import ThreadPoolExecutor
        with ThreadPoolExecutor(8) as pool:
            results = list(pool.map(lambda _: self.run_child(verb, *fails, stdin_mode=stdin_mode), range(n)))
        codes = [c for c, _ in results]
        bad = [c for c in codes if c != want]
        self.assertEqual(bad, [], f"{verb} {fails}: {len(bad)} of {n} runs exited otherwise than {want}: {sorted(set(codes))}")

    def test_sh_failures(self):
        for fail in ("stdout", "stderr", "stdin_write", "drain", "write_eof", "wait"):
            with self.subTest(fail=fail):
                self.loop(LOOPS, "sh", (fail,), 1)
                code, out = self.run_child("sh", fail)
                self.assertIn("RuntimeError", out)

    def test_lifecycle(self):
        for name, (how, want, _) in shapes().items():
            with self.subTest(scenario=name):
                self.loop(LOOPS, "sh", ("shape:" + name,), want, stdin_mode=how)

    def test_sh_list_failure_refuses(self):
        code, out = self.run_child("sh", "list")
        self.assertEqual(code, 2, out)

    def test_rm_failures(self):
        for fails, want in ((("list",), 2), (("terminate",), 7), (("poll",), 7), (("list_after_terminate",), 7)):
            with self.subTest(fails=fails):
                code, out = self.run_child("rm", *fails)
                self.assertEqual(code, want, out)

    def test_noise_the_sdk_makes(self):
        for fail, line in (("warn", "bridge: warning (UserWarning)"), ("log", None),
                           ("unraisable", "bridge: an error was ignored (RuntimeError)"),
                           ("thread", "bridge: a worker failed (RuntimeError)")):
            with self.subTest(fail=fail):
                code, out = self.run_child("sh", fail)
                self.assertEqual(code, 0, out)
                if line:
                    self.assertIn(line, out)

    def test_success_still_passes_output(self):
        code, out = self.run_child("sh")
        self.assertEqual(code, 0, out)
        self.assertIn("probe output", out)
        self.assertIn("probe note", out)


if __name__ == "__main__":
    if len(sys.argv) > 2 and sys.argv[1] == "--child":
        child(sys.argv[2], sys.argv[3:])
    unittest.main(verbosity=1)
