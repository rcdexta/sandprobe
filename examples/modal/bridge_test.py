"""FIX-10: bridge.py against a fake modal module. No network, no Modal account: the real SDK is never imported.

Run with: python3 -I -B examples/modal/bridge_test.py (cmd/sandprobe's TestModalBridge does).
"""
import importlib.util
import io
import json
import os
import stat
import sys
import tempfile
import types
import unittest


class FakeWorld:
    def __init__(self):
        self.apps = {}  # name -> app_id
        self.sandboxes = []  # live FakeSandbox
        self.calls = []  # ("exec"|"terminate"|"create", sandbox id)
        self.fail_create = None  # an exception create raises before returning
        self.terminate_confirms = True


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


class FakeProcess:
    def __init__(self):
        self.stdin = types.SimpleNamespace(write=lambda b: None, drain=lambda: None, write_eof=lambda: None)
        self.stdout = [b"probe output\n"]
        self.stderr = []

    def wait(self):
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
        for sb in world.sandboxes:
            if not sb.done and sb.app_id == app_id and all(sb.tags.get(k) == v for k, v in (tags or {}).items()):
                yield sb

    def exec(self, *argv, **kw):
        world.calls.append(("exec", self.object_id))
        return FakeProcess()

    def terminate(self):
        world.calls.append(("terminate", self.object_id))
        if world.terminate_confirms:
            self.done = True

    def poll(self):
        return 0 if self.done else None


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
        out, sys.stdout = sys.stdout, types.SimpleNamespace(buffer=io.BytesIO())
        sys.stdin, stdin = types.SimpleNamespace(buffer=io.BufferedReader(io.BytesIO(b"echo hi\n"))), sys.stdin
        try:
            self.assertEqual(exit_code(bridge.sh, self.state), 0)
        finally:
            sys.stdout, sys.stdin = out, stdin
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


if __name__ == "__main__":
    unittest.main(verbosity=1)
