//go:build darwin || linux

package main

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// TestPTYHelperProcess runs inside a real child PTY when spawned by TestPTYKeyLoopIdleEOFSignalsAndOptOut.
func TestPTYHelperProcess(t *testing.T) {
	if os.Getenv("SANDPROBE_PTY_HELPER") != "1" {
		return
	}
	vibe := loadReportJSON(t, "../../demo/reports/vibe.json")
	code, err := finish(
		opts{out: "text", stdout: os.Stdout},
		runFlags{outDir: os.Getenv("SANDPROBE_PTY_OUTDIR"), theme: "graphite", min: os.Getenv("SANDPROBE_PTY_MIN")},
		vibe,
		true,
	)
	if err != nil {
		os.Exit(99)
	}
	os.Exit(code)
}

type ptyCollector struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (c *ptyCollector) start(r *os.File) {
	go func() {
		tmp := make([]byte, 1024)
		for {
			n, err := r.Read(tmp)
			if n > 0 {
				c.mu.Lock()
				c.buf.Write(tmp[:n])
				c.mu.Unlock()
			}
			if err != nil {
				return
			}
		}
	}()
}

func (c *ptyCollector) String() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.buf.String()
}

func waitForSubstring(t *testing.T, col *ptyCollector, sub string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if strings.Contains(col.String(), sub) {
			return
		}
		time.Sleep(15 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %q in PTY output:\n%s", sub, col.String())
}

// UX-7, AGT-1: exercises finish() + interactResult() over a real OS PTY across silent open stdin,
// q, EOF, SIGTERM, SIGHUP, CI=true, and SANDPROBE_NO_KEYS=1, verifying bounded completion and cooked termios restoration.
func TestPTYKeyLoopIdleEOFSignalsAndOptOut(t *testing.T) {
	spawn := func(t *testing.T, extraEnv ...string) (*exec.Cmd, *os.File, *os.File, *ptyCollector) {
		t.Helper()
		master, slave, err := openPTY()
		if err != nil {
			t.Fatalf("openPTY: %v", err)
		}
		t.Cleanup(func() {
			_ = master.Close()
			_ = slave.Close()
		})
		cmd := exec.Command(os.Args[0], "-test.run=^TestPTYHelperProcess$")
		cmd.Stdin = slave
		cmd.Stdout = slave
		cmd.Stderr = slave
		cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
		env := []string{
			"PATH=" + os.Getenv("PATH"),
			"HOME=" + t.TempDir(),
			"TERM=xterm-256color",
			"NO_COLOR=1",
			"CI=",
			"SANDPROBE_NO_KEYS=",
			"SANDPROBE_PTY_HELPER=1",
			"SANDPROBE_PTY_OUTDIR=" + t.TempDir(),
		}
		cmd.Env = append(env, extraEnv...)
		col := &ptyCollector{}
		col.start(master)
		if err := cmd.Start(); err != nil {
			t.Fatalf("start helper: %v", err)
		}
		return cmd, master, slave, col
	}

	waitExit := func(t *testing.T, cmd *exec.Cmd, timeout time.Duration) int {
		t.Helper()
		done := make(chan error, 1)
		go func() { done <- cmd.Wait() }()
		select {
		case err := <-done:
			if err == nil {
				return 0
			}
			var ee *exec.ExitError
			if errors.As(err, &ee) {
				return ee.ExitCode()
			}
			t.Fatalf("unexpected wait error: %v", err)
			return -1
		case <-time.After(timeout):
			_ = cmd.Process.Kill()
			t.Fatalf("child hung on PTY beyond %s", timeout)
			return -1
		}
	}

	t.Run("silent open stdin auto-exits with OUT-4 exit code and restores termios", func(t *testing.T) {
		cmd, _, slave, col := spawn(t, "SANDPROBE_KEY_IDLE_MS=180", "SANDPROBE_PTY_MIN=5")
		code := waitExit(t, cmd, 4*time.Second)
		if code != exitBelowMin {
			t.Fatalf("exit code = %d, want %d; output:\n%s", code, exitBelowMin, col.String())
		}
		if !strings.Contains(col.String(), "Idle timeout; exiting.") {
			t.Fatalf("missing idle timeout notice:\n%s", col.String())
		}
		if cooked, err := isCookedTTY(int(slave.Fd())); err != nil || !cooked {
			t.Fatalf("PTY left in raw mode after idle exit (cooked=%v err=%v)", cooked, err)
		}
	})

	t.Run("q exits and restores termios", func(t *testing.T) {
		cmd, master, slave, col := spawn(t, "SANDPROBE_KEY_IDLE_MS=8000")
		waitForSubstring(t, col, "[q] quit", 4*time.Second)
		if cooked, err := isCookedTTY(int(slave.Fd())); err != nil || cooked {
			t.Fatalf("expected raw mode while key bar active (cooked=%v err=%v)", cooked, err)
		}
		_, _ = master.Write([]byte("q"))
		if code := waitExit(t, cmd, 3*time.Second); code != exitGraded {
			t.Fatalf("exit code = %d, want 0", code)
		}
		if cooked, err := isCookedTTY(int(slave.Fd())); err != nil || !cooked {
			t.Fatalf("PTY left in raw mode after q (cooked=%v err=%v)", cooked, err)
		}
	})

	t.Run("Ctrl-D EOF key exits and restores termios", func(t *testing.T) {
		cmd, master, slave, col := spawn(t, "SANDPROBE_KEY_IDLE_MS=8000")
		waitForSubstring(t, col, "[q] quit", 4*time.Second)
		_, _ = master.Write([]byte{0x04})
		if code := waitExit(t, cmd, 3*time.Second); code != exitGraded {
			t.Fatalf("exit code = %d, want 0", code)
		}
		if cooked, err := isCookedTTY(int(slave.Fd())); err != nil || !cooked {
			t.Fatalf("PTY left in raw mode after Ctrl-D (cooked=%v err=%v)", cooked, err)
		}
	})

	t.Run("EOF on master close exits and restores termios", func(t *testing.T) {
		cmd, master, slave, col := spawn(t, "SANDPROBE_KEY_IDLE_MS=8000")
		waitForSubstring(t, col, "[q] quit", 4*time.Second)
		_ = master.Close()
		if code := waitExit(t, cmd, 3*time.Second); code != exitGraded {
			t.Fatalf("exit code = %d, want 0", code)
		}
		if cooked, err := isCookedTTY(int(slave.Fd())); err != nil || !cooked {
			t.Fatalf("PTY left in raw mode after master EOF (cooked=%v err=%v)", cooked, err)
		}
	})

	for _, sigCase := range []struct {
		name string
		sig  syscall.Signal
	}{
		{"SIGTERM", syscall.SIGTERM},
		{"SIGHUP", syscall.SIGHUP},
	} {
		t.Run(sigCase.name+" restores termios", func(t *testing.T) {
			cmd, _, slave, col := spawn(t, "SANDPROBE_KEY_IDLE_MS=10000")
			waitForSubstring(t, col, "[q] quit", 4*time.Second)
			if cooked, err := isCookedTTY(int(slave.Fd())); err != nil || cooked {
				t.Fatalf("expected raw mode before %s (cooked=%v err=%v)", sigCase.name, cooked, err)
			}
			if err := cmd.Process.Signal(sigCase.sig); err != nil {
				t.Fatalf("signal %s: %v", sigCase.name, err)
			}
			_ = waitExit(t, cmd, 3*time.Second)
			if cooked, err := isCookedTTY(int(slave.Fd())); err != nil || !cooked {
				t.Fatalf("PTY left in raw mode after %s (cooked=%v err=%v)", sigCase.name, cooked, err)
			}
		})
	}

	for _, envOpt := range []string{"CI=true", "SANDPROBE_NO_KEYS=1"} {
		t.Run(envOpt+" skips key loop immediately", func(t *testing.T) {
			start := time.Now()
			cmd, _, slave, col := spawn(t, "SANDPROBE_KEY_IDLE_MS=10000", envOpt)
			if code := waitExit(t, cmd, 3*time.Second); code != exitGraded {
				t.Fatalf("%s exit = %d, want 0", envOpt, code)
			}
			if elapsed := time.Since(start); elapsed > 2*time.Second {
				t.Fatalf("%s waited %s", envOpt, elapsed)
			}
			if strings.Contains(col.String(), "[Enter] walk") {
				t.Fatalf("%s entered interactive key bar:\n%s", envOpt, col.String())
			}
			if cooked, err := isCookedTTY(int(slave.Fd())); err != nil || !cooked {
				t.Fatalf("%s left PTY raw (cooked=%v err=%v)", envOpt, cooked, err)
			}
		})
	}
}
