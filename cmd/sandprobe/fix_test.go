package main

import (
	"bytes"
	"encoding/json"
	"os"
	osexec "os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"sandprobe/internal/analysis"
	"sandprobe/internal/fix"
	"sandprobe/internal/host"
	"sandprobe/internal/obs"
	"sandprobe/internal/report"
)

// FIX-1, FIX-4: flags, -platform only on a run exec report and only from the fixed list, and exit codes.
func TestFixCLI(t *testing.T) {
	const vibe = "../../demo/reports/vibe.json" // a run docker report
	exec := skipSaved(t, "exec", host.Options{Excluded: host.ExecExclusions(), ExcludedKind: obs.SkipOptIn})
	for _, tc := range []struct {
		args     []string
		exit     int
		contains string
	}{
		{[]string{"fix"}, exitUsage, "name one saved report file"},
		{[]string{"fix", vibe, vibe}, exitUsage, "name one saved report file"},
		{[]string{"fix", vibe, "-o", "yaml"}, exitUsage, "-o takes text or json"},
		{[]string{"fix", vibe, "-y"}, exitUsage, "flag provided but not defined"},
		{[]string{"fix", "/dev/null"}, exitUsage, "unsupported, inconsistent or unsafe report input"},
		{[]string{"fix", vibe, "-platform", "modal"}, exitUsage, "-platform applies only to a run exec report"},
		{[]string{"fix", exec, "-platform", "nowhere"}, exitUsage, "-platform takes one of"},
		{[]string{"fix", exec, "-platform", "exec"}, exitUsage, "-platform takes one of"},
		{[]string{"fix", vibe}, exitGraded, "Fixes for Docker"},
		{[]string{"fix", vibe, "-o", "json"}, exitGraded, `"schema": "sandprobe.fix/1"`},
		{[]string{"fix", exec}, exitGraded, "Fixes for an unknown platform"},
		{[]string{"fix", exec}, exitGraded, "Not an action for an agent:"},
		{[]string{"fix", exec, "-platform", "modal", "-o", "json"}, exitGraded, `"platform": "modal"`},
		{[]string{"fix", vibe, "-provider", "modal"}, exitUsage, "flag provided but not defined: -provider"},
		{[]string{"fix", "../../test/reports/canary-down.json"}, exitPartial, "This report is incomplete: "},
		{[]string{"fix", "../../test/reports/canary-down.json", "-o", "json"}, exitPartial, `"complete": false`},
	} {
		var out, errb bytes.Buffer
		code := run(tc.args, &out, &errb)
		if code != tc.exit || !strings.Contains(out.String()+errb.String(), tc.contains) {
			t.Errorf("%v: exit %d, want %d with %q:\n%s%s", tc.args, code, tc.exit, tc.contains, out.String(), errb.String())
		}
	}
}

// FIX-1, FIX-8, UX-9: the text says the report wasn't re-verified, fits 80 columns, and carries nothing the report
// holds, even from a report whose every string is hostile.
func TestFixTextIsFixedAndFits(t *testing.T) {
	b, err := os.ReadFile("../../demo/reports/vibe.json")
	if err != nil {
		t.Fatal(err)
	}
	var d report.Doc
	if err := json.Unmarshal(b, &d); err != nil {
		t.Fatal(err)
	}
	const payload = "PWNED\x1b[31m\u202e$(id)\nnext"
	d.Run.Box.Name, d.Lead, d.Statement = payload, payload, payload
	for i := range d.Checks {
		c := &d.Checks[i]
		c.Title, c.Gets, c.Fix = payload, payload, payload
		if c.Evidence != "" {
			c.Evidence = payload
		}
		if c.Reason != "" {
			c.Reason = payload
		}
	}
	for i := range d.Findings {
		d.Findings[i].Title, d.Findings[i].Gets, d.Findings[i].Fix = payload, payload, payload
	}
	hostile, _ := json.Marshal(d)
	path := filepath.Join(t.TempDir(), "hostile.json")
	if err := os.WriteFile(path, hostile, 0o644); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"fix", path}, {"fix", path, "-o", "json"}} {
		var out, errb bytes.Buffer
		if code := run(args, &out, &errb); code != exitGraded {
			t.Fatalf("%v: exit %d: %s", args, code, errb.String())
		}
		s := out.String()
		if strings.Contains(s, "PWNED") || strings.Contains(s, "\x1b") || strings.Contains(s, "$(id)") || strings.Contains(s, "\u202e") {
			t.Errorf("%v: a report string reached the output:\n%s", args, s)
		}
		if !strings.Contains(s, "From a saved report: structurally checked only") && !strings.Contains(s, `"verification": "structural_only_unauthenticated"`) {
			t.Errorf("%v: no ANL-1 note", args)
		}
		if args[len(args)-1] == "json" {
			continue
		}
		for _, l := range strings.Split(s, "\n") {
			if w := displayWidth(l); w > 80 {
				t.Errorf("%d columns: %q", w, l)
			}
		}
		for _, want := range []string{"remove-credential-files", fix.GeneralAdvice, "Next:"} {
			if !strings.Contains(s, want) {
				t.Errorf("no %q in:\n%s", want, s)
			}
		}
	}
}

// FIX-1: an invalid run, as an invalid run writes it, has nothing to fix, and exits 5.
func TestFixInvalidRun(t *testing.T) {
	b, err := os.ReadFile("../../test/reports/egress-refused.json")
	if err != nil {
		t.Fatal(err)
	}
	var d report.Doc
	if err := json.Unmarshal(b, &d); err != nil {
		t.Fatal(err)
	}
	d.Grade = report.Grade{Invalid: "the probe's digest didn't match", Unknown: []string{},
		Counts: map[string]int{"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}}
	d.Findings = []report.Finding{}
	d.Checks = slices.DeleteFunc(d.Checks, func(c report.Check) bool { return c.Result != obs.Skipped })
	invalid, _ := json.Marshal(d)
	path := filepath.Join(t.TempDir(), "invalid.json")
	if err := os.WriteFile(path, invalid, 0o644); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	if code := run([]string{"fix", path}, &out, &errb); code != exitPartial {
		t.Fatalf("exit %d, want %d: %s", code, exitPartial, errb.String())
	}
	if s := out.String(); !strings.Contains(s, "Score: none (invalid run)") || strings.Contains(s, "Next:") || strings.Contains(s, "1. ") {
		t.Errorf("invalid run text:\n%s", s)
	}
}

// FIX-8: a report's provider names a platform only by matching the fixed list.
func TestFixHostileProvider(t *testing.T) {
	b, err := os.ReadFile("../../demo/reports/vibe.json")
	if err != nil {
		t.Fatal(err)
	}
	var d report.Doc
	if err := json.Unmarshal(b, &d); err != nil {
		t.Fatal(err)
	}
	d.Run.Provider = "docker\x1b[31mPWNED\u202e"
	hostile, _ := json.Marshal(d)
	path := filepath.Join(t.TempDir(), "hostile.json")
	if err := os.WriteFile(path, hostile, 0o644); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"fix", path}, {"fix", path, "-o", "json"}} {
		var out, errb bytes.Buffer
		if code := run(args, &out, &errb); code != exitGraded {
			t.Fatalf("%v: exit %d: %s", args, code, errb.String())
		}
		if s := out.String(); strings.Contains(s, "PWNED") || strings.Contains(s, "proven on Docker") || strings.Contains(s, `"platform": "docker"`) {
			t.Errorf("%v: the report's provider string reached the output:\n%s", args, s)
		}
	}
}

// FIX-1: an incomplete report keeps its plan, says so in text and JSON, names its unknowns, and exits 5.
func TestFixIncomplete(t *testing.T) {
	const down = "../../test/reports/canary-down.json" // valid, incomplete: the canary was down
	d, err := analysis.Load(down)
	if err != nil || !d.Grade.Valid || d.Grade.Complete || len(d.Grade.Unknown) == 0 {
		t.Fatalf("%s isn't a valid, incomplete report: %v", down, err)
	}
	var out, errb bytes.Buffer
	if code := run([]string{"fix", down, "-o", "json"}, &out, &errb); code != exitPartial {
		t.Fatalf("exit %d, want %d", code, exitPartial)
	}
	var p fix.Plan
	if err := json.Unmarshal(out.Bytes(), &p); err != nil {
		t.Fatal(err)
	}
	if !p.Valid || p.Complete || !slices.Equal(p.Unknown, d.Grade.Unknown) || len(p.Actions) == 0 || p.Loop == nil {
		t.Errorf("plan: valid %v complete %v unknown %v, %d actions", p.Valid, p.Complete, p.Unknown, len(p.Actions))
	}
	out.Reset()
	run([]string{"fix", down}, &out, &errb)
	if want := fix.IncompleteLine(len(d.Grade.Unknown)); !strings.HasPrefix(out.String(), want+"\n") || !strings.Contains(out.String(), "1. ") {
		t.Errorf("text doesn't open with %q, or has no plan:\n%s", want, out.String())
	}
	// A complete report says nothing of the kind, and exits 0.
	out.Reset()
	if code := run([]string{"fix", "../../demo/reports/vibe.json"}, &out, &errb); code != exitGraded || strings.Contains(out.String(), "incomplete") {
		t.Errorf("a complete report: exit %d:\n%s", code, out.String())
	}
}

// FIX-10: examples/modal/bridge.py's guards, against a fake modal module (examples/modal/bridge_test.py). It runs
// isolated (-I), with no Modal token in its environment or home, so the real SDK can never be reached.
func TestModalBridge(t *testing.T) {
	py, err := osexec.LookPath("python3")
	if err != nil {
		t.Skip("no python3 on PATH")
	}
	cmd := osexec.Command(py, "-I", "-B", "../../examples/modal/bridge_test.py")
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, "MODAL_") && !strings.HasPrefix(kv, "HOME=") {
			cmd.Env = append(cmd.Env, kv)
		}
	}
	cmd.Env = append(cmd.Env, "HOME="+t.TempDir())
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
}
