package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"sandprobe/internal/analysis"
	"sandprobe/internal/fix"
	"sandprobe/internal/report"
)

// fixSetup is one run docker invocation: the image, -as, and the docker run options after --.
type fixSetup struct {
	image, as string
	opts      []string
}

// fixRound is what one run gave: its report, its score card, its red checks and fix's plan for it.
type fixRound struct {
	card report.Card
	red  map[string]bool // found above Info, or unknown (SCR-2)
	plan fix.Plan
}

// With Docker (SANDPROBE_FIXTURES=1): FIX-9. Each Docker action alone, from a baseline where its checks are red,
// clears every check the table claims for Docker and greens every category it says it could; then the loop, top
// action first, to the end. Every container, canary and network goes with its run's own teardown, by ID; the test
// removes only the image tags it built.
func TestFixLoopDocker(t *testing.T) {
	if os.Getenv("SANDPROBE_FIXTURES") == "" {
		t.Skip("needs Docker: set SANDPROBE_FIXTURES=1")
	}
	bin := filepath.Join(t.TempDir(), "sandprobe")
	if b, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("%v\n%s", err, b)
	}
	// A weak box like the demo's: an agent user with a writable home, a secret-shaped ENV, root by default, the default
	// network. Its variants: no ENV (clean-env's image change), a long-running process of its own (--entrypoint), and a
	// credential in the agent's own home beside root's /etc/shadow (FIX-3's side-effect case).
	build := func(dockerfile string, files map[string]string) string {
		dir := t.TempDir()
		for name, body := range files {
			if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o755); err != nil {
				t.Fatal(err)
			}
		}
		if err := os.WriteFile(filepath.Join(dir, "Dockerfile"), []byte(dockerfile), 0o644); err != nil {
			t.Fatal(err)
		}
		return testImage(t, dir)
	}
	const base = "FROM debian:trixie-slim\nRUN useradd -m -u 1000 -s /bin/bash agent\n"
	weak := build(base+"ENV ANTHROPIC_API_KEY=sandprobe-fake\nWORKDIR /home/agent\n", nil)
	clean := build(base+"WORKDIR /home/agent\n", nil)
	idle := map[string]string{"agent-idle": "#!/bin/sh\nexec sleep infinity\n"}
	weakIdle := build("FROM "+weak+"\nCOPY agent-idle /usr/local/bin/agent-idle\n", idle)
	cleanIdle := build("FROM "+clean+"\nCOPY agent-idle /usr/local/bin/agent-idle\n", idle)
	weakCred := build("FROM "+weak+"\nRUN printf 'OPENAI_API_KEY=sandprobe-fake\\n' > /home/agent/.env && chown agent:agent /home/agent/.env && chmod 0600 /home/agent/.env\n", nil)
	cleaned := map[string]string{weak: clean, weakIdle: cleanIdle}

	runRound := func(s fixSetup) fixRound {
		t.Helper()
		out := t.TempDir()
		args := []string{"run", "docker", s.image, "-y", "-o", "json", "-out", out}
		if s.as != "" {
			args = append(args, "-as", s.as)
		}
		b, _ := exec.Command(bin, append(append(args, "--"), s.opts...)...).Output()
		var d struct {
			Grade   struct{ Valid bool }
			Cleanup struct{ Outcome string }
		}
		if json.Unmarshal(b, &d) != nil || !d.Grade.Valid || !strings.HasPrefix(d.Cleanup.Outcome, "deleted") {
			t.Fatalf("%+v: want a valid run with everything deleted: %.300s", s, b)
		}
		m, _ := filepath.Glob(filepath.Join(out, "*.json"))
		doc, err := analysis.Load(m[0])
		if err != nil {
			t.Fatal(err)
		}
		r := fixRound{card: report.Score(*doc), red: map[string]bool{}}
		for _, row := range r.card.Rows {
			for _, id := range append(append([]string{}, row.Found...), row.Unknown...) {
				r.red[id] = true
			}
		}
		cmd := exec.Command(bin, "fix", m[0], "-o", "json")
		pb, _ := cmd.Output()
		if json.Unmarshal(pb, &r.plan) != nil {
			t.Fatalf("fix: %s", pb)
		}
		// FIX-1: exit 5 exactly when the report is incomplete, with the plan still given.
		if want := map[bool]int{true: exitGraded, false: exitPartial}[r.plan.Complete]; cmd.ProcessState.ExitCode() != want || r.plan.Complete != doc.Grade.Complete {
			t.Fatalf("fix: exit %d, complete %v, report complete %v", cmd.ProcessState.ExitCode(), r.plan.Complete, doc.Grade.Complete)
		}
		return r
	}
	snippet := func(id string) fix.Snippet {
		for _, e := range fix.Table {
			if e.ID == id {
				return e.Proven["docker"]
			}
		}
		t.Fatalf("no entry %s", id)
		return fix.Snippet{}
	}
	apply := func(s fixSetup, a fix.Action) fixSetup {
		sn := snippet(a.ID)
		next := fixSetup{image: s.image, as: s.as, opts: slices.Clone(s.opts)}
		switch {
		case sn.Image:
			next.image = cleaned[s.image]
		default:
			next.opts = append(next.opts, sn.Options...)
		}
		if a.ID == "isolate-processes" { // the agent through docker exec -u, the container's own processes another user
			next.as = "agent"
		}
		return next
	}
	green := func(r fixRound, name string) bool {
		i := slices.IndexFunc(r.card.Rows, func(row report.Row) bool { return row.Name == name })
		return i >= 0 && r.card.Rows[i].Green
	}

	// Each action alone, from each baseline: every check it addressed was red and is no longer. A side effect is only
	// recorded when it cleared; it is never asserted, since it may not clear on another box (FIX-3).
	proved := map[string]bool{} // "action check" pairs a rerun showed red, then cleared
	for name, tc := range map[string]struct {
		s    fixSetup
		only string // the one action to apply from this baseline; every proven one when empty
	}{
		"root":                   {fixSetup{image: weak}, ""},
		"agent user":             {fixSetup{image: weak, opts: []string{"--user", "1000:1000"}}, "protect-home"},
		"root, CAP_SYS_PTRACE":   {fixSetup{image: weak, opts: []string{"--cap-add", "SYS_PTRACE"}}, "run-as-user"},
		"own process, agent uid": {fixSetup{image: weakIdle, opts: []string{"--user", "1000:1000", "--entrypoint", "/usr/local/bin/agent-idle"}}, "isolate-processes"},
	} {
		s := tc.s
		before := runRound(s)
		if tc.only != "" && !slices.ContainsFunc(before.plan.Actions, func(a fix.Action) bool { return a.ID == tc.only && a.Proven }) {
			t.Errorf("%s: %s isn't offered", name, tc.only)
		}
		for _, a := range before.plan.Actions {
			if !a.Proven || tc.only != "" && a.ID != tc.only {
				continue
			}
			after := runRound(apply(s, a))
			for _, id := range append(slices.Clone(a.Findings), a.Unknowns...) {
				if !before.red[id] || after.red[id] {
					t.Errorf("%s, %s: %s red before %v, after %v", name, a.ID, id, before.red[id], after.red[id])
				}
				proved[a.ID+" "+id] = true
			}
			for _, id := range a.MayAlsoClear {
				if before.red[id] && !after.red[id] {
					proved[a.ID+" "+id] = true
				}
			}
			for _, c := range a.CouldTurnGreen {
				if !green(after, c) {
					t.Errorf("%s, %s: %s isn't green after it", name, a.ID, c)
				}
			}
			if a.ID == "run-as-user" && name == "root, CAP_SYS_PTRACE" && len(a.Unknowns) == 0 {
				t.Errorf("%s: run-as-user took no TWN-4 unknown", name)
			}
		}
	}
	// The side effect that doesn't hold: on a root box with a credential in the agent's home, run-as-user closes
	// /etc/shadow but not the credential, and remove-credential-files stays offered before and after (FIX-3).
	before := runRound(fixSetup{image: weakCred})
	ru := slices.IndexFunc(before.plan.Actions, func(a fix.Action) bool { return a.ID == "run-as-user" })
	if ru < 0 || !slices.Contains(before.plan.Actions[ru].MayAlsoClear, "SEC-3") ||
		!slices.ContainsFunc(before.plan.Actions, func(a fix.Action) bool { return a.ID == "remove-credential-files" }) {
		t.Fatalf("credential in home: want run-as-user that may clear SEC-3 and remove-credential-files: %+v", before.plan.Actions)
	}
	after := runRound(apply(fixSetup{image: weakCred}, before.plan.Actions[ru]))
	if !after.red["SEC-3"] || !slices.ContainsFunc(after.plan.Actions, func(a fix.Action) bool { return a.ID == "remove-credential-files" }) {
		t.Errorf("credential in home: after run-as-user, SEC-3 red %v, actions %+v", after.red["SEC-3"], after.plan.Actions)
	}

	for _, e := range fix.Table {
		for _, id := range e.Proven["docker"].Proves {
			if !proved[e.ID+" "+id] {
				t.Errorf("%s: its Docker claim on %s was never shown red, then cleared", e.ID, id)
			}
		}
	}

	// The loop, top action first, until fix has nothing left (FIX-7), from the bare box and from one whose own process
	// runs.
	for name, s := range map[string]fixSetup{
		"bare":        {image: weak},
		"own process": {image: weakIdle, opts: []string{"--entrypoint", "/usr/local/bin/agent-idle"}},
	} {
		var scores []int
		var applied []string
		for round := 0; ; round++ {
			r := runRound(s)
			scores = append(scores, r.card.Score)
			if len(r.plan.Actions) == 0 {
				t.Logf("%s: scores by round %v, applying %v; last setup %+v", name, scores, applied, s)
				if r.card.Score != r.card.Of {
					t.Errorf("%s: the loop ended at %d/%d", name, r.card.Score, r.card.Of)
				}
				break
			}
			top := r.plan.Actions[0]
			if !top.Proven || round > 8 {
				t.Fatalf("%s: round %d stops at %s (proven %v); scores %v", name, round, top.ID, top.Proven, scores)
			}
			s, applied = apply(s, top), append(applied, top.ID)
		}
		for i := 1; i < len(scores); i++ {
			if scores[i] < scores[i-1] {
				t.Errorf("%s: the score fell, %v", name, scores)
			}
		}
	}
}
