package fix

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"sandprobe/internal/analysis"
	"sandprobe/internal/catalog"
	"sandprobe/internal/host"
	"sandprobe/internal/obs"
	"sandprobe/internal/report"
)

// FIX-3: every catalog check that can be red is the trigger of exactly one entry; every claim is a catalog check; an
// After names an entry; a Docker snippet is options FIX-9 applies, or an image change.
func TestTableCoversTheCatalog(t *testing.T) {
	triggers := map[string]int{}
	ids := map[string]bool{}
	for _, e := range Table {
		if ids[e.ID] || e.Title == "" || len(e.Triggers) == 0 {
			t.Errorf("%s: a duplicate, or no title or trigger", e.ID)
		}
		ids[e.ID] = true
		for _, id := range e.Triggers {
			triggers[id]++
		}
	}
	for _, c := range catalog.Checks {
		redCapable := false
		for _, v := range c.Variants {
			redCapable = redCapable || v.Severity > catalog.Info
		}
		if redCapable && triggers[c.ID] != 1 || !redCapable && triggers[c.ID] != 0 {
			t.Errorf("%s: triggers %d entries", c.ID, triggers[c.ID])
		}
	}
	for _, e := range Table {
		for platform, s := range e.Proven {
			if platform != "modal" && platform != "docker" {
				t.Errorf("%s: a snippet for %s, which no rerun proved", e.ID, platform)
			}
			if len(s.Apply) == 0 || s.Proof == "" || len(s.Proves) == 0 {
				t.Errorf("%s on %s: no apply, proof or proven checks", e.ID, platform)
			}
			for _, id := range s.Proves {
				if _, ok := catalog.Get(id); !ok {
					t.Errorf("%s on %s: %s isn't a catalog check", e.ID, platform, id)
				}
			}
			if _, ok := entry(s.After); s.After != "" && !ok {
				t.Errorf("%s on %s: after %q, no such entry", e.ID, platform, s.After)
			}
			if platform == "docker" && (len(s.Options) > 0) == s.Image {
				t.Errorf("%s on docker: options or an image change, exactly one", e.ID)
			}
			if platform == "docker" && len(s.Options) > 0 && !strings.Contains(strings.Join(s.Apply, " "), strings.Join(s.Options, " ")) {
				t.Errorf("%s on docker: the text doesn't give the options FIX-9 applies", e.ID)
			}
			for _, a := range s.Apply {
				if strings.Contains(a, "-e NAME") || strings.Contains(a, "--env NAME") {
					t.Errorf("%s: a bare -e passes the host's own value into the box (FIX-4)", e.ID)
				}
			}
		}
	}
	// FIX-4: on Modal, SEC-2 stayed found in every round and AMP-3 was never found.
	for _, e := range Table {
		if s, ok := e.Proven["modal"]; ok && (slices.Contains(s.Proves, "SEC-2") || slices.Contains(s.Proves, "AMP-3")) {
			t.Errorf("%s: a Modal snippet claims SEC-2 or AMP-3", e.ID)
		}
	}
}

// doc is a valid run exec report with these results, built in memory: SEC-4, EGR-3, AMP-6 and AMP-7 skipped as
// PRV-15's opt_in defaults, every other check passing unless named.
func doc(results map[string]string) report.Doc {
	d := report.Doc{Grade: report.Grade{Valid: true}, Run: report.Run{Provider: "exec"},
		Manifest: obs.Manifest{Skipped: map[string]string{}, SkipKinds: map[string]string{}}}
	excluded := host.ExecExclusions()
	for _, id := range catalog.IDs() {
		c := report.Check{ID: id, Result: obs.Pass}
		switch r := results[id]; {
		case excluded[id] != "":
			c.Result, c.Reason = obs.Skipped, excluded[id]
			d.Manifest.Skipped[id], d.Manifest.SkipKinds[id] = excluded[id], obs.SkipOptIn
		case r == "":
		case strings.HasPrefix(r, "unknown"):
			c.Result, c.Reason = obs.Unknown, strings.TrimPrefix(r, "unknown:")
			d.Grade.Unknown = append(d.Grade.Unknown, id)
		case r == obs.NotFound || r == obs.Absent || r == obs.ScopedOut || r == obs.Skipped:
			c.Result = r
		default:
			c.Result, c.Severity = obs.Finding, r
		}
		d.Checks = append(d.Checks, c)
	}
	return d
}

const twn4 = "unknown:nothing was found, but the agent holds CAP_SYS_PTRACE, which reaches past file permissions and mounts altogether, so no refusal, absence or empty listing shows anything (TWN-4)"

// The Modal rounds of 24 November 2026, as their reports read, built in memory (run data is never committed).
var (
	modalR0 = map[string]string{"SEC-1": "high", "SEC-2": "high", "SEC-3": "high", "SEC-5": "high", "EGR-1": "medium",
		"EGR-2": "medium", "EGR-4": obs.NotFound, "EGR-5.22": "medium", "EGR-5.80": "medium", "EGR-5.8080": "medium",
		"EGR-5.53u": "medium", "EGR-6": obs.Skipped, "PER-1": "low", "PER-2": "low", "PER-3": "low", "PER-4": "low",
		"PER-5": obs.Skipped, "AMP-1": twn4, "AMP-2": "critical", "AMP-4": twn4, "AMP-8.sys": "high", "AMP-8.blk": twn4}
	modalR1 = map[string]string{"SEC-1": "high", "SEC-2": "high", "EGR-1": obs.NotFound, "EGR-4": obs.NotFound,
		"EGR-5.53u": obs.NotFound, "EGR-6": obs.Skipped, "PER-1": "low", "PER-3": "low", "PER-4": "low",
		"PER-5": obs.Skipped, "AMP-1": obs.Absent, "AMP-4": obs.Absent, "AMP-8.blk": obs.ScopedOut}
	modalR2 = map[string]string{"SEC-2": "high", "EGR-1": obs.NotFound, "EGR-4": obs.NotFound, "EGR-5.53u": obs.NotFound,
		"EGR-6": obs.Skipped, "PER-5": obs.Skipped, "AMP-1": obs.Absent, "AMP-4": obs.Absent, "AMP-8.blk": obs.ScopedOut}
)

func ids(p Plan) []string {
	var out []string
	for _, a := range p.Actions {
		out = append(out, a.ID)
	}
	return out
}

func action(p Plan, id string) (Action, bool) {
	i := slices.IndexFunc(p.Actions, func(a Action) bool { return a.ID == id })
	if i < 0 {
		return Action{}, false
	}
	return p.Actions[i], true
}

// FIX-3, FIX-4, FIX-6: the Modal loop's own rounds rank as the loop ran them.
func TestModalRounds(t *testing.T) {
	if s := report.Score(doc(modalR0)); s.Score != 0 || report.Score(doc(modalR1)).Score != 3 || report.Score(doc(modalR2)).Score != 4 {
		t.Fatalf("the in-memory rounds don't score 0, 3 and 4: %d", s.Score)
	}
	p := Build(doc(modalR0), "exec", "modal")
	want := []string{"run-as-user", "block-network", "protect-home", "clean-env", "isolate-processes"}
	if !slices.Equal(ids(p), want) {
		t.Fatalf("round 0: %v, want %v", ids(p), want)
	}
	ru, _ := action(p, "run-as-user")
	if !ru.Proven || !slices.Equal(ru.Unknowns, []string{"AMP-1", "AMP-4", "AMP-8.blk"}) ||
		!slices.Equal(ru.CouldTurnGreen, []string{"Containment", "Privilege"}) || !slices.Contains(ru.Findings, "AMP-8.sys") {
		t.Errorf("round 0 run-as-user: %+v", ru)
	}
	ph, _ := action(p, "protect-home")
	if ph.After != "run-as-user" || !slices.Equal(ph.CouldTurnGreen, []string{"Persistence"}) || slices.Contains(ph.Findings, "PER-2") {
		t.Errorf("round 0 protect-home: %+v", ph)
	}
	ip, _ := action(p, "isolate-processes")
	if ip.Proven || !slices.Equal(ip.Findings, []string{"SEC-2"}) || len(ip.General) != 1 || ip.General[0].Text != catalog.Guide["SEC-2"].Fix {
		t.Errorf("round 0 isolate-processes: %+v", ip)
	}
	for _, a := range p.Actions { // FIX-3: what run-as-user proved on Modal isn't repeated as general advice
		if a.ID == "close-host-access" || a.ID == "remove-credential-files" {
			t.Errorf("round 0 repeats %s as general advice", a.ID)
		}
		if !strings.Contains(a.Prediction, "a rerun proves it") {
			t.Errorf("%s: %q isn't a prediction", a.ID, a.Prediction)
		}
	}

	p = Build(doc(modalR1), "exec", "modal")
	if want := []string{"protect-home", "clean-env", "isolate-processes"}; !slices.Equal(ids(p), want) {
		t.Fatalf("round 1: %v, want %v", ids(p), want)
	}
	if ph, _ := action(p, "protect-home"); ph.After != "" || !slices.Equal(ph.CouldTurnGreen, []string{"Persistence"}) {
		t.Errorf("round 1 protect-home: %+v", ph)
	}
	p = Build(doc(modalR2), "exec", "modal")
	if want := []string{"isolate-processes"}; !slices.Equal(ids(p), want) {
		t.Fatalf("round 2: %v, want %v", ids(p), want)
	}
}

// FIX-5: Cloud access left untested is never an action and names no flag, provider name or terms, whatever the
// platform; nothing else in the output does either.
func TestCloudIsNotAnAction(t *testing.T) {
	for _, tc := range []struct{ runProvider, platform string }{{"exec", "modal"}, {"exec", ""}, {"exec", "docker"}, {"kubernetes", "kubernetes"}} {
		p := Build(doc(modalR0), tc.runProvider, tc.platform)
		if len(p.NotAnAction) != 1 || p.NotAnAction[0].Category != "Cloud access" || p.NotAnAction[0].Why != CloudNotTested {
			t.Errorf("%v: not an action: %+v", tc, p.NotAnAction)
		}
		if _, ok := action(p, "cloud-identity"); ok {
			t.Errorf("%v: an action for untested Cloud access", tc)
		}
		b, _ := json.Marshal(p)
		for _, banned := range []string{"-provider", "terms", "modal", "Modal"} {
			if banned == "modal" || banned == "Modal" {
				if tc.platform == "modal" {
					continue // the snippets say where they were proven
				}
			}
			if strings.Contains(string(b), banned) {
				t.Errorf("%v: the output says %q", tc, banned)
			}
		}
	}
}

// FIX-3: run-as-user is offered only when AMP-2 is found, never for a readable .env on a box whose agent isn't root.
func TestRunAsUserOnlyForRoot(t *testing.T) {
	for _, path := range []string{"../../demo/reports/vibe.json", "../../demo/reports/regressed.json"} {
		d, err := analysis.Load(path)
		if err != nil {
			t.Fatal(err)
		}
		p := Build(*d, "docker", "docker")
		if _, ok := action(p, "run-as-user"); ok {
			t.Errorf("%s: run-as-user offered without AMP-2's finding: %v", path, ids(p))
		}
		rc, ok := action(p, "remove-credential-files")
		if !ok || rc.Proven || rc.General[0].Text != catalog.Guide["SEC-3"].Fix {
			t.Errorf("%s: SEC-3 doesn't get the catalog's general advice: %+v", path, rc)
		}
		if p.Loop == nil || !strings.Contains(p.Loop[1], "sandprobe run docker <image> -as <user> -y -out <next-folder>") {
			t.Errorf("%s: loop %q", path, p.Loop)
		}
	}
}

// FIX-2: a TWN-4 unknown joins only run-as-user, and only beside AMP-2's finding; any other unknown is not decided by
// a setting.
func TestTWN4UnknownsJoinRunAsUser(t *testing.T) {
	r := map[string]string{"AMP-2": "critical", "AMP-4": twn4, "SEC-5": "unknown:the call failed"}
	p := Build(doc(r), "exec", "")
	ru, ok := action(p, "run-as-user")
	if !ok || !slices.Equal(ru.Unknowns, []string{"AMP-4"}) || ru.Proven || len(ru.General) != 1 {
		t.Fatalf("run-as-user: %+v", ru)
	}
	if !slices.Equal(ru.CouldTurnGreen, []string{"Containment", "Privilege"}) {
		t.Errorf("could turn green: %v", ru.CouldTurnGreen)
	}
	for _, a := range p.Actions {
		if a.ID != "run-as-user" && (slices.Contains(a.Unknowns, "AMP-4") || slices.Contains(a.Findings, "AMP-4")) {
			t.Errorf("%s takes AMP-4", a.ID)
		}
	}
	if !slices.ContainsFunc(p.NotDecided, func(it Item) bool { return it.Check == "SEC-5" }) ||
		slices.ContainsFunc(p.NotDecided, func(it Item) bool { return it.Check == "AMP-4" }) {
		t.Errorf("not decided: %+v", p.NotDecided)
	}
	// Without AMP-2's finding, the same reason decides nothing, and nothing is offered for it.
	p = Build(doc(map[string]string{"AMP-4": twn4}), "exec", "")
	if len(p.Actions) != 0 || !slices.ContainsFunc(p.NotDecided, func(it Item) bool { return it.Check == "AMP-4" }) {
		t.Errorf("without AMP-2: %v %+v", ids(p), p.NotDecided)
	}
}

// FIX-1: an invalid run has nothing to fix.
func TestInvalidRun(t *testing.T) {
	d := doc(modalR0)
	d.Grade.Valid, d.Grade.Invalid = false, "the probe's digest didn't match"
	p := Build(d, "exec", "modal")
	if p.Valid || len(p.Actions) != 0 || p.Loop != nil || len(p.Notes) != 1 {
		t.Errorf("%+v", p)
	}
}

// FIX-8: nothing the report holds reaches the output, text or JSON: only IDs, the catalog, the table and fixed text.
func TestNoReportStrings(t *testing.T) {
	const payload = "PWNED\x1b[31m‮$(id)\nnext"
	d := doc(modalR0)
	d.Run.Box.Name, d.Run.Box.ProviderID, d.Lead, d.Statement = payload, payload, payload, payload
	d.Run.Provider = payload
	for i := range d.Checks {
		c := &d.Checks[i]
		c.Title, c.Evidence, c.Gets, c.Fix = payload, payload, payload, payload
		if c.Result == obs.Unknown {
			c.Reason += payload
		}
	}
	d.Findings = []report.Finding{{ID: "CHN-1", Severity: "critical", Title: payload, Gets: payload, Fix: payload, Checks: []string{"SEC-1"}}}
	for _, platform := range []string{"", "modal", "docker"} {
		b, err := json.Marshal(Build(d, "other", platform))
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(b), "PWNED") || strings.Contains(string(b), "$(id)") {
			t.Errorf("%q: a report string reached the output: %s", platform, b)
		}
	}
}
