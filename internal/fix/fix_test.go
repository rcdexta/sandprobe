package fix

import (
	"encoding/json"
	"fmt"
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
	// The identity as the Modal rounds saw it: root with Modal's default capability sets when AMP-2 is found, an
	// unprivileged user with none otherwise.
	none := "0000000000000000"
	d.Identity = &obs.Identity{UID: 1000, GID: 1000, CapEff: none, CapPrm: none, CapInh: none, CapBnd: rootCaps, CapAmb: none}
	if r := results["AMP-2"]; r != "" && !strings.HasPrefix(r, "unknown") {
		d.Identity = &obs.Identity{CapEff: rootCaps, CapPrm: rootCaps, CapInh: "00000000a80405fb", CapBnd: rootCaps, CapAmb: rootCaps}
	}
	return d
}

const rootCaps = "00000000a80c05fb" // Modal's defaults for root, CAP_SYS_PTRACE among them

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

// FIX-3, FIX-4, FIX-6: the Modal rounds rank from their direct checks; every red check keeps its own action, and a
// snippet's side effects sit apart, uncounted.
func TestModalRounds(t *testing.T) {
	if s := report.Score(doc(modalR0)); s.Score != 0 || report.Score(doc(modalR1)).Score != 3 || report.Score(doc(modalR2)).Score != 4 {
		t.Fatalf("the in-memory rounds don't score 0, 3 and 4: %d", s.Score)
	}
	p := Build(doc(modalR0), "exec", "modal")
	want := []string{"block-network", "run-as-user", "protect-home", "isolate-processes", "clean-env", "remove-credential-files", "close-host-access"}
	if !slices.Equal(ids(p), want) {
		t.Fatalf("round 0: %v, want %v", ids(p), want)
	}
	ru, _ := action(p, "run-as-user")
	if !ru.Proven || !slices.Equal(ru.Findings, []string{"AMP-2"}) || !slices.Equal(ru.Unknowns, []string{"AMP-1", "AMP-4", "AMP-8.blk"}) ||
		!slices.Equal(ru.MayAlsoClear, []string{"SEC-3", "SEC-5", "PER-2", "AMP-8.sys"}) || !slices.Equal(ru.CouldTurnGreen, []string{"Privilege"}) {
		t.Errorf("round 0 run-as-user: %+v", ru)
	}
	// The Modal siblings of SEC-3's case: each side effect keeps its own action, with its own general advice.
	for id, own := range map[string]string{"SEC-3": "remove-credential-files", "SEC-5": "isolate-processes", "PER-2": "protect-home", "AMP-8.sys": "close-host-access"} {
		a, ok := action(p, own)
		if !ok || !slices.Contains(a.Findings, id) || !slices.ContainsFunc(a.General, func(g Advice) bool { return slices.Contains(g.Checks, id) && g.Text == catalog.Guide[id].Fix }) {
			t.Errorf("round 0: %s lost its own action %s: %+v", id, own, a)
		}
	}
	ph, _ := action(p, "protect-home")
	if ph.After != "run-as-user" || !slices.Equal(ph.CouldTurnGreen, []string{"Persistence"}) || !slices.Equal(ph.Findings, []string{"PER-1", "PER-2", "PER-3", "PER-4"}) {
		t.Errorf("round 0 protect-home: %+v", ph)
	}
	ip, _ := action(p, "isolate-processes")
	if ip.Proven || !slices.Equal(ip.Findings, []string{"SEC-2", "SEC-5"}) || len(ip.General) != 2 || ip.General[0].Text != catalog.Guide["SEC-2"].Fix {
		t.Errorf("round 0 isolate-processes: %+v", ip)
	}
	for _, a := range p.Actions {
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

// FIX-3: a root box whose SEC-3 is red, a credential in the agent's home as well as /etc/shadow, keeps
// remove-credential-files beside run-as-user, ranked as it would be without run-as-user's side effect.
func TestSideEffectNeverHidesAnAction(t *testing.T) {
	results := map[string]string{"AMP-2": "critical", "AMP-3": "medium", "SEC-3": "high", "PER-2": "low"}
	d := doc(results)
	for i := range d.Checks {
		if d.Checks[i].ID == "SEC-3" {
			d.Checks[i].Evidence = "the agent can open /etc/shadow and ~/.env (nothing was read)"
		}
	}
	p := Build(d, "docker", "docker")
	ru, _ := action(p, "run-as-user")
	rc, ok := action(p, "remove-credential-files")
	if !ok || !slices.Equal(rc.Findings, []string{"SEC-3"}) || rc.General[0].Text != catalog.Guide["SEC-3"].Fix {
		t.Fatalf("remove-credential-files: %+v in %v", rc, ids(p))
	}
	if !slices.Equal(ru.MayAlsoClear, []string{"SEC-3", "PER-2"}) || slices.Contains(ru.Findings, "SEC-3") || len(ru.CouldTurnGreen) != 0 {
		t.Errorf("run-as-user: %+v", ru)
	}
	if ph, ok := action(p, "protect-home"); !ok || !slices.Equal(ph.Findings, []string{"PER-2"}) {
		t.Errorf("protect-home: %+v", ph)
	}
	// Without run-as-user's snippet at all (an unknown platform), the same actions rank the same way.
	q := Build(d, "docker", "")
	strip := func(p Plan) []string {
		var out []string
		for _, a := range p.Actions {
			out = append(out, fmt.Sprintf("%s %v %v %v", a.ID, a.Findings, a.Unknowns, a.CouldTurnGreen))
		}
		return out
	}
	if !slices.Equal(strip(p), strip(q)) {
		t.Errorf("a side effect moved an action:\n%v\n%v", strip(p), strip(q))
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
		for _, banned := range []string{"-provider", "-platform", "terms", "modal", "Modal"} {
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

// FIX-2: an unknown joins run-as-user only beside AMP-2's finding and a capability TWN-4 names for its mechanism, from
// the identity's capability sets; any other unknown is not decided by a setting.
func TestCapabilityUnknownsJoinRunAsUser(t *testing.T) {
	for _, m := range catalog.Checks {
		if _, ok := powers[m.Mechanism]; !ok {
			t.Errorf("%s: mechanism %q has no TWN-4 powers", m.ID, m.Mechanism)
		}
	}
	// CAP_FOWNER defeats a write refusal, never a refusal to open another process's files.
	d := doc(map[string]string{"AMP-2": "high", "AMP-4": "unknown:the call failed", "SEC-5": "unknown:the call failed"})
	fowner := "0000000000000008"
	d.Identity = &obs.Identity{UID: 1000, GID: 1000, CapEff: fowner, CapPrm: fowner, CapInh: fowner, CapBnd: rootCaps, CapAmb: "0000000000000000"}
	p := Build(d, "exec", "")
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
	// Without AMP-2's finding, a missing identity, or a set that doesn't parse, nothing is decided from capabilities.
	for name, change := range map[string]func(*report.Doc){
		"no AMP-2": func(d *report.Doc) {
			d.Checks[slices.IndexFunc(d.Checks, func(c report.Check) bool { return c.ID == "AMP-2" })].Result = obs.Pass
		},
		"no identity": func(d *report.Doc) { d.Identity = nil },
		"bad set":     func(d *report.Doc) { d.Identity.CapAmb = "not hex" },
	} {
		d := doc(map[string]string{"AMP-2": "critical", "AMP-4": "unknown:the call failed"})
		change(&d)
		p := Build(d, "exec", "")
		if ru, ok := action(p, "run-as-user"); ok && len(ru.Unknowns) > 0 || !slices.ContainsFunc(p.NotDecided, func(it Item) bool { return it.Check == "AMP-4" }) {
			t.Errorf("%s: AMP-4 decided from capabilities: %v %+v", name, ids(p), p.NotDecided)
		}
	}
}

// FIX-2: a report's reasons can't move anything. One whose reasons claim TWN-4 and a capability, and one whose
// reasons say nothing, rank and read the same, whatever the identity holds.
func TestLyingReasonsChangeNothing(t *testing.T) {
	for name, results := range map[string]map[string]string{
		"root":         {"AMP-2": "critical", "AMP-4": "unknown:x", "SEC-3": "unknown:x", "EGR-2": "medium"},
		"no AMP-2":     {"AMP-4": "unknown:x", "SEC-3": "unknown:x", "EGR-2": "medium"},
		"unprivileged": {"AMP-3": "medium", "AMP-4": "unknown:x", "PER-1": "low"},
	} {
		plain, lying := doc(results), doc(results)
		for i := range lying.Checks {
			if lying.Checks[i].Result == obs.Unknown {
				lying.Checks[i].Reason = strings.TrimPrefix(twn4, "unknown:")
				lying.Checks[i].Evidence = "the agent holds CAP_SYS_ADMIN (TWN-4)"
			}
		}
		a, _ := json.Marshal(Build(plain, "exec", "modal"))
		b, _ := json.Marshal(Build(lying, "exec", "modal"))
		if string(a) != string(b) {
			t.Errorf("%s: lying reasons changed the plan:\n%s\n%s", name, a, b)
		}
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
