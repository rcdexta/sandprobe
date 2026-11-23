package analysis

import (
	"encoding/json"
	"html/template"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"sandprobe/internal/catalog"
	"sandprobe/internal/grade"
	"sandprobe/internal/host"
	"sandprobe/internal/obs"
	"sandprobe/internal/report"
)

// attestedRun is a real Docker fixture run (test/reports/bundles) as run exec with -provider-endpoints SEC-4,AMP-7
// plans it, graded and built as a run writes it. invalid breaks the probe's nonce, so the grader grades nothing (GRD-5).
func attestedRun(t *testing.T, invalid bool) report.Doc {
	t.Helper()
	raw, err := os.ReadFile("../../test/reports/bundles/egress-refused.bundle.json")
	if err != nil {
		t.Fatal(err)
	}
	var q struct {
		Manifest     obs.Manifest       `json:"manifest"`
		Observations string             `json:"observations"`
		Evidence     obs.CanaryEvidence `json:"evidence"`
	}
	if err := json.Unmarshal(raw, &q); err != nil {
		t.Fatal(err)
	}
	off := host.ExecExclusions()
	delete(off, "SEC-4")
	delete(off, "AMP-7")
	plan, _ := host.Plan(host.Options{Mode: "exec", Excluded: off, ExcludedKind: obs.SkipOptIn, Attested: []string{"SEC-4", "AMP-7"}, Existing: true},
		&obs.Survey{Schema: obs.SurveySchema}, q.Manifest.BoxID, host.Storage{}, "", "", "")
	m := q.Manifest
	for id := range off {
		m.Skipped[id] = plan.Skipped[id]
		m.Selected = slices.DeleteFunc(m.Selected, func(s string) bool { return s == id })
	}
	m.SkipKinds, m.Attested = plan.SkipKinds, plan.Attested
	pd, err := obs.ParseDoc([]byte(q.Observations))
	if err != nil {
		t.Fatal(err)
	}
	if invalid {
		pd.Nonce = "n-not-this-run"
	}
	b, _ := json.Marshal(pd)
	r := &host.Run{Manifest: m, Doc: b, Evidence: q.Evidence, Report: grade.GradeBytes(m, b, &q.Evidence)}
	d := report.Build(r, report.Meta{Version: "fixture", Provider: "exec", BoxName: m.BoxID,
		StartedAt: time.Date(2026, 11, 21, 0, 0, 0, 0, time.UTC), Duration: 4 * time.Second})
	if d.Grade.Valid == invalid {
		t.Fatalf("valid %v: %s", d.Grade.Valid, d.Grade.Invalid)
	}
	return d
}

func rowOf(d report.Doc, id string) (report.Check, bool) {
	for _, c := range d.Checks {
		if c.ID == id {
			return c, true
		}
	}
	return report.Check{}, false
}

// PRV-15 and GRD-5: an invalid run keeps each attested check's row, with its attestation and "not graded", in the JSON
// and on the page, since the check may already have contacted its endpoint; it grades nothing else, and the saved
// report reads under ANL-1.
func TestInvalidRunKeepsAttestedRows(t *testing.T) {
	d := attestedRun(t, true)
	for _, id := range []string{"SEC-4", "AMP-7"} {
		c, ok := rowOf(d, id)
		if !ok || c.Attestation != report.Attestation || c.Result != obs.Unknown || c.Reason != report.NotGraded {
			t.Errorf("%s: row %v %+v", id, ok, c)
		}
	}
	for _, c := range d.Checks {
		if c.Result != obs.Skipped && !slices.Contains(d.Manifest.Attested, c.ID) {
			t.Errorf("an invalid run graded %s: %s", c.ID, c.Result)
		}
	}
	if len(d.Grade.Unknown) != 0 || d.Schema != report.SchemaSkipKinds {
		t.Errorf("unknown %v, schema %s", d.Grade.Unknown, d.Schema)
	}
	b, _ := json.Marshal(d)
	if _, err := Parse(b); err != nil {
		t.Fatalf("the saved invalid report doesn't load: %v", err)
	}
	page, err := report.HTML(d, "modern")
	if err != nil {
		t.Fatal(err)
	}
	p := string(page)
	for _, want := range []string{"Turned on by your attestation (-provider-endpoints, PRV-15)", template.HTMLEscapeString(report.Attestation),
		template.HTMLEscapeString(report.NotGraded), "INVALID RUN", "report schema sandprobe/2"} {
		if !strings.Contains(p, want) {
			t.Errorf("the invalid run's page doesn't say %q", want)
		}
	}
	valid := attestedRun(t, false)
	if page, _ := report.HTML(valid, "modern"); strings.Count(string(page), template.HTMLEscapeString(report.Attestation)) != 4 {
		t.Error("a valid run's page doesn't show each attestation beside its test and in the appendix")
	}
}

// PRV-15 and ANL-1, the code review's reproduction: a saved report with an attested check's row deleted is refused,
// valid or invalid; and an invalid one may carry no unknown row but an attested check's.
func TestAttestedRowsAreRequired(t *testing.T) {
	for _, invalid := range []bool{true, false} {
		d := attestedRun(t, invalid)
		d.Checks = slices.DeleteFunc(d.Checks, func(c report.Check) bool { return c.ID == "SEC-4" })
		b, _ := json.Marshal(d)
		if _, err := Parse(b); err == nil {
			t.Errorf("invalid %v: a report without its attested SEC-4 row was accepted", invalid)
		}
	}
	d := attestedRun(t, true)
	ck, _ := catalog.Get("SEC-3")
	d.Checks = append(d.Checks, report.Check{ID: "SEC-3", Category: ck.Category, Title: ck.Title, Kind: "two_sided", Result: obs.Unknown})
	b, _ := json.Marshal(d)
	if _, err := Parse(b); err == nil {
		t.Error("an invalid report carried an unknown row for a check nobody attested")
	}
	d = attestedRun(t, true)
	d.Grade.Unknown = []string{"SEC-4"}
	b, _ = json.Marshal(d)
	if _, err := Parse(b); err == nil {
		t.Error("an invalid report listed unknowns in its grade")
	}
}

// GRD-5 and PRV-15, the code review of #12: an invalid run grades nothing, so a saved invalid report's attested rows
// stay exactly "not graded". The reviewer's mutation (SEC-4 turned not_found with a reason of its own) is refused, as
// is any other outcome, reason, evidence or graded row; the unchanged report and a deliberate skip still read.
func TestInvalidAttestedRowsStayNotGraded(t *testing.T) {
	if b, _ := json.Marshal(attestedRun(t, true)); func() bool { _, err := Parse(b); return err != nil }() {
		t.Fatal("the unchanged invalid report was refused")
	}
	set := func(id string, edit func(*report.Check)) func(*report.Doc) {
		return func(d *report.Doc) {
			for i := range d.Checks {
				if d.Checks[i].ID == id {
					edit(&d.Checks[i])
				}
			}
		}
	}
	for name, mutate := range map[string]func(*report.Doc){
		"SEC-4 not_found (the reviewer's reproduction)": set("SEC-4", func(c *report.Check) { c.Result, c.Reason = obs.NotFound, "no metadata service listed a role" }),
		"AMP-7 a finding": set("AMP-7", func(c *report.Check) {
			c.Result, c.Reason, c.Severity, c.EvidenceClass = obs.Finding, "", "medium", "indicator"
		}),
		"SEC-4 unknown, another reason":   set("SEC-4", func(c *report.Check) { c.Reason = "the box said so" }),
		"SEC-4 not graded, with evidence": set("SEC-4", func(c *report.Check) { c.Evidence = "a role was listed" }),
		"SEC-4 not graded, with a scope":  set("SEC-4", func(c *report.Check) { c.Scope = &report.Scope{Destination: "169.254.169.254", Port: "80"} }),
		"a graded row nobody attested": func(d *report.Doc) { // AMP-1 is find-only, so not_found is legal for it in a valid run
			ck, _ := catalog.Get("AMP-1")
			d.Checks = append(d.Checks, report.Check{ID: "AMP-1", Category: ck.Category, Title: ck.Title, Kind: "find_only", Result: obs.NotFound})
		},
	} {
		d := attestedRun(t, true)
		mutate(&d)
		b, _ := json.Marshal(d)
		if _, err := Parse(b); err == nil {
			t.Errorf("%s: an invalid report with a graded row was accepted", name)
		}
	}
}
