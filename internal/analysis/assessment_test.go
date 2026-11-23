package analysis

import (
	"slices"
	"testing"

	"sandprobe/internal/obs"
	"sandprobe/internal/report"
)

// Two real runs of local Docker boxes, as root, that differ only in a firewall: every route out to the canary open, or
// every TCP port to it refused with a reset and UDP to it rejected (test/reports/README.md).
const openReport = "../../test/reports/egress-open.json"
const refusedReport = "../../test/reports/egress-refused.json"

func loadReport(t *testing.T, path string) *report.Doc {
	t.Helper()
	d, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// CAL-5: replay saved evidence, not expectations tuned from prose.
func TestAssessmentCalibration(t *testing.T) {
	for _, tc := range []struct {
		path, outcome, tcp          string
		refused, delivered, unknown int
		drivers                     []string
	}{
		{openReport, "reported_violation", "reported_violation", 0, 6, 0, []string{"AMP-2", "CHN-1"}},
		{refusedReport, Inconclusive, "reported_four_route_requirements_met", 4, 0, 2, []string{"AMP-2"}},
	} {
		d := loadReport(t, tc.path)
		a, err := Assess(d, CanaryDenyProfile)
		if err != nil {
			t.Fatal(err)
		}
		if a.Outcome != tc.outcome || a.DirectTCP != tc.tcp || a.Counts[ReportedRefusal] != tc.refused || a.Counts[ReportedDelivery] != tc.delivered || a.Counts[Inconclusive] != tc.unknown || len(a.Routes) != 6 {
			t.Fatalf("unexpected interpretation: %+v", a)
		}
		if !slices.Equal(a.LegacyDrivers, tc.drivers) || a.ObservedUID == nil || *a.ObservedUID != 0 || !a.SourceComplete || len(a.Coverage.Areas) != 5 || a.Coverage.ReportedGrade != "F" || d.Grade.Letter != "F" {
			t.Fatal("root context, source coverage or legacy grade lost")
		}
	}
}

// Remove stale aggregate metadata after a synthetic observation change. This
// fixture is not a new provider run or proof of real-world containment.
func recountAssessmentFixture(d *report.Doc) {
	d.Grade.Unknown = []string{}
	d.Grade.Counts = map[string]int{"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
	d.Findings = []report.Finding{}
	for _, c := range d.Checks {
		if c.Result == obs.Unknown {
			d.Grade.Unknown = append(d.Grade.Unknown, c.ID)
		}
		if c.Result == obs.Finding {
			d.Grade.Counts[c.Severity]++
			d.Findings = append(d.Findings, report.Finding{ID: c.ID, Severity: c.Severity, Class: c.EvidenceClass})
		}
	}
	d.Grade.Complete = len(d.Grade.Unknown) == 0
}

func checkRow(d *report.Doc, id string) *report.Check {
	for i := range d.Checks {
		if d.Checks[i].ID == id {
			return &d.Checks[i]
		}
	}
	panic("missing synthetic fixture row")
}

func TestAssessmentDoesNotInventNegativeProof(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(*report.Doc)
		err  bool
	}{
		{"wrong-port", func(d *report.Doc) { checkRow(d, "EGR-2").Scope.Port = "80" }, false},
		{"wrong-route", func(d *report.Doc) { checkRow(d, "EGR-2").Scope.Route = "proxy" }, false},
		{"wrong-destination", func(d *report.Doc) { checkRow(d, "EGR-2").Scope.Destination = "192.0.2.1" }, false},
		{"empty-destination-matched-endpoint", func(d *report.Doc) {
			checkRow(d, "EGR-2").Scope.Destination = ""
			d.Manifest.Endpoints["EGR-2"] = ":443"
		}, false},
		{"invalid-destination-matched-endpoint", func(d *report.Doc) {
			checkRow(d, "EGR-2").Scope.Destination = "not an IP"
			d.Manifest.Endpoints["EGR-2"] = "not an IP:443"
		}, false},
		{"missing-nonce", func(d *report.Doc) { delete(d.Manifest.CheckNonces, "EGR-2") }, false},
		{"missing-scope", func(d *report.Doc) { checkRow(d, "EGR-2").Scope = nil }, false},
		{"unknown", func(d *report.Doc) { checkRow(d, "EGR-2").Result = obs.Unknown; checkRow(d, "EGR-2").Proof = nil }, false},
		{"missing-proof", func(d *report.Doc) { checkRow(d, "EGR-2").Proof = nil }, true},
		{"wrong-mechanism", func(d *report.Doc) { checkRow(d, "EGR-2").Proof.Mechanism = "not-canary" }, true},
		{"wrong-proof-result", func(d *report.Doc) { checkRow(d, "EGR-2").Proof.Result = obs.Finding }, true},
		{"absent", func(d *report.Doc) { c := checkRow(d, "EGR-2"); c.Result = obs.Absent; c.Proof.Result = obs.Absent }, true},
		{"scoped-out", func(d *report.Doc) { checkRow(d, "EGR-2").Result = obs.ScopedOut }, true},
		{"missing-required-row", func(d *report.Doc) {
			for i, c := range d.Checks {
				if c.ID == "EGR-2" {
					d.Checks = append(d.Checks[:i], d.Checks[i+1:]...)
					break
				}
			}
		}, true},
		{"omitted-from-manifest-and-rows", func(d *report.Doc) {
			d.Manifest.Selected = slices.DeleteFunc(d.Manifest.Selected, func(s string) bool { return s == "EGR-2" })
			d.Checks = slices.DeleteFunc(d.Checks, func(c report.Check) bool { return c.ID == "EGR-2" })
		}, false},
		{"skipped-required-route", func(d *report.Doc) {
			d.Manifest.Selected = slices.DeleteFunc(d.Manifest.Selected, func(s string) bool { return s == "EGR-2" })
			d.Manifest.Skipped["EGR-2"] = "synthetic exclusion"
			checkRow(d, "EGR-2").Result = obs.Skipped
		}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := loadReport(t, refusedReport)
			tc.edit(d)
			recountAssessmentFixture(d)
			a, err := Assess(d, CanaryDenyProfile)
			if (err != nil) != tc.err {
				t.Fatalf("error = %v, expected error %t", err, tc.err)
			}
			if !tc.err && (a.Counts[ReportedRefusal] != 3 || a.Counts[Inconclusive] != 3 || a.DirectTCP != Inconclusive || a.Outcome != Inconclusive) {
				t.Fatalf("false refusal: %+v", a)
			}
		})
	}
}

func TestAssessmentRejectsForgedAllRefused(t *testing.T) {
	d := loadReport(t, refusedReport)
	for _, id := range []string{"EGR-1", "EGR-5.53u"} {
		c := checkRow(d, id)
		c.Result = obs.Pass
		c.Proof.Result = obs.Pass
	}
	if _, err := Assess(d, CanaryDenyProfile); err == nil {
		t.Fatal("find-only silence fabricated into complete negative coverage")
	}
}

func TestAssessmentSourceAndViolationVisibility(t *testing.T) {
	d := loadReport(t, openReport)
	checkRow(d, "EGR-2").Result = obs.Unknown
	checkRow(d, "EGR-2").Severity = ""
	checkRow(d, "EGR-2").EvidenceClass = ""
	checkRow(d, "EGR-2").Proof = nil
	recountAssessmentFixture(d)
	a, err := Assess(d, CanaryDenyProfile)
	if err != nil || a.SourceComplete || a.Outcome != "reported_violation" || a.Counts[ReportedDelivery] != 5 || a.Counts[Inconclusive] != 1 {
		t.Fatal("uncertainty hid delivery")
	}
	d = loadReport(t, refusedReport)
	d.Identity = nil
	if _, err = Assess(d, CanaryDenyProfile); err == nil {
		t.Fatal("derived pass without identity accepted")
	}
	checkRow(d, "AMP-3").Result = obs.Unknown
	checkRow(d, "AMP-3").Proof = nil
	recountAssessmentFixture(d)
	a, err = Assess(d, CanaryDenyProfile)
	if err != nil || a.SourceComplete || a.ObservedUID != nil {
		t.Fatal("missing identity treated as complete")
	}
	d = loadReport(t, refusedReport)
	d.Grade.Valid = false
	d.Grade.Complete = false
	d.Grade.Letter = ""
	if _, err = Assess(d, CanaryDenyProfile); err == nil { // GRD-5: an invalid run grades nothing, so graded rows are refused
		t.Fatal("an invalid report carrying graded rows was assessed")
	}
	d.Checks = slices.DeleteFunc(d.Checks, func(c report.Check) bool { return c.Result != obs.Skipped }) // as an invalid run writes it
	recountAssessmentFixture(d)
	d.Grade.Complete = false
	a, err = Assess(d, CanaryDenyProfile)
	if err != nil || a.SourceComplete || len(a.Routes) != 0 || a.Outcome != Inconclusive {
		t.Fatal("invalid run assessed")
	}
	if _, err = Assess(nil, CanaryDenyProfile); err == nil {
		t.Fatal("nil source accepted")
	}
	if _, err = Assess(loadReport(t, refusedReport), "custom-drop-DNS"); err == nil {
		t.Fatal("unsupported profile accepted")
	}
}
