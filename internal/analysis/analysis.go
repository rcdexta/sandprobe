// Package analysis provides structural-only offline analysis, never an attestation.
package analysis

import (
	"errors"
	"reflect"
	"slices"
	"strings"

	"sandprobe/internal/catalog"
	"sandprobe/internal/obs"
	"sandprobe/internal/report"
	"sandprobe/internal/strictjson"
)

const MaxReport = 8 << 20

var ErrInput = errors.New("unsupported, inconsistent or unsafe report input")

// Load never follows the final symlink, opens devices or accepts unframed JSON.
func Load(path string) (*report.Doc, error) {
	b, err := readFile(path)
	if err != nil {
		return nil, ErrInput
	}
	return Parse(b)
}
func Parse(b []byte) (*report.Doc, error) {
	var d report.Doc
	if strictjson.Decode(b, MaxReport, &d) != nil {
		return nil, ErrInput
	}
	if Validate(&d) != nil {
		return nil, ErrInput
	}
	return &d, nil
}

func severity(s string) int {
	return slices.Index([]string{"info", "low", "medium", "high", "critical"}, s)
}
func set(a []string) (map[string]bool, bool) {
	m := map[string]bool{}
	for _, s := range a {
		if m[s] {
			return nil, false
		}
		m[s] = true
	}
	return m, true
}
func kind(c catalog.Check) string {
	if c.Kind == catalog.FindOnly {
		return "find_only"
	}
	return "two_sided"
}

// Validate checks exported consistency only. The saved letter is unverified and
// never used for profile/comparison decisions (ANL-1); raw proofs are unavailable.
func Validate(d *report.Doc) error {
	if obs.ValidateWorkloadContract(d.Manifest.WorkloadContract) != nil || (d.Manifest.WorkloadContract != nil && d.Manifest.WorkloadContract.BoxID != d.Manifest.BoxID) {
		return ErrInput
	}
	if obs.ValidateBoundaryContract(d.Manifest.BoundaryContract) != nil {
		return ErrInput
	}
	for _, check := range catalog.Checks {
		if area(check.ID) == "" {
			return ErrInput
		}
	}

	if d.Schema != report.SchemaFor(d.Manifest) || d.Run.ID == "" || d.Run.Provider == "" || d.Run.Mode == "" || d.Manifest.RunID != d.Run.ID || d.Manifest.Nonce != d.Run.Nonce || d.Manifest.Mode != d.Run.Mode || d.Run.Nonce == "" {
		return ErrInput
	}
	if !slices.Contains([]string{"exec", "entrypoint"}, d.Run.Mode) {
		return ErrInput
	}
	if d.Manifest.BoxID == "" || d.Manifest.BoxID != d.Run.Box.ProviderID || d.Manifest.ProbeSHA256 == "" || d.Manifest.ProbeSHA256 != d.Probe.SHA256 {
		return ErrInput
	}
	if d.Grade.Valid && len(d.Manifest.Selected) == 0 {
		return ErrInput
	}
	if d.Grade.Valid && (!strings.Contains("ABCDF", d.Grade.Letter) || len(d.Grade.Letter) != 1 || d.Grade.Invalid != "") {
		return ErrInput
	}
	if !d.Grade.Valid && (d.Grade.Letter != "" || d.Grade.Complete) {
		return ErrInput
	}
	selected, ok := set(d.Manifest.Selected)
	if !ok {
		return ErrInput
	}
	for id := range selected {
		if _, ok := catalog.Get(id); !ok {
			return ErrInput
		}
		if _, ok := d.Manifest.Skipped[id]; ok {
			return ErrInput
		}
	}
	for id := range d.Manifest.Skipped {
		if _, ok := catalog.Get(id); !ok {
			return ErrInput
		}
	}
	policy := report.PolicyKinds(d.Run.Provider)
	// PRV-15: an attestation names a provider endpoint once, never one that still carries a skip kind, only where this
	// binary's own policy makes it opt-in (run exec, a shipped recipe), and each report row carries the fixed sentence
	// exactly when its check was attested.
	for i, id := range d.Manifest.Attested {
		if _, kind := d.Manifest.SkipKinds[id]; !catalog.ProviderEndpoints[id] || kind || policy[id] != obs.SkipOptIn || slices.Contains(d.Manifest.Attested[:i], id) {
			return ErrInput
		}
	}
	for _, c := range d.Checks {
		if want := slices.Contains(d.Manifest.Attested, c.ID); c.Attestation != "" && (!want || c.Attestation != report.Attestation) || want && c.Attestation == "" {
			return ErrInput
		}
	}
	// SCR-2: a skip kind names only a skipped provider-endpoint check, and only one of the two kinds; and it must be
	// the kind this binary's own policy derives for the run's provider, so an edited kind is refused, never scored.
	for id, kind := range d.Manifest.SkipKinds {
		if _, ok := d.Manifest.Skipped[id]; !ok || !catalog.ProviderEndpoints[id] || (kind != obs.SkipProviderTerms && kind != obs.SkipOptIn) || policy[id] != kind {
			return ErrInput
		}
	}
	unknown, ok := set(d.Grade.Unknown)
	if !ok {
		return ErrInput
	}
	rows := map[string]report.Check{}
	actualUnknown := map[string]bool{}
	for _, c := range d.Checks {
		cat, ok := catalog.Get(c.ID)
		if !ok || rows[c.ID].ID != "" || c.Category != cat.Category || c.Kind != kind(*cat) {
			return ErrInput
		}
		rows[c.ID] = c
		if c.Result == obs.Skipped {
			if _, ok := d.Manifest.Skipped[c.ID]; !ok {
				return ErrInput
			}
			continue
		}
		if !selected[c.ID] {
			return ErrInput
		}
		switch c.Result {
		case obs.Finding:
			legal := false
			for _, v := range cat.Variants {
				if v.Severity.String() == c.Severity && string(v.Class) == c.EvidenceClass {
					legal = true
				}
			}
			if !legal {
				return ErrInput
			}
		case obs.Pass:
			if cat.Kind != catalog.TwoSided {
				return ErrInput
			}
			if cat.Derived {
				if d.Identity == nil {
					return ErrInput
				}
			} else if c.Proof == nil || c.Proof.Result != obs.Pass || c.Proof.Mechanism != proofMechanism(*cat) {
				return ErrInput
			}
		case obs.Absent:
			if !cat.AbsentOK || c.Proof == nil || c.Proof.Result != obs.Absent || c.Proof.Mechanism != cat.Mechanism {
				return ErrInput
			}
		case obs.ScopedOut:
			if cat.ScopeOut == "" {
				return ErrInput
			}
		case obs.NotFound:
			if cat.Kind != catalog.FindOnly {
				return ErrInput
			}
		case obs.Unknown:
			actualUnknown[c.ID] = true
		default:
			return ErrInput
		}
	}
	if d.Grade.Valid && !reflect.DeepEqual(actualUnknown, unknown) {
		return ErrInput
	}
	if !d.Grade.Valid { // GRD-5: an invalid run grades nothing: each row is a skip, or an attested check not graded (PRV-15)
		if len(unknown) != 0 {
			return ErrInput
		}
		for _, c := range d.Checks {
			if c.Result == obs.Skipped {
				continue
			}
			if !slices.Contains(d.Manifest.Attested, c.ID) || c.Result != obs.Unknown || c.Reason != report.NotGraded ||
				c.Evidence != "" || c.Severity != "" || c.EvidenceClass != "" || c.Proof != nil || c.Scope != nil {
				return ErrInput
			}
		}
	}
	for _, id := range d.Manifest.Attested { // PRV-15: every attested check keeps its row, valid run or not
		if rows[id].ID == "" {
			return ErrInput
		}
	}
	if d.Grade.Valid {
		for id := range selected {
			if rows[id].ID == "" {
				return ErrInput
			}
		}
		for id := range d.Manifest.Skipped {
			if rows[id].Result != obs.Skipped {
				return ErrInput
			}
		}
		if d.Grade.Complete != (len(unknown) == 0) {
			return ErrInput
		}
	}
	counts := map[string]int{"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
	findings := map[string]bool{}
	for _, f := range d.Findings {
		if severity(f.Severity) < 0 || findings[f.ID] || (f.Class != "proof" && f.Class != "indicator") {
			return ErrInput
		}
		if strings.HasPrefix(f.ID, "CHN-") {
			if !slices.Contains([]string{"CHN-1", "CHN-2", "CHN-3"}, f.ID) || len(f.Checks) == 0 {
				return ErrInput
			}
			for _, id := range f.Checks {
				if rows[id].Result != obs.Finding {
					return ErrInput
				}
			}
		} else if rows[f.ID].Result != obs.Finding || rows[f.ID].Severity != f.Severity || rows[f.ID].EvidenceClass != f.Class {
			return ErrInput
		}
		findings[f.ID] = true
		counts[f.Severity]++
	}
	for _, c := range d.Checks {
		if c.Result == obs.Finding && !findings[c.ID] {
			return ErrInput
		}
	}
	if !reflect.DeepEqual(counts, d.Grade.Counts) {
		return ErrInput
	}
	return nil
}

type Area struct {
	Name     string         `json:"name"`
	Counts   map[string]int `json:"counts"`
	Findings []string       `json:"findings"`
}
type Profile struct {
	WorkloadContext *obs.WorkloadContract `json:"declared_workload_context,omitempty"`
	Schema          string                `json:"schema"`
	Verification    string                `json:"verification"`
	ReportedGrade   string                `json:"reported_grade_unverified"`
	Provider        string                `json:"provider"`
	Valid           bool                  `json:"reported_valid"`
	Complete        bool                  `json:"selected_checks_complete"`
	Areas           []Area                `json:"areas"`
	Limits          []string              `json:"limits"`
}

// ANL-2: every catalog check is classified explicitly. A new check must not
// silently fall into provider reach or disappear from the profile.
func area(id string) string {
	switch id {
	case "EGR-1", "EGR-2", "EGR-3", "EGR-4", "EGR-5.22", "EGR-5.80", "EGR-5.8080", "EGR-5.53u", "EGR-6":
		return "egress"
	case "PER-1", "PER-2", "PER-3", "PER-4", "PER-5":
		return "persistence"
	case "SEC-1", "SEC-2", "SEC-3", "SEC-5":
		return "secrets"
	case "AMP-1", "AMP-2", "AMP-3", "AMP-8.sys", "AMP-8.blk":
		return "privilege"
	case "SEC-4", "AMP-4", "AMP-5", "AMP-6", "AMP-7":
		return "provider_reach"
	default:
		return ""
	}
}

// Summarize assumes Validate succeeded, and never labels an area secure.
func Summarize(d *report.Doc) Profile {
	p := Profile{Schema: "sandprobe.profile/1", Verification: "structural_only_unauthenticated", ReportedGrade: d.Grade.Letter, Provider: d.Run.Provider, Valid: d.Grade.Valid, Complete: d.Grade.Complete && d.Identity != nil, Areas: []Area{}, Limits: []string{"Self-observed saved data; raw proofs and receipts not reverified; no attestation.", "Selected completeness excludes skipped and missing catalog coverage.", "No finding does not establish containment; reported grade is unverified."}}
	if !d.Grade.Valid {
		return p
	}
	if d.Manifest.WorkloadContract != nil {
		context := *d.Manifest.WorkloadContract
		p.WorkloadContext = &context
		p.Limits = append(p.Limits, "Workload configuration context is a declaration in unauthenticated saved data, not a live workload grade or assurance.")
	}

	rows := map[string]report.Check{}
	for _, c := range d.Checks {
		rows[c.ID] = c
	}
	for _, name := range []string{"egress", "secrets", "privilege", "persistence", "provider_reach"} {
		a := Area{Name: name, Counts: map[string]int{}, Findings: []string{}}
		for _, cat := range catalog.Checks {
			if area(cat.ID) != name {
				continue
			}
			c, ok := rows[cat.ID]
			r := "missing"
			if ok {
				r = c.Result
			}
			a.Counts[r]++
			if r == obs.Finding {
				a.Findings = append(a.Findings, cat.ID)
			}
		}
		p.Areas = append(p.Areas, a)
	}
	return p
}

type Comparison struct {
	Schema           string   `json:"schema"`
	Verification     string   `json:"verification"`
	NewOrWorse       []string `json:"new_or_worse_findings"`
	CoverageLoss     []string `json:"coverage_loss"`
	ContextChanges   []string `json:"context_changes"`
	Incomplete       bool     `json:"incomplete"`
	NoObservedChange bool     `json:"no_observed_change"`
	Limits           []string `json:"limits"`
}

func proofMechanism(c catalog.Check) string {
	if c.Canary != nil {
		return "canary"
	}
	return c.Mechanism
}

// termsSkips is the checks a report skipped for the provider's terms (SCR-2), sorted: the only kind that changes
// which categories its score counts. An opt-in skip and one with no kind both read "Not tested".
func termsSkips(m obs.Manifest) []string {
	var ids []string
	for id, kind := range m.SkipKinds {
		if kind == obs.SkipProviderTerms {
			ids = append(ids, id)
		}
	}
	slices.Sort(ids)
	return ids
}

func covered(c report.Check) bool {
	return c.ID != "" && c.Result != obs.Unknown && c.Result != obs.Skipped
}

// REF-3: only these CLI-written notes carry reference configuration. Grader
// findings and lifecycle error notes are outcomes, not configuration changes.
func referenceContextNotes(notes []string) []string {
	var context []string
	for _, note := range notes {
		if strings.HasPrefix(note, "REF-2: ") || strings.HasPrefix(note, "REF-3: ") {
			context = append(context, note)
		}
	}
	return context
}

func Compare(a, b *report.Doc) Comparison {
	out := Comparison{Schema: "sandprobe.compare/1", Verification: "structural_only_unauthenticated", NewOrWorse: []string{}, CoverageLoss: []string{}, ContextChanges: []string{}, Incomplete: !a.Grade.Valid || !b.Grade.Valid || !a.Grade.Complete || !b.Grade.Complete || a.Identity == nil || b.Identity == nil, Limits: []string{"Unrecorded image, policy and workload differences remain unknown.", "Comparison covers exported fields only; ephemeral canary IPs ignored, ports/routes retained; no equivalent-security or attestation claim."}}
	// BND-3: addition/removal is a context change too.
	if !reflect.DeepEqual(a.Manifest.BoundaryContract, b.Manifest.BoundaryContract) {
		out.ContextChanges = append(out.ContextChanges, "declared_boundary_context")
	}
	if !reflect.DeepEqual(a.Manifest.WorkloadContract, b.Manifest.WorkloadContract) {
		out.ContextChanges = append(out.ContextChanges, "declared_workload_context")
	}

	if !a.Grade.Valid || !b.Grade.Valid {
		return out
	}
	if a.Run.Provider != b.Run.Provider {
		out.ContextChanges = append(out.ContextChanges, "provider")
	}
	if a.Run.Mode != b.Run.Mode {
		out.ContextChanges = append(out.ContextChanges, "mode")
	}
	if !reflect.DeepEqual(a.Identity, b.Identity) {
		out.ContextChanges = append(out.ContextChanges, "identity")
	}
	// Compare reference context as opaque data, without parsing its prose.
	if !reflect.DeepEqual(referenceContextNotes(a.Grade.Notes), referenceContextNotes(b.Grade.Notes)) {
		out.ContextChanges = append(out.ContextChanges, "reported_reference_context")
	}
	// SCR-2: a changed set of provider-terms skips changes which categories the score counts, so it's a changed setup.
	if !reflect.DeepEqual(a.Manifest.Targets, b.Manifest.Targets) || !reflect.DeepEqual(a.Manifest.Discover, b.Manifest.Discover) || !reflect.DeepEqual(a.Manifest.Overrides, b.Manifest.Overrides) || a.Manifest.Reset != b.Manifest.Reset || a.Manifest.AllowLocalProxy != b.Manifest.AllowLocalProxy || a.Manifest.ProxyMalformed != b.Manifest.ProxyMalformed || a.Manifest.Proxy != b.Manifest.Proxy || a.Manifest.KubeAPI != b.Manifest.KubeAPI || !slices.Equal(termsSkips(a.Manifest), termsSkips(b.Manifest)) {
		out.ContextChanges = append(out.ContextChanges, "declared_configuration")
	}
	rowsA, rowsB := map[string]report.Check{}, map[string]report.Check{}
	for _, c := range a.Checks {
		rowsA[c.ID] = c
	}
	for _, c := range b.Checks {
		rowsB[c.ID] = c
	}
	changed := false
	for _, cat := range catalog.Checks {
		x, y := rowsA[cat.ID], rowsB[cat.ID]
		if y.Result == obs.Finding && (x.Result != obs.Finding || severity(y.Severity) > severity(x.Severity) || x.EvidenceClass != y.EvidenceClass) {
			out.NewOrWorse = append(out.NewOrWorse, cat.ID)
		}
		if covered(x) && !covered(y) {
			out.CoverageLoss = append(out.CoverageLoss, cat.ID)
		}
		if x.Result != y.Result || x.Severity != y.Severity || x.EvidenceClass != y.EvidenceClass {
			changed = true
		}
		scopeEqual := reflect.DeepEqual(x.Scope, y.Scope)
		// Canary IPs are run-owned ephemeral endpoints, but port and route define coverage.
		if cat.Canary != nil && x.Scope != nil && y.Scope != nil {
			scopeEqual = x.Scope.Port == y.Scope.Port && x.Scope.Route == y.Scope.Route
		}
		if covered(x) && covered(y) && (!scopeEqual || x.Kind != y.Kind) {
			out.ContextChanges = append(out.ContextChanges, cat.ID+":scope_or_kind")
		}
	}
	out.NoObservedChange = !changed && !out.Incomplete && len(out.ContextChanges) == 0 && len(out.CoverageLoss) == 0
	return out
}
