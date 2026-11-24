// Package fix turns a saved report's red checks into a short, ranked list of changes a person can make to the
// sandbox's own config or code, with the rerun and compare steps that show whether each one worked (SPEC.md, "Fix
// loop", FIX-1 to FIX-9). It predicts; it never marks anything fixed. Everything it says comes from the catalog, the
// action table and fixed sentences, never from a string the report holds (FIX-8).
package fix

import (
	"slices"
	"sort"
	"strconv"

	"sandprobe/internal/catalog"
	"sandprobe/internal/obs"
	"sandprobe/internal/report"
	"sandprobe/recipes"
)

// Schema is the fix document's version (FIX-8).
const Schema = "sandprobe.fix/1"

// Prediction is FIX-8's wording: a fix is a prediction until a rerun shows it.
const Prediction = "should clear; a rerun proves it"

// SideEffect is FIX-3's wording for a check a snippet's rerun also cleared, beyond its triggers.
const SideEffect = "A side effect seen on another box, not counted here: this may also clear it; a rerun proves it. " +
	"Each keeps its own action."

// IncompleteLine is FIX-1's fixed warning for an incomplete report.
func IncompleteLine(n int) string {
	if n == 1 {
		return "This report is incomplete: 1 check unknown; a rerun may change the plan."
	}
	return "This report is incomplete: " + strconv.Itoa(n) + " checks unknown; a rerun may change the plan."
}

// GeneralAdvice labels the catalog's own fix sentences where no rerun proved a setting on this platform (FIX-3).
const GeneralAdvice = "General advice, not proven on this platform"

// Plan is FIX-1's document.
type Plan struct {
	Schema       string   `json:"schema"`
	Verification string   `json:"verification"` // ANL-1: a saved report is never re-verified
	Note         string   `json:"note"`
	Valid        bool     `json:"valid"`
	Complete     bool     `json:"complete"` // FIX-1: an incomplete report keeps its plan, and says so
	Unknown      []string `json:"unknown"`  // the grade's unknown check IDs
	Platform     string   `json:"platform"` // from the fixed list, or "unknown"
	Score        int      `json:"score"`
	Of           int      `json:"of"`
	Actions      []Action `json:"actions"`
	NotDecided   []Item   `json:"not_decided,omitempty"`
	NotAnAction  []Item   `json:"not_an_action,omitempty"` // FIX-5: never an action, never a flag
	Notes        []string `json:"notes,omitempty"`
	Loop         []string `json:"loop,omitempty"`
}

// Action is one offered entry, as it applies to this report.
type Action struct {
	Rank           int      `json:"rank"`
	ID             string   `json:"id"`
	Title          string   `json:"title"`
	Findings       []string `json:"findings,omitempty"`       // its red triggers
	Unknowns       []string `json:"unknowns,omitempty"`       // FIX-2's capability unknowns (run-as-user)
	MayAlsoClear   []string `json:"may_also_clear,omitempty"` // FIX-3: side effects; never rank, greens or another's action
	CouldTurnGreen []string `json:"could_turn_green"`         // categories, with After's checks when that one is offered too
	After          string   `json:"after,omitempty"`          // proven with this action in place, and offered here
	Proven         bool     `json:"platform_tested"`          // a rerun tested its snippet on this platform (FIX-3)
	Apply          []string `json:"apply,omitempty"`
	Proof          string   `json:"proof,omitempty"`
	Costs          []string `json:"costs,omitempty"`
	General        []Advice `json:"general_advice,omitempty"`
	Prediction     string   `json:"prediction"`
}

// Advice is one catalog fix sentence and the checks it is for.
type Advice struct {
	Checks []string `json:"checks"`
	Text   string   `json:"text"`
}

// Item is something no setting here decides (FIX-2), by check ID or category name, with fixed text.
type Item struct {
	Check    string `json:"check,omitempty"`
	Category string `json:"category,omitempty"`
	Why      string `json:"why"`
}

// Build is FIX-1 to FIX-7 for a structurally valid saved report. runProvider is the report's provider when it is in
// the fixed list, else "other"; platform is the platform's name from that list, or "" when it is unknown. Both come
// from the caller's fixed list, never straight from the report.
func Build(d report.Doc, runProvider, platform string) Plan {
	p := Plan{Schema: Schema, Verification: "structural_only_unauthenticated", Note: report.SavedNote,
		Platform: platform, Actions: []Action{}, Unknown: []string{}}
	if platform == "" {
		p.Platform = "unknown"
	}
	card := report.Score(d)
	p.Valid, p.Score, p.Of = card.Valid, card.Score, card.Of
	p.Complete = card.Valid && d.Grade.Complete
	for _, id := range d.Grade.Unknown { // catalog IDs only (FIX-8); ANL-1 already refused any other
		if _, ok := catalog.Get(id); ok {
			p.Unknown = append(p.Unknown, id)
		}
	}
	if !card.Valid {
		p.Notes = []string{"The run is invalid, so it says nothing about the box and there is nothing to fix (GRD-5): run it again."}
		return p
	}
	found, unknown := map[string]bool{}, map[string]bool{}
	for _, r := range card.Rows {
		for _, id := range r.Found {
			found[id] = true
		}
		for _, id := range r.Unknown {
			unknown[id] = true
		}
	}
	twn4 := map[string]bool{} // FIX-2: unknown while the agent holds a power TWN-4 names, from structured data only
	if held, ok := heldCaps(d.Identity); ok && found["AMP-2"] {
		for id := range unknown {
			if c, ok := catalog.Get(id); ok && held&powers[c.Mechanism] != 0 {
				twn4[id] = true
			}
		}
	}

	// Offer each entry whose trigger is found, with what it addresses here (FIX-3). A snippet's side effects are kept
	// apart: they never count, and never take anything from another action.
	type offer struct {
		e        Entry
		snip     Snippet
		proven   bool
		checks   map[string]bool // addressed: red triggers, and capability unknowns for run-as-user
		provenOn map[string]bool // the addressed checks its snippet proved
		sides    map[string]bool // red checks its snippet's rerun also cleared, beyond its triggers
	}
	var offers []*offer
	for _, e := range Table {
		if !slices.ContainsFunc(e.Triggers, func(id string) bool { return found[id] }) {
			continue
		}
		o := &offer{e: e, checks: map[string]bool{}, provenOn: map[string]bool{}, sides: map[string]bool{}}
		o.snip, o.proven = e.Proven[platform]
		for _, id := range e.Triggers {
			if found[id] {
				o.checks[id] = true
			}
		}
		if o.proven {
			for _, id := range o.snip.Proves {
				switch {
				case !found[id]:
				case o.checks[id]:
					o.provenOn[id] = true
				default:
					o.sides[id] = true
				}
			}
		}
		if e.Unknowns {
			for id := range twn4 {
				o.checks[id] = true
			}
		}
		offers = append(offers, o)
	}
	byID := map[string]*offer{}
	for _, o := range offers {
		byID[o.e.ID] = o
	}

	// Categories each could turn green, with its After's checks when that one is offered too (FIX-6).
	greens := map[string][]string{}
	for _, o := range offers {
		addressed := o.checks
		if a, ok := byID[o.snip.After]; ok && o.proven {
			addressed = map[string]bool{}
			for id := range o.checks {
				addressed[id] = true
			}
			for id := range a.checks {
				addressed[id] = true
			}
		}
		greens[o.e.ID] = []string{}
		for _, r := range card.Rows {
			blockers := append(append([]string{}, r.Found...), r.Unknown...)
			if r.Green || r.NotApplicable || len(blockers) == 0 {
				continue
			}
			if !slices.ContainsFunc(blockers, func(id string) bool { return !addressed[id] }) &&
				slices.ContainsFunc(blockers, func(id string) bool { return o.checks[id] }) {
				greens[o.e.ID] = append(greens[o.e.ID], r.Name)
			}
		}
	}
	order := map[string]int{}
	for i, e := range Table {
		order[e.ID] = i
	}
	sort.SliceStable(offers, func(i, j int) bool {
		a, b := offers[i], offers[j]
		ga, gb := len(greens[a.e.ID]) > 0, len(greens[b.e.ID]) > 0
		switch {
		case ga != gb:
			return ga
		case len(a.checks) != len(b.checks):
			return len(a.checks) > len(b.checks)
		case len(greens[a.e.ID]) != len(greens[b.e.ID]):
			return len(greens[a.e.ID]) > len(greens[b.e.ID])
		}
		return order[a.e.ID] < order[b.e.ID]
	})
	// An action proven only with another in place moves to just after it (FIX-6).
	for moved := true; moved; {
		moved = false
		for i, o := range offers {
			if !o.proven || o.snip.After == "" {
				continue
			}
			j := slices.IndexFunc(offers, func(x *offer) bool { return x.e.ID == o.snip.After })
			if j > i {
				offers = slices.Delete(offers, i, i+1)
				offers = slices.Insert(offers, j, o)
				moved = true
				break
			}
		}
	}

	for i, o := range offers {
		a := Action{Rank: i + 1, ID: o.e.ID, Title: o.e.Title, CouldTurnGreen: greens[o.e.ID], Proven: o.proven,
			Prediction: Prediction}
		for _, id := range catalog.IDs() { // catalog order, so the output is stable
			switch {
			case o.sides[id]:
				a.MayAlsoClear = append(a.MayAlsoClear, id)
			case !o.checks[id]:
			case found[id]:
				a.Findings = append(a.Findings, id)
			default:
				a.Unknowns = append(a.Unknowns, id)
			}
		}
		if _, ok := byID[o.snip.After]; ok && o.proven {
			a.After = o.snip.After
		}
		if o.proven {
			a.Apply, a.Proof, a.Costs = o.snip.Apply, o.snip.Proof, o.snip.Costs
		}
		for _, id := range a.Findings { // the catalog's own sentence where no rerun proved a setting (FIX-3)
			if o.provenOn[id] {
				continue
			}
			text := catalog.Guide[id].Fix
			if k := slices.IndexFunc(a.General, func(g Advice) bool { return g.Text == text }); k >= 0 {
				a.General[k].Checks = append(a.General[k].Checks, id)
			} else {
				a.General = append(a.General, Advice{Checks: []string{id}, Text: text})
			}
		}
		p.Actions = append(p.Actions, a)
	}

	// What no setting here decides (FIX-2, FIX-5).
	for _, id := range catalog.IDs() {
		switch {
		case !unknown[id] || twn4[id] && byID["run-as-user"] != nil:
		case d.Run.NoCanary && catalog.NeedsCanary(mustGet(id)):
			p.NotDecided = append(p.NotDecided, Item{Check: id, Why: "not tested: the run had no canary; run again without -no-canary to test it (HCN-5)"})
		default:
			p.NotDecided = append(p.NotDecided, Item{Check: id, Why: "unknown: no setting here decides it; a rerun may (sandprobe explain " + id + ")"})
		}
	}
	for _, r := range card.Rows {
		switch {
		case r.Green || r.NotApplicable || len(r.Found)+len(r.Unknown) > 0:
		case r.Name == "Cloud access": // FIX-5: the person's call alone, so never an action and never a flag
			p.NotAnAction = append(p.NotAnAction, Item{Category: r.Name, Why: CloudNotTested})
		default:
			p.NotDecided = append(p.NotDecided, Item{Category: r.Name, Why: "nothing in it was tested in this run, so no setting here can turn it green"})
		}
	}
	if len(p.Actions) == 0 {
		p.Notes = append(p.Notes, "Nothing here for a setting to fix: no check is found above Info.")
		return p
	}
	p.Loop = loop(runProvider)
	return p
}

// capBit is a capability's bit, by its name in catalog.CapNames.
func capBit(name string) uint64 {
	i := slices.Index(catalog.CapNames, name)
	if i < 0 {
		panic("no capability " + name)
	}
	return 1 << i
}

// powers are TWN-4's capabilities that keep a mechanism's refusals from standing, by catalog mechanism (FIX-2).
var powers = func() map[string]uint64 {
	past := capBit("SYS_ADMIN") | capBit("SYS_MODULE") | capBit("SYS_PTRACE") // everywhere
	owner := capBit("CHOWN") | capBit("FOWNER") | capBit("SETUID") | capBit("DAC_OVERRIDE")
	read := past | owner | capBit("DAC_READ_SEARCH") | capBit("SETGID")
	return map[string]uint64{
		"file_read":  read,
		"read_perm":  read,
		"proc_open":  past | capBit("SETUID") | capBit("SETGID"),
		"write_perm": past | owner | capBit("SETGID"),
		"sudo_paths": past,
		"env_names":  0, "net_table": 0, "self_status": 0, "": 0,
	}
}()

// heldCaps is the agent's effective, permitted and ambient capabilities from the report's identity; ok is false when
// there is no identity or a set doesn't parse, and then nothing is decided from it (FIX-2).
func heldCaps(id *obs.Identity) (uint64, bool) {
	if id == nil {
		return 0, false
	}
	var held uint64
	for _, set := range []string{id.CapEff, id.CapPrm, id.CapAmb} {
		v, err := strconv.ParseUint(set, 16, 64)
		if err != nil {
			return 0, false
		}
		held |= v
	}
	return held, true
}

func mustGet(id string) *catalog.Check {
	c, _ := catalog.Get(id)
	return c
}

// CloudNotTested is FIX-5's fixed text for Cloud access left untested by default. It names no flag and no provider.
const CloudNotTested = "not tested: its checks (SEC-4, AMP-7) contact the provider's own endpoints, outside Sandprobe's " +
	"reviewed scope for this run. Only your person decides whether they are tested; an agent never changes the run to clear it."

// Name is a platform's name for text, from the fixed list.
func Name(platform string) string {
	names := map[string]string{"modal": "Modal", "docker": "Docker", "kubernetes": "Kubernetes", "sprites": "Sprites",
		"e2b": "E2B", "daytona": "Daytona", "vercel": "Vercel", "cloudflare": "Cloudflare", "boat": "Boat",
		"baseten": "Baseten", "aws-nitro": "AWS Nitro", "unknown": "an unknown platform", "": "an unknown platform"}
	if n, ok := names[platform]; ok {
		return n
	}
	return platform
}

// loop is FIX-7's next steps, as templates: the report keeps no command of the person's, and its strings are untrusted.
func loop(runProvider string) []string {
	var rerun string
	switch {
	case runProvider == "docker":
		rerun = "sandprobe run docker <image> -as <user> -y -out <next-folder> -- <your docker run options, with the fix>"
	case runProvider == "exec":
		rerun = "sandprobe run exec -as <user> -y -out <next-folder> -- <your command>"
	case recipes.Shipped[runProvider] != "":
		rerun = "sandprobe run " + runProvider + " -as <user> -y -out <next-folder>"
	case runProvider == "other":
		rerun = "sandprobe run <the way you ran it> -y -out <next-folder>"
	default:
		rerun = "sandprobe run " + runProvider + " -y -out <next-folder>"
	}
	again := "sandprobe fix <next-folder>/*.json, with the same flags as this one"
	return []string{
		"Show your person the top action, and apply it to the sandbox's own config or code only with their OK.",
		"Run again into a new folder: " + rerun,
		"Compare the two: sandprobe compare <report.json> <next-folder>/*.json",
		"Then again, until nothing actionable is left or your person stops: " + again,
	}
}
