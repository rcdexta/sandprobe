package main

import (
	"flag"
	"fmt"
	"io"
	"slices"
	"strings"

	"sandprobe/internal/analysis"
	"sandprobe/internal/fix"
)

const fixUsage = "sandprobe fix <report.json> [-provider <name>] [-o json]"

// fixCmd is FIX-1: a saved report's red checks as ranked actions, offline. It has its own flags, like feedback.
func fixCmd(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("fix", flag.ContinueOnError)
	fs.SetOutput(stderr)
	o := opts{stdout: stdout}
	var provider string
	fs.StringVar(&o.out, "o", "text", "output: text or json")
	fs.StringVar(&provider, "provider", "", "run exec reports only: the platform the box runs on, such as modal or docker (FIX-4)")
	positional, err := parse(fs, args)
	if err != nil {
		return reportErr(o, stderr, fail("usage", err.Error(), fixUsage, exitUsage))
	}
	if o.out != "text" && o.out != "json" {
		return reportErr(o, stderr, fail("usage", "-o takes text or json", fixUsage, exitUsage))
	}
	if len(positional) != 1 {
		return reportErr(o, stderr, fail("usage", "name one saved report file", fixUsage, exitUsage))
	}
	known := feedbackProviders() // FBK-1's fixed list (FIX-4)
	if provider != "" && (!known[provider] || provider == "exec") {
		var names []string
		for n := range known {
			if n != "exec" {
				names = append(names, n)
			}
		}
		slices.Sort(names)
		return reportErr(o, stderr, fail("usage", "-provider takes one of: "+strings.Join(names, ", "), fixUsage, exitUsage))
	}
	d, err := analysis.Load(positional[0])
	if err != nil {
		return reportErr(o, stderr, fail("report.input", "unsupported, inconsistent or unsafe report input", reportInputFix, exitUsage))
	}
	runProvider, platform := "other", ""
	if known[d.Run.Provider] { // a platform only by matching the fixed list, never the report's word (FIX-8)
		runProvider = d.Run.Provider
	}
	switch {
	case provider != "" && runProvider != "exec":
		return reportErr(o, stderr, fail("usage", "-provider applies only to a run exec report: this report's own provider sets the platform",
			"sandprobe fix <report.json>", exitUsage))
	case runProvider == "exec":
		platform = provider
	case runProvider != "other":
		platform = runProvider
	}
	p := fix.Build(*d, runProvider, platform)
	if o.json() {
		o.emit(p)
	} else {
		printFix(o.stdout, p)
	}
	if !p.Valid {
		return exitPartial
	}
	return exitGraded
}

// printFix is FIX-1's text: every line from the plan, which holds only fixed text and catalog IDs (FIX-8), still
// escaped and wrapped at 80 columns (UX-9).
func printFix(w io.Writer, p fix.Plan) {
	var b strings.Builder
	line := func(first, rest, text string) { writeWrapped(&b, first, rest, printable(text), maxTUIWidth, "", "") }
	if !p.Valid {
		line("", "", "Score: none (invalid run)")
	} else {
		line("", "", fmt.Sprintf("Score %d/%d. Fixes for %s, most effective first.", p.Score, p.Of, fix.Name(p.Platform)))
	}
	if len(p.Actions) > 0 {
		line("", "", "Each one is a prediction: its checks "+fix.Prediction+".")
	}
	for _, a := range p.Actions {
		b.WriteByte('\n')
		num := fmt.Sprintf("%d. ", a.Rank)
		line(num, "   ", a.ID+": "+a.Title)
		const in = "   "
		if len(a.Findings) > 0 {
			line(in+"Found: ", in+"       ", strings.Join(a.Findings, ", "))
		}
		if len(a.Unknowns) > 0 {
			line(in+"Unknown only because of root's capabilities: ", in+"  ", strings.Join(a.Unknowns, ", "))
		}
		if len(a.CouldTurnGreen) > 0 {
			green := strings.Join(a.CouldTurnGreen, ", ")
			if a.After != "" {
				green += " (with " + a.After + ")"
			}
			line(in+"Could turn green: ", in+"  ", green)
		}
		if a.After != "" {
			line(in, in, "Proven with "+a.After+" in place: apply that one first.")
		}
		if a.Proven {
			line(in, in, "Apply (proven on "+fix.Name(p.Platform)+"):")
			for _, s := range a.Apply {
				line(in+"  ", in+"    ", s)
			}
			for _, c := range a.Costs {
				line(in+"Cost: ", in+"  ", c)
			}
			line(in+"Proof: ", in+"  ", a.Proof)
		}
		if len(a.General) > 0 {
			line(in, in, fix.GeneralAdvice+":")
			for _, g := range a.General {
				line(in+"  "+strings.Join(g.Checks, ", ")+": ", in+"    ", g.Text)
			}
		}
	}
	if len(p.NotDecided) > 0 {
		b.WriteByte('\n')
		line("", "", "Not decided by a setting:")
		for _, it := range p.NotDecided {
			name := it.Check
			if name == "" {
				name = it.Category
			}
			line("  "+name+": ", "    ", it.Why)
		}
	}
	if len(p.NotAnAction) > 0 {
		b.WriteByte('\n')
		line("", "", "Not an action for an agent:")
		for _, it := range p.NotAnAction {
			line("  "+it.Category+": ", "    ", it.Why)
		}
	}
	for _, n := range p.Notes {
		b.WriteByte('\n')
		line("", "", n)
	}
	if len(p.Loop) > 0 {
		b.WriteByte('\n')
		line("", "", "Next:")
		for i, s := range p.Loop {
			line(fmt.Sprintf("  %d. ", i+1), "     ", s)
		}
	}
	b.WriteByte('\n')
	line("", "", p.Note)
	_, _ = io.WriteString(w, b.String())
}

// fixLoopLine is UX-6's fixed last line of Fix first: where every fix is, in order (FIX-1).
const fixLoopLine = "Run sandprobe fix <report.json> for every fix, in order."
