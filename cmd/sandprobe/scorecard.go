package main

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"unicode"

	"sandprobe/internal/analysis"
	"sandprobe/internal/report"
)

// scorecard is SCR-3 offline: one saved report's headline, and its page re-rendered only when -out is given.
func scorecard(o opts, r runFlags, args []string) (int, error) {
	if len(args) != 1 {
		return 0, fail("usage", "name one saved report file", "sandprobe scorecard <report.json> [-out <dir>]", exitUsage)
	}
	d, err := analysis.Load(args[0])
	if err != nil {
		return 0, fail("report.input", "unsupported, inconsistent or unsafe report input", reportInputFix, exitUsage)
	}
	card := report.Score(*d)
	card.Verification = "structural_only_unauthenticated" // ANL-1: a saved report is never re-verified
	if r.outSet {
		page, err := report.SavedHTML(*d, r.theme)
		if err != nil {
			return 0, err
		}
		if err := writeInside(r.outDir, reportFile(d.Run.Provider, d.Run.ID), page); err != nil {
			return 0, fail("report.output", "couldn't write the page inside "+r.outDir+": "+err.Error(), "choose an -out directory you own", exitUsage)
		}
	}
	if o.json() {
		o.emit(card)
	} else {
		printCard(o, card, d.Statement)
		fmt.Fprintf(o.stdout, "\n%s\n", report.SavedNote)
	}
	if !d.Grade.Valid || !d.Grade.Complete {
		return exitPartial, nil
	}
	return exitGraded, nil
}

// reportInputFix is the fix for a saved report this build refuses (ANL-1): it names the versions this build reads,
// so a report from a newer sandprobe says what it needs (AGT-6).
var reportInputFix = "Use a regular, unedited " + strings.Join(report.Schemas, " or ") + " report file under 8 MiB; a report that declares a later schema needs a newer sandprobe."

// A saved report is unauthenticated input (ANL-1): its provider and run ID name the page only when each is a plain
// name, never a path, and anything else gets a fixed name.
var (
	safeProvider = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,39}(\.[a-z0-9-]{1,20})?$`)
	safeRunID    = regexp.MustCompile(`^r[0-9a-f]{8,64}$`)
)

func reportFile(provider, id string) string {
	if safeProvider.MatchString(provider) && safeRunID.MatchString(id) {
		return "sandprobe-" + provider + "-" + id + ".html"
	}
	return "sandprobe-report.html"
}

// writeInside writes name, a plain file name, inside dir and nowhere else: never through a symlink already there.
func writeInside(dir, name string, data []byte) error {
	if name != filepath.Base(name) || name == "." || name == ".." {
		return fmt.Errorf("not a plain file name")
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	f, err := os.OpenFile(filepath.Join(dir, name), os.O_WRONLY|os.O_CREATE|os.O_TRUNC|syscall.O_NOFOLLOW, 0o644)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// printable is text from a box, CLI argument or saved report made safe for a terminal: every control character
// (ESC included), Unicode format character (category Cf: bidi overrides/isolates, ALM, zero-width, BOM) and line or
// paragraph separator is shown escaped, so untrusted text cannot move the cursor, recolor, reorder or hide output.
func printable(s string) string {
	var b strings.Builder
	for _, r := range s {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || unicode.Is(unicode.Zl, r) || unicode.Is(unicode.Zp, r) {
			if r <= 0xFFFF {
				fmt.Fprintf(&b, "\\u%04x", r)
			} else {
				fmt.Fprintf(&b, "\\U%08x", r)
			}
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// printCard writes the headline: the score, then one line per category, green, green not proven, red or not applicable (SCR-2).
func printCard(o opts, c report.Card, statement string) {
	caps := detectTermCaps(o.stdout, false)
	st := styleFor(caps.color)
	g := glyphsFor(caps.ascii)
	w := o.stdout
	if !c.Valid {
		fmt.Fprintf(w, "\nScore: none (invalid run)\n")
		return
	}
	fmt.Fprintf(w, "\nScore %d/%d\n", c.Score, c.Of)
	for _, line := range c.NotCounted() {
		fmt.Fprintln(w, printable(line))
	}
	fmt.Fprintln(w)
	if c.Coverage != nil {
		fmt.Fprintln(w, c.Coverage.Description())
	}
	for _, row := range c.Rows {
		dot, mark, color := "●", "RED  ", st.red
		if caps.ascii {
			dot = g.red
		}
		switch {
		case row.Green && row.GreenNotProven: // SCR-2, UX-9: distinct symbol and words from proven green
			dot, mark, color = g.gnp, g.gnpWords, st.gnp
		case row.Green:
			if caps.ascii {
				dot = g.green
			}
			mark, color = "GREEN", st.green
		case row.NotApplicable: // SCR-2: never green, and out of the score
			if caps.ascii {
				dot = g.na
			}
			mark, color = "N/A  ", ""
		}
		fmt.Fprintf(w, "  %s%s %s%s  %-13s %s\n", color, dot, mark, st.reset, printable(row.Name), printable(row.Question))
		if row.Why != "" { // a not-applicable reason is the report's own skip reason: escaped like its other text
			fmt.Fprintf(w, "  %-22s %s%s%s\n", "", color, printable(row.Why), st.reset)
		}
		if row.NotProven != "" {
			fmt.Fprintf(w, "  %-22s %s\n", "", printable(row.NotProven))
		}
		if row.Coverage != nil {
			fmt.Fprintf(w, "  %-22s %s\n", "", printable(row.Coverage.Description()))
		}
	}
	if statement != "" {
		fmt.Fprintf(w, "\n%s\n", printable(statement))
	}
}
