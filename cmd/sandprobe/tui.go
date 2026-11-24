package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode"

	"sandprobe/internal/catalog"
	"sandprobe/internal/obs"
	"sandprobe/internal/report"
)

// maxTUIWidth is UX-9's 80-column budget for all rendered terminal views.
const maxTUIWidth = 80

// defaultKeyIdleTimeout bounds how long the post-run key bar waits on an untouched TTY before exiting (UX-7, AGT-1).
const (
	defaultKeyIdleTimeout = 15 * time.Second
	activeKeyIdleTimeout  = 2 * time.Minute
)

// termCaps describes the active terminal environment (UX-9, AGT-1).
type termCaps struct {
	tty           bool
	color         bool
	ascii         bool
	reducedMotion bool
	width         int
}

// detectTermCaps inspects stdout and standard terminal environment variables (UX-9).
func detectTermCaps(stdout io.Writer, interactiveTTY bool) termCaps {
	dumb := strings.EqualFold(strings.TrimSpace(os.Getenv("TERM")), "dumb")
	noColor := os.Getenv("NO_COLOR") != "" || dumb
	reduced := os.Getenv("SANDPROBE_REDUCED_MOTION") != "" || dumb
	ascii := isASCIILocale()

	isOutTTY := false
	width := maxTUIWidth
	if f, ok := stdout.(*os.File); ok && isTerminal(f) {
		isOutTTY = true
		if cols, _ := termSize(int(f.Fd())); cols > 0 && cols < maxTUIWidth {
			width = cols
		}
	}
	if width < 40 {
		width = 40
	}
	return termCaps{
		tty:           interactiveTTY && !dumb,
		color:         isOutTTY && !noColor,
		ascii:         ascii,
		reducedMotion: reduced,
		width:         width,
	}
}

func isASCIILocale() bool {
	for _, k := range []string{"LC_ALL", "LC_CTYPE", "LANG"} {
		v := strings.TrimSpace(os.Getenv(k))
		if v == "" {
			continue
		}
		u := strings.ToUpper(v)
		return u == "C" || u == "POSIX" || u == "C.ASCII" || u == "ASCII"
	}
	return false
}

type tuiGlyphs struct {
	brand, sep, bullet  string
	red, green, gnp, na string
	active, done        string
	gnpWords            string
}

func glyphsFor(ascii bool) tuiGlyphs {
	if ascii {
		return tuiGlyphs{
			brand:    "*",
			sep:      ">",
			bullet:   ".",
			red:      "x",
			green:    "+",
			gnp:      "o",
			na:       "-",
			active:   ">",
			done:     "+",
			gnpWords: "GREEN . NOT PROVEN",
		}
	}
	return tuiGlyphs{
		brand:    "◇",
		sep:      "›",
		bullet:   "·",
		red:      "✗",
		green:    "✓",
		gnp:      "◌",
		na:       "–",
		active:   "▸",
		done:     "✓",
		gnpWords: "GREEN · NOT PROVEN",
	}
}

type tuiStyle struct {
	bold, dim, red, green, gnp, amber, cyan, reset string
}

func styleFor(color bool) tuiStyle {
	if !color {
		return tuiStyle{}
	}
	return tuiStyle{
		bold:  "\x1b[1m",
		dim:   "\x1b[2m",
		red:   "\x1b[1;31m",
		green: "\x1b[1;32m",
		gnp:   "\x1b[32m",
		amber: "\x1b[33m",
		cyan:  "\x1b[36m",
		reset: "\x1b[0m",
	}
}

// livePhase names one step in UX-5's plan-derived live progress view.
type livePhase struct {
	ID    string
	Label string
}

// livePhasesFor derives the run's live phases from its adapter and flags (UX-5).
// Providers without a reset never show a reset phase; -no-canary omits canary; exec has no delete.
func livePhasesFor(provider string, noCanary, keepSandbox bool) []livePhase {
	var phases []livePhase
	switch provider {
	case "docker":
		return []livePhase{
			{ID: "network", Label: "network"},
			{ID: "canary", Label: "canary"},
			{ID: "box", Label: "box"},
			{ID: "probe", Label: "probe"},
			{ID: "reset", Label: "reset"},
			{ID: "delete", Label: "delete"},
		}
	case "exec":
		if !noCanary {
			phases = append(phases, livePhase{ID: "canary", Label: "canary"})
		}
		return append(phases,
			livePhase{ID: "preflight", Label: "preflight"},
			livePhase{ID: "probe", Label: "probe"},
			livePhase{ID: "cleanup", Label: "cleanup"},
		)
	case "sprites":
		return []livePhase{
			{ID: "canary", Label: "canary"},
			{ID: "box", Label: "box"},
			{ID: "probe", Label: "probe"},
			{ID: "reset", Label: "reset"},
			{ID: "delete", Label: "delete"},
		}
	default: // aws-nitro, kubernetes/recipes, baseten, e2b, vercel, cloudflare, daytona, boat, exe.dev
		if !noCanary {
			phases = append(phases, livePhase{ID: "canary", Label: "canary"})
		}
		phases = append(phases,
			livePhase{ID: "box", Label: "box"},
			livePhase{ID: "probe", Label: "probe"},
		)
		if provider == "baseten" && keepSandbox {
			phases = append(phases, livePhase{ID: "retain", Label: "retain"})
		} else {
			phases = append(phases, livePhase{ID: "delete", Label: "delete"})
		}
		return phases
	}
}

// liveTracker renders UX-5's live phase block on an interactive TTY stderr, or plain append-only lines otherwise.
type liveTracker struct {
	mu       sync.Mutex
	w        io.Writer
	silent   bool
	inPlace  bool
	caps     termCaps
	provider string
	phases   []livePhase
	current  int
	details  map[string]string
	started  time.Time
	drawn    int
	stopCh   chan struct{}
	doneCh   chan struct{}
	closed   bool
}

func newLive(o opts, stderr io.Writer, provider string, phases []livePhase) *liveTracker {
	lv := &liveTracker{
		w:        stderr,
		silent:   o.json() || stderr == nil,
		provider: provider,
		phases:   phases,
		current:  -1,
		details:  map[string]string{},
		started:  time.Now(),
	}
	if lv.silent {
		return lv
	}
	f, ok := stderr.(*os.File)
	dumb := strings.EqualFold(strings.TrimSpace(os.Getenv("TERM")), "dumb")
	if ok && isTerminal(f) && !dumb && os.Getenv("CI") == "" {
		cols := maxTUIWidth
		if c, _ := termSize(int(f.Fd())); c > 0 && c < maxTUIWidth {
			cols = c
		}
		if cols < 40 {
			cols = 40
		}
		lv.caps = termCaps{
			tty:           true,
			color:         os.Getenv("NO_COLOR") == "",
			ascii:         isASCIILocale(),
			reducedMotion: os.Getenv("SANDPROBE_REDUCED_MOTION") != "",
			width:         cols,
		}
		if !lv.caps.reducedMotion {
			lv.inPlace = true
			lv.stopCh = make(chan struct{})
			lv.doneCh = make(chan struct{})
			go lv.loop()
		}
	}
	return lv
}

func (lv *liveTracker) loop() {
	defer close(lv.doneCh)
	t := time.NewTicker(100 * time.Millisecond)
	defer t.Stop()
	for {
		select {
		case <-lv.stopCh:
			return
		case <-t.C:
			lv.mu.Lock()
			if !lv.closed && lv.current >= 0 {
				lv.redrawLocked()
			}
			lv.mu.Unlock()
		}
	}
}

func (lv *liveTracker) phase(id, format string, a ...any) {
	msg := printable(fmt.Sprintf(format, a...))
	lv.mu.Lock()
	defer lv.mu.Unlock()
	if lv.silent || lv.closed {
		return
	}
	idx := -1
	for i, p := range lv.phases {
		if p.ID == id {
			idx = i
			break
		}
	}
	if idx >= 0 {
		if idx > lv.current {
			lv.current = idx
		}
		lv.details[id] = msg
	}
	if !lv.inPlace {
		g := glyphsFor(lv.caps.ascii)
		fmt.Fprintf(lv.w, "%s %s\n", g.bullet, msg)
		return
	}
	lv.redrawLocked()
}

func (lv *liveTracker) stepFunc(id string) func(string, ...any) {
	return func(format string, a ...any) {
		lv.phase(id, format, a...)
	}
}

func (lv *liveTracker) redrawLocked() {
	g := glyphsFor(lv.caps.ascii)
	st := styleFor(lv.caps.color)
	w := lv.caps.width
	if w <= 0 || w > maxTUIWidth {
		w = maxTUIWidth
	}

	var lines []string
	elapsed := fmt.Sprintf("%02d:%04.1f", int(time.Since(lv.started).Minutes()), time.Since(lv.started).Seconds()-float64(int(time.Since(lv.started).Minutes())*60))
	left := fmt.Sprintf("%s sandprobe  %s", g.brand, printable(lv.provider))
	lines = append(lines, joinLR(left, elapsed, w, st.cyan, st.dim, st.reset))

	for i, p := range lv.phases {
		mark, col := g.bullet, st.dim
		switch {
		case i < lv.current:
			mark, col = g.done, st.green
		case i == lv.current:
			mark, col = g.active, st.cyan
		}
		detail := lv.details[p.ID]
		plainPrefix := fmt.Sprintf("  %s %-10s ", mark, p.Label)
		avail := w - displayWidth(plainPrefix)
		if avail < 10 {
			avail = 10
		}
		detail = clipCols(detail, avail)
		if detail != "" {
			lines = append(lines, fmt.Sprintf("  %s%s %-10s%s %s%s%s", col, mark, p.Label, st.reset, st.dim, detail, st.reset))
		} else {
			lines = append(lines, fmt.Sprintf("  %s%s %-10s%s", col, mark, p.Label, st.reset))
		}
	}

	var out strings.Builder
	if lv.drawn > 0 {
		fmt.Fprintf(&out, "\x1b[%dA", lv.drawn)
	}
	for _, line := range lines {
		out.WriteString("\r\x1b[2K")
		out.WriteString(line)
		out.WriteByte('\n')
	}
	lv.drawn = len(lines)
	_, _ = io.WriteString(lv.w, out.String())
}

func (lv *liveTracker) close(finishAll bool) {
	lv.mu.Lock()
	if lv.closed {
		lv.mu.Unlock()
		return
	}
	lv.closed = true
	inPlace := lv.inPlace
	stopCh := lv.stopCh
	doneCh := lv.doneCh
	lv.mu.Unlock()

	if inPlace && stopCh != nil {
		close(stopCh)
		<-doneCh
		lv.mu.Lock()
		if finishAll && lv.drawn > 0 {
			lv.current = len(lv.phases)
			lv.redrawLocked()
		}
		lv.mu.Unlock()
	}
}

// renderResult renders UX-6's compact score-first result within caps.width (<= 80 columns).
// Every string from the box, CLI or saved report is escaped through printable before styling (UX-6, UX-9).
func renderResult(d report.Doc, base string, cleaned bool, caps termCaps) string {
	w := caps.width
	if w <= 0 || w > maxTUIWidth {
		w = maxTUIWidth
	}
	g := glyphsFor(caps.ascii)
	st := styleFor(caps.color)
	sep := " " + g.bullet + " "

	var b strings.Builder
	b.WriteByte('\n')

	// Header: ◇ sandprobe  provider › box [› uid N]     done in Xs
	prov := printable(d.Run.Provider)
	if prov == "" {
		prov = "sandbox"
	}
	boxLabel := printable(d.Run.Box.Name)
	if boxLabel == "" {
		boxLabel = printable(d.Run.Box.ProviderID)
	}
	headParts := []string{g.brand + " sandprobe  " + prov}
	if boxLabel != "" {
		headParts = append(headParts, boxLabel)
	}
	if d.Identity != nil {
		headParts = append(headParts, fmt.Sprintf("uid %d", d.Identity.UID))
	}
	headLeft := strings.Join(headParts, " "+g.sep+" ")
	headRight := ""
	if d.Run.DurationMS > 0 {
		headRight = fmt.Sprintf("done in %.1fs", float64(d.Run.DurationMS)/1000.0)
	}
	writeHeader(&b, headLeft, headRight, w, st)
	b.WriteByte('\n')

	card := report.Score(d)
	if !d.Grade.Valid || !card.Valid {
		// UX-6, GRD-5: invalid run shows no score, no category rows, and no finding counts.
		fmt.Fprintf(&b, "  %sSCORE none%s  Invalid run\n", st.red, st.reset)
		if d.Grade.Invalid != "" {
			writeWrapped(&b, "  Reason: ", "          ", printable(d.Grade.Invalid), w, st.dim, st.reset)
		} else {
			writeWrapped(&b, "  ", "  ", "The probe's observations could not be verified (GRD-5).", w, st.dim, st.reset)
		}
		b.WriteByte('\n')
		writeCleanupAndReport(&b, d, base, cleaned, w, g, st)
		return b.String()
	}

	// Score headline
	scoreCol := st.red
	if card.Score == card.Of {
		scoreCol = st.green
	} else if !d.Grade.Complete {
		scoreCol = st.amber
	}
	scoreHead := fmt.Sprintf("SCORE %d/%d", card.Score, card.Of)
	scoreRest := fmt.Sprintf("%d of %d categories green", card.Score, card.Of)
	fmt.Fprintf(&b, "  %s%s%s  %s\n", scoreCol, scoreHead, st.reset, scoreRest)

	if !d.Grade.Complete {
		unkMsg := fmt.Sprintf("Incomplete: %d check(s) unknown", len(d.Grade.Unknown))
		if len(d.Grade.Unknown) == 0 {
			unkMsg = "Incomplete: required checks did not finish conclusively"
		}
		writeWrapped(&b, "  ", "  ", unkMsg, w, st.amber, st.reset)
		if d.Run.NoCanary {
			writeWrapped(&b, "  ", "  ", "Run without -no-canary to test exfiltration routes.", w, st.dim, st.reset)
		}
	}
	for _, nc := range card.NotCounted() {
		writeWrapped(&b, "  ", "  ", printable(nc), w, st.dim, st.reset)
	}

	conclusive, graded, total := countCoverage(d, card)
	if total > 0 {
		covLine := fmt.Sprintf("%d/%d checks conclusive%s%d graded%snot a certification", conclusive, total, sep, graded, sep)
		writeWrapped(&b, "  ", "  ", covLine, w, st.dim, st.reset)
	}
	b.WriteByte('\n')

	// Six category rows (SCR-1, SCR-2, UX-6, UX-9): reasons strictly from catalog/fixed labels.
	const rowIndent = "                         " // 25 spaces
	for _, row := range card.Rows {
		switch {
		case row.Green && row.GreenNotProven:
			// Distinct symbol + words so Green · not proven is never mistaken for proven green (SCR-2, UX-9).
			line := fmt.Sprintf("  %s%s %s%s  %s", st.gnp, g.gnp, g.gnpWords, st.reset, printable(row.Name))
			plainLen := 2 + displayWidth(g.gnp) + 1 + displayWidth(g.gnpWords) + 2 + displayWidth(printable(row.Name))
			detail := printable(row.NotProven)
			if detail != "" {
				if plainLen+2+displayWidth(detail) <= w {
					b.WriteString(line + "  " + st.dim + detail + st.reset + "\n")
				} else {
					b.WriteString(line + "\n")
					writeWrapped(&b, rowIndent, rowIndent, detail, w, st.dim, st.reset)
				}
			} else {
				b.WriteString(line + "\n")
			}
		case row.Green:
			detail := "all tested checks proven"
			if row.NotProven != "" {
				detail = printable(row.NotProven)
			}
			prefixPlain := fmt.Sprintf("  %s %-5s  %-13s ", g.green, "GREEN", printable(row.Name))
			prefixStyled := fmt.Sprintf("  %s%s %-5s%s  %-13s ", st.green, g.green, "GREEN", st.reset, printable(row.Name))
			writeStyledPrefixWrapped(&b, prefixPlain, prefixStyled, rowIndent, detail, w, st.dim, st.reset)
		case row.NotApplicable:
			detail := printable(row.Why)
			prefixPlain := fmt.Sprintf("  %s %-5s  %-13s ", g.na, "N/A", printable(row.Name))
			prefixStyled := fmt.Sprintf("  %s%s %-5s%s  %-13s ", st.dim, g.na, "N/A", st.reset, printable(row.Name))
			writeStyledPrefixWrapped(&b, prefixPlain, prefixStyled, rowIndent, detail, w, st.dim, st.reset)
		default:
			detail := printable(row.Why)
			prefixPlain := fmt.Sprintf("  %s %-5s  %-13s ", g.red, "RED", printable(row.Name))
			prefixStyled := fmt.Sprintf("  %s%s %-5s%s  %-13s ", st.red, g.red, "RED", st.reset, printable(row.Name))
			writeStyledPrefixWrapped(&b, prefixPlain, prefixStyled, rowIndent, detail, w, st.red, st.reset)
		}
	}

	// Top chain / finding + canary receipt summary + Fix first (UX-6).
	b.WriteByte('\n')
	switch {
	case len(d.Findings) > 0:
		top := d.Findings[0]
		sev := strings.ToUpper(printable(top.Severity))
		var head, body string
		if strings.HasPrefix(top.ID, "CHN-") {
			kind := "CHAIN " + printable(top.ID)
			if top.Potential {
				kind = "POTENTIAL CHAIN " + printable(top.ID)
			}
			head = kind + sep + sev
			body = report.ChainSentence(top.ID, top.Potential)
			if body == "" {
				body = printable(top.Title)
			} else {
				body = printable(body)
			}
		} else {
			head = "TOP FINDING " + printable(top.ID) + sep + sev
			if top.Gets != "" {
				body = "A hijacked agent " + printable(top.Gets) + "."
			} else {
				body = printable(top.Title)
			}
		}
		writeWrapped(&b, "  ", "  ", head, w, st.red, st.reset)
		writeWrapped(&b, "  ", "  ", body, w, st.bold, st.reset)
		if len(d.Receipts) > 0 {
			writeWrapped(&b, "  Canary receipts: ", "                   ", summarizeReceipts(d.Receipts), w, st.dim, st.reset)
		}
		fix := printable(top.Fix)
		if len(d.Findings) > 1 {
			if fix != "" {
				fix += fmt.Sprintf(" (+%d more findings in report)", len(d.Findings)-1)
			} else {
				fix = fmt.Sprintf("+%d more findings in report", len(d.Findings)-1)
			}
		}
		if fix != "" {
			writeWrapped(&b, "  Fix first: ", "             ", fix, w, "", "")
		}
	case !d.Grade.Complete && len(d.Grade.Unknown) > 0:
		ids := make([]string, 0, len(d.Grade.Unknown))
		for _, id := range d.Grade.Unknown {
			ids = append(ids, printable(id))
		}
		writeWrapped(&b, "  Unknown: ", "           ", strings.Join(ids, ", "), w, st.amber, st.reset)
	default:
		if len(d.Receipts) > 0 {
			writeWrapped(&b, "  Canary receipts: ", "                   ", summarizeReceipts(d.Receipts), w, st.dim, st.reset)
		}
		writeWrapped(&b, "  ", "  ", "No findings across tested checks.", w, st.green, st.reset)
	}

	b.WriteByte('\n')
	writeCleanupAndReport(&b, d, base, cleaned, w, g, st)
	return b.String()
}

func writeCleanupAndReport(b *strings.Builder, d report.Doc, base string, cleaned bool, w int, g tuiGlyphs, st tuiStyle) {
	outcome := printable(d.Cleanup.Outcome)
	if outcome == "" {
		if cleaned {
			outcome = "confirmed clean"
		} else {
			outcome = "deletion could not be confirmed"
		}
	}
	const cleanIndent = "             " // 13 spaces
	if cleaned {
		prefixPlain := fmt.Sprintf("  %s Cleanup  ", g.green)
		prefixStyled := fmt.Sprintf("  %s%s Cleanup%s  ", st.green, g.green, st.reset)
		writeStyledPrefixWrapped(b, prefixPlain, prefixStyled, cleanIndent, outcome, w, st.dim, st.reset)
	} else {
		// OUT-4 / UX-6: loud unconfirmed cleanup warning on exit 7.
		warn := fmt.Sprintf("%s CLEANUP UNCONFIRMED (exit 7)", g.red)
		writeWrapped(b, "  ", "  ", warn, w, st.red, st.reset)
		writeWrapped(b, cleanIndent, cleanIndent, outcome, w, st.red, st.reset)
	}
	if base != "" {
		path := printable(base + ".html")
		prefixPlain := "  Report     "
		prefixStyled := fmt.Sprintf("  %sReport%s     ", st.dim, st.reset)
		writeStyledPrefixWrapped(b, prefixPlain, prefixStyled, cleanIndent, path, w, "", "")
	}
}

func countCoverage(d report.Doc, card report.Card) (conclusive, graded, total int) {
	if card.Coverage != nil && card.Coverage.Checks > 0 {
		for _, r := range card.Rows {
			if r.Coverage != nil {
				graded += r.Coverage.Total - len(r.Coverage.Skipped) - len(r.Coverage.Missing)
			}
		}
		return card.Coverage.Conclusive, graded, card.Coverage.Checks
	}
	total = len(d.Checks)
	for _, c := range d.Checks {
		switch c.Result {
		case obs.Pass, obs.Finding, obs.Absent:
			conclusive++
			graded++
		case obs.ScopedOut, obs.NotFound, obs.Unknown:
			graded++
		}
	}
	return conclusive, graded, total
}

func summarizeReceipts(rs []obs.Receipt) string {
	var routes []string
	seen := map[string]bool{}
	for _, r := range rs {
		k := fmt.Sprintf("%s/%d", printable(r.Proto), r.Port)
		if !seen[k] {
			seen[k] = true
			routes = append(routes, k)
		}
	}
	return fmt.Sprintf("%d (%s)", len(rs), strings.Join(routes, ", "))
}

func writeHeader(b *strings.Builder, left, right string, w int, st tuiStyle) {
	if right == "" {
		writeWrapped(b, "  ", "    ", left, w, st.bold, st.reset)
		return
	}
	if 2+displayWidth(left)+2+displayWidth(right) <= w {
		pad := w - 2 - displayWidth(left) - displayWidth(right)
		fmt.Fprintf(b, "  %s%s%s%s%s%s%s\n", st.bold, left, st.reset, strings.Repeat(" ", pad), st.dim, right, st.reset)
		return
	}
	writeWrapped(b, "  ", "    ", left, w, st.bold, st.reset)
	writeWrapped(b, "    ", "    ", right, w, st.dim, st.reset)
}

func joinLR(left, right string, w int, leftCol, rightCol, reset string) string {
	if right == "" {
		return leftCol + clipCols(left, w) + reset
	}
	availLeft := w - displayWidth(right) - 2
	if availLeft < 12 {
		return leftCol + clipCols(left, w) + reset
	}
	l := clipCols(left, availLeft)
	pad := w - displayWidth(l) - displayWidth(right)
	if pad < 1 {
		pad = 1
	}
	return leftCol + l + reset + strings.Repeat(" ", pad) + rightCol + right + reset
}

func writeStyledPrefixWrapped(b *strings.Builder, prefixPlain, prefixStyled, contIndent, text string, w int, bodyCol, reset string) {
	firstAvail := w - displayWidth(prefixPlain)
	contAvail := w - displayWidth(contIndent)
	if firstAvail < 12 || contAvail < 12 {
		b.WriteString(prefixStyled + bodyCol + text + reset + "\n")
		return
	}
	lines := wrapText(text, firstAvail, contAvail)
	for i, l := range lines {
		if i == 0 {
			b.WriteString(prefixStyled + bodyCol + l + reset + "\n")
		} else {
			b.WriteString(contIndent + bodyCol + l + reset + "\n")
		}
	}
}

func writeWrapped(b *strings.Builder, firstPrefix, contIndent, text string, w int, col, reset string) {
	firstAvail := w - displayWidth(firstPrefix)
	contAvail := w - displayWidth(contIndent)
	if firstAvail < 12 || contAvail < 12 {
		b.WriteString(firstPrefix + col + text + reset + "\n")
		return
	}
	lines := wrapText(text, firstAvail, contAvail)
	for i, l := range lines {
		if i == 0 {
			b.WriteString(firstPrefix + col + l + reset + "\n")
		} else {
			b.WriteString(contIndent + col + l + reset + "\n")
		}
	}
}

// wrapText wraps plain printable text so line 0 fits within firstWidth terminal columns and later lines within nextWidth.
func wrapText(s string, firstWidth, nextWidth int) []string {
	if s == "" {
		return []string{""}
	}
	words := strings.Fields(s)
	if len(words) == 0 {
		return []string{""}
	}
	var lines []string
	limit := firstWidth
	cur := ""
	flush := func() {
		lines = append(lines, cur)
		cur = ""
		limit = nextWidth
	}
	for _, word := range words {
		for displayWidth(word) > limit {
			if cur != "" {
				flush()
			}
			head, rest := splitAtCols(word, limit)
			lines = append(lines, head)
			limit = nextWidth
			word = rest
		}
		if cur == "" {
			cur = word
		} else if displayWidth(cur)+1+displayWidth(word) <= limit {
			cur += " " + word
		} else {
			flush()
			cur = word
		}
	}
	if cur != "" || len(lines) == 0 {
		lines = append(lines, cur)
	}
	return lines
}

// runeCols returns the terminal column width of r (0 for combining/control/format, 2 for East Asian Wide/Fullwidth
// and wide emoji blocks, 1 otherwise).
func runeCols(r rune) int {
	if unicode.Is(unicode.Mn, r) || unicode.Is(unicode.Me, r) || unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
		return 0
	}
	if isWideRune(r) {
		return 2
	}
	return 1
}

func isWideRune(r rune) bool {
	return r >= 0x1100 && (r <= 0x115F ||
		r == 0x2329 || r == 0x232A ||
		(r >= 0x2E80 && r <= 0x303E) ||
		(r >= 0x3040 && r <= 0xA4CF && r != 0x303F) ||
		(r >= 0xAC00 && r <= 0xD7A3) ||
		(r >= 0xF900 && r <= 0xFAFF) ||
		(r >= 0xFE10 && r <= 0xFE19) ||
		(r >= 0xFE30 && r <= 0xFE6F) ||
		(r >= 0xFF00 && r <= 0xFF60) ||
		(r >= 0xFFE0 && r <= 0xFFE6) ||
		(r >= 0x1F300 && r <= 0x1FAFF) ||
		(r >= 0x20000 && r <= 0x3FFFD))
}

func displayWidth(s string) int {
	cols := 0
	for _, r := range s {
		cols += runeCols(r)
	}
	return cols
}

func splitAtCols(s string, maxCols int) (string, string) {
	if maxCols <= 0 {
		return "", s
	}
	cols := 0
	for idx, r := range s {
		w := runeCols(r)
		if cols+w > maxCols {
			if idx == 0 {
				// Single wide rune in a 1-column slot: advance one rune to guarantee progress.
				_, next := splitFirstRune(s)
				return s[:len(s)-len(next)], next
			}
			return s[:idx], s[idx:]
		}
		cols += w
	}
	return s, ""
}

func splitFirstRune(s string) (rune, string) {
	for _, r := range s {
		rs := string(r)
		return r, s[len(rs):]
	}
	return 0, ""
}

func clipCols(s string, max int) string {
	if max <= 0 {
		return ""
	}
	if displayWidth(s) <= max {
		return s
	}
	if max <= 1 {
		h, _ := splitAtCols(s, max)
		return h
	}
	h, _ := splitAtCols(s, max-1)
	return h + "."
}

// shouldInteract gates UX-7's post-run key loop on foreground interactive stdin+stdout TTYs,
// skipping under -o json, TERM=dumb, CI, or SANDPROBE_NO_KEYS (AGT-1).
func shouldInteract(o opts) bool {
	if o.json() || o.stdout != os.Stdout {
		return false
	}
	if strings.EqualFold(strings.TrimSpace(os.Getenv("TERM")), "dumb") {
		return false
	}
	if os.Getenv("CI") != "" || os.Getenv("SANDPROBE_NO_KEYS") != "" {
		return false
	}
	if !isTerminal(os.Stdout) || !isTerminal(os.Stdin) {
		return false
	}
	return isForegroundTTY(int(os.Stdin.Fd()))
}

func keyIdleDuration() time.Duration {
	if raw := strings.TrimSpace(os.Getenv("SANDPROBE_KEY_IDLE_MS")); raw != "" {
		if ms, err := strconv.Atoi(raw); err == nil && ms >= 50 && ms <= 600_000 {
			return time.Duration(ms) * time.Millisecond
		}
	}
	return defaultKeyIdleTimeout
}

type walkerItem struct {
	ID       string
	Severity string
	Title    string
	Detail   string
	Evidence string
	Fix      string
}

func walkerItems(d report.Doc) []walkerItem {
	byID := map[string]report.Check{}
	for _, c := range d.Checks {
		byID[c.ID] = c
	}
	var items []walkerItem
	seen := map[string]bool{}
	for _, f := range d.Findings {
		seen[f.ID] = true
		detail := ""
		if strings.HasPrefix(f.ID, "CHN-") {
			detail = report.ChainSentence(f.ID, f.Potential)
		} else if f.Gets != "" {
			detail = "A hijacked agent " + f.Gets + "."
		}
		ev := ""
		if ck, ok := byID[f.ID]; ok && ck.Evidence != "" {
			ev = ck.Evidence
		} else if len(f.Checks) > 0 {
			ev = "Checks: " + strings.Join(f.Checks, ", ")
		}
		items = append(items, walkerItem{
			ID:       f.ID,
			Severity: strings.ToUpper(f.Severity),
			Title:    f.Title,
			Detail:   detail,
			Evidence: ev,
			Fix:      f.Fix,
		})
	}
	for _, c := range d.Checks {
		if c.Result == obs.Unknown && !seen[c.ID] {
			items = append(items, walkerItem{
				ID:       c.ID,
				Severity: "UNKNOWN",
				Title:    c.Title,
				Detail:   c.Reason,
				Evidence: c.Evidence,
				Fix:      c.Fix,
			})
		}
	}
	return items
}

type walkerHooks struct {
	open func(path string) error
	copy func(text string) error
}

func defaultWalkerHooks() walkerHooks {
	return walkerHooks{
		open: openBrowserFile,
		copy: copyToClipboard,
	}
}

// resolveReportPath resolves a written report path to a verified regular absolute path,
// preventing a relative path beginning with "-" from being parsed as a flag by open or xdg-open.
func resolveReportPath(path string) (string, error) {
	if path == "" {
		return "", errors.New("empty report path")
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	if !filepath.IsAbs(abs) || strings.HasPrefix(abs, "-") {
		return "", errors.New("unsafe report path")
	}
	st, err := os.Stat(abs)
	if err != nil || !st.Mode().IsRegular() {
		return "", errors.New("report is not a regular file")
	}
	return abs, nil
}

func openBrowserFile(path string) error {
	abs, err := resolveReportPath(path)
	if err != nil {
		return err
	}
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", abs)
	default:
		cmd = exec.Command("xdg-open", abs)
	}
	return cmd.Start()
}

func copyToClipboard(text string) error {
	type tool struct {
		name string
		args []string
	}
	var candidates []tool
	if runtime.GOOS == "darwin" {
		candidates = []tool{{name: "pbcopy"}}
	} else {
		candidates = []tool{
			{name: "wl-copy"},
			{name: "xclip", args: []string{"-selection", "clipboard"}},
			{name: "xsel", args: []string{"--clipboard", "--input"}},
		}
	}
	for _, c := range candidates {
		p, err := exec.LookPath(c.name)
		if err != nil {
			continue
		}
		cmd := exec.Command(p, c.args...)
		cmd.Stdin = strings.NewReader(text)
		if err := cmd.Run(); err == nil {
			return nil
		}
	}
	return fmt.Errorf("no clipboard utility available")
}

var errKeyIdleTimeout = errors.New("idle timeout")

type fdKeyReader struct {
	fd          int
	initialIdle time.Duration
	activeIdle  time.Duration
	interacted  bool
	sigCh       chan os.Signal
	suspend     func()
}

func (r *fdKeyReader) Read(p []byte) (int, error) {
	idle := r.initialIdle
	if r.interacted && r.activeIdle > idle {
		idle = r.activeIdle
	}
	deadline := time.Now().Add(idle)
	for {
		select {
		case sig := <-r.sigCh:
			if sig == syscall.SIGTSTP {
				if r.suspend != nil {
					r.suspend()
				}
				deadline = time.Now().Add(idle)
				continue
			}
			if sig == syscall.SIGCONT {
				deadline = time.Now().Add(idle)
				continue
			}
			return 0, io.EOF
		default:
		}
		rem := time.Until(deadline)
		if rem <= 0 {
			return 0, errKeyIdleTimeout
		}
		sliceMS := 100
		if remMS := int(rem.Milliseconds()); remMS < sliceMS {
			if remMS < 1 {
				remMS = 1
			}
			sliceMS = remMS
		}
		ready, hup, err := pollFD(r.fd, sliceMS)
		if err != nil {
			if errors.Is(err, syscall.EINTR) {
				continue
			}
			return 0, err
		}
		if ready {
			n, rerr := syscall.Read(r.fd, p)
			if n > 0 {
				if p[0] == 0x1a { // Ctrl-Z in raw mode (ISIG off)
					if r.suspend != nil {
						r.suspend()
					}
					deadline = time.Now().Add(idle)
					continue
				}
				r.interacted = true
				return n, nil
			}
			if rerr != nil && errors.Is(rerr, syscall.EINTR) {
				continue
			}
			return 0, io.EOF
		}
		if hup {
			return 0, io.EOF
		}
	}
}

func interactResult(o opts, d report.Doc, base string, cleaned bool, caps termCaps) {
	fd := int(os.Stdin.Fd())
	var mu sync.Mutex
	var restore func()
	enterRaw := func() error {
		mu.Lock()
		defer mu.Unlock()
		if restore != nil {
			return nil
		}
		fn, err := makeRaw(fd)
		if err != nil {
			return err
		}
		restore = fn
		return nil
	}
	leaveRaw := func() {
		mu.Lock()
		fn := restore
		restore = nil
		mu.Unlock()
		if fn != nil {
			fn()
		}
	}

	sigCh := make(chan os.Signal, 8)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGINT, syscall.SIGQUIT, syscall.SIGTSTP, syscall.SIGCONT)
	defer func() {
		signal.Stop(sigCh)
		leaveRaw()
	}()
	if err := enterRaw(); err != nil {
		return
	}

	reader := &fdKeyReader{
		fd:          fd,
		initialIdle: keyIdleDuration(),
		activeIdle:  activeKeyIdleTimeout,
		sigCh:       sigCh,
		suspend: func() {
			leaveRaw()
			signal.Reset(syscall.SIGTSTP)
			_ = syscall.Kill(syscall.Getpid(), syscall.SIGTSTP)
			signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGINT, syscall.SIGQUIT, syscall.SIGTSTP, syscall.SIGCONT)
			_ = enterRaw()
		},
	}
	runKeyLoop(reader, o.stdout, d, base, cleaned, caps, defaultWalkerHooks())
}

func runKeyLoop(in io.Reader, out io.Writer, d report.Doc, base string, cleaned bool, caps termCaps, hooks walkerHooks) {
	w := caps.width
	if w <= 0 || w > maxTUIWidth {
		w = maxTUIWidth
	}
	st := styleFor(caps.color)
	items := walkerItems(d)
	htmlPath := base + ".html"

	printBar := func() {
		var bar string
		if len(items) > 0 {
			bar = fmt.Sprintf("[Enter] walk (%d)  [o] open report  [e] explain  [q] quit", len(items))
		} else {
			bar = "[o] open report  [q] quit"
		}
		var sb strings.Builder
		sb.WriteByte('\n')
		writeWrapped(&sb, "  ", "  ", bar, w, st.dim, st.reset)
		_, _ = io.WriteString(out, sb.String())
	}

	idx := -1
	renderItem := func(i int) {
		it := items[i]
		var sb strings.Builder
		sb.WriteByte('\n')
		head := fmt.Sprintf("[%d/%d] %s  %s  %s", i+1, len(items), printable(it.ID), printable(it.Severity), printable(it.Title))
		col := st.red
		if it.Severity == "UNKNOWN" {
			col = st.amber
		}
		writeWrapped(&sb, "  ", "    ", head, w, col, st.reset)
		if it.Detail != "" {
			writeWrapped(&sb, "    ", "    ", printable(it.Detail), w, "", "")
		}
		if it.Evidence != "" {
			writeWrapped(&sb, "    Evidence: ", "              ", printable(it.Evidence), w, st.dim, st.reset)
		}
		if it.Fix != "" {
			writeWrapped(&sb, "    Fix: ", "         ", printable(it.Fix), w, "", "")
		}
		writeWrapped(&sb, "    ", "    ", "[j/k] next/prev  [e] explain  [c] copy fix  [o] open  [b] summary  [q] quit", w, st.dim, st.reset)
		_, _ = io.WriteString(out, sb.String())
	}

	printBar()
	buf := make([]byte, 16)
	for {
		n, err := in.Read(buf)
		if errors.Is(err, errKeyIdleTimeout) {
			var sb strings.Builder
			writeWrapped(&sb, "  ", "  ", "Idle timeout; exiting.", w, st.dim, st.reset)
			_, _ = io.WriteString(out, sb.String())
			return
		}
		if n == 0 || err != nil {
			return
		}
		key := decodeKey(buf[:n])
		switch key {
		case "quit":
			_, _ = io.WriteString(out, "\n")
			return
		case "next":
			if len(items) == 0 {
				continue
			}
			idx = (idx + 1) % len(items)
			renderItem(idx)
		case "prev":
			if len(items) == 0 {
				continue
			}
			if idx <= 0 {
				idx = len(items) - 1
			} else {
				idx--
			}
			renderItem(idx)
		case "open":
			var sb strings.Builder
			if hooks.open != nil {
				absPath, rerr := resolveReportPath(htmlPath)
				if rerr != nil {
					writeWrapped(&sb, "  ", "  ", "Could not open browser; open "+printable(htmlPath), w, st.amber, st.reset)
				} else if err := hooks.open(absPath); err != nil {
					writeWrapped(&sb, "  ", "  ", "Could not open browser; open "+printable(absPath), w, st.amber, st.reset)
				} else {
					writeWrapped(&sb, "  ", "  ", "Opened "+printable(absPath), w, st.dim, st.reset)
				}
			}
			_, _ = io.WriteString(out, sb.String())
		case "copy":
			if len(items) == 0 {
				continue
			}
			target := idx
			if target < 0 {
				target = 0
			}
			fix := items[target].Fix
			var sb strings.Builder
			if fix == "" {
				writeWrapped(&sb, "  ", "  ", "No fix text recorded for "+printable(items[target].ID), w, st.dim, st.reset)
			} else if hooks.copy != nil && hooks.copy(fix) == nil {
				writeWrapped(&sb, "  ", "  ", "Copied fix for "+printable(items[target].ID), w, st.green, st.reset)
			} else {
				writeWrapped(&sb, "  Fix: ", "       ", printable(fix), w, "", "")
			}
			_, _ = io.WriteString(out, sb.String())
		case "explain":
			if len(items) == 0 {
				var sb strings.Builder
				writeWrapped(&sb, "  ", "  ", "No findings or unknown checks to explain.", w, st.dim, st.reset)
				_, _ = io.WriteString(out, sb.String())
				continue
			}
			target := idx
			if target < 0 {
				target = 0
			}
			_, _ = io.WriteString(out, renderExplainCard(items[target].ID, w, st))
		case "back":
			idx = -1
			_, _ = io.WriteString(out, renderResult(d, base, cleaned, caps))
			printBar()
		}
	}
}

func decodeKey(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	if b[0] == 0x1b {
		if len(b) == 1 {
			return "quit"
		}
		if len(b) >= 3 && b[1] == '[' {
			switch b[2] {
			case 'A', 'D':
				return "prev"
			case 'B', 'C':
				return "next"
			}
		}
		return ""
	}
	switch b[0] {
	case 'q', 'Q', 0x03, 0x04:
		return "quit"
	case '\r', '\n', 'j', 'n':
		return "next"
	case 'k', 'p':
		return "prev"
	case 'o', 'O':
		return "open"
	case 'c', 'C':
		return "copy"
	case 'e', 'E':
		return "explain"
	case 'b', 'B':
		return "back"
	}
	return ""
}

func renderExplainCard(rawID string, w int, st tuiStyle) string {
	var id string
	for k := range catalog.Guide {
		if strings.EqualFold(k, rawID) {
			id = k
			break
		}
	}
	a, ok := catalog.Guide[id]
	if !ok {
		var sb strings.Builder
		writeWrapped(&sb, "  ", "  ", "No catalog guide for "+printable(rawID), w, st.dim, st.reset)
		return sb.String()
	}
	title := chains[id]
	kind := ""
	if ck, ok := catalog.Get(id); ok {
		title = ck.Title
		kind = "two-sided: a pass needs a refusal proven next to an allowed twin"
		if ck.Kind == catalog.FindOnly {
			kind = "find-only: it can find, never prove a refusal"
		}
	}
	var sb strings.Builder
	sb.WriteByte('\n')
	writeWrapped(&sb, "  ", "    ", id+"  "+printable(title), w, st.bold, st.reset)
	if kind != "" {
		writeWrapped(&sb, "    kind:  ", "           ", printable(kind), w, st.dim, st.reset)
	}
	writeWrapped(&sb, "    found: ", "           ", "A hijacked agent "+printable(a.Gets)+".", w, "", "")
	writeWrapped(&sb, "    fix:   ", "           ", printable(a.Fix), w, "", "")
	return sb.String()
}
