package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"unicode"

	"sandprobe/internal/catalog"
	"sandprobe/internal/host"
	"sandprobe/internal/obs"
	"sandprobe/internal/report"
)

var ansiSGR = regexp.MustCompile(`\x1b\[[0-9;]*m`)
var letterGradePattern = regexp.MustCompile(`(?i)\bgrade\s+[ABCDF]\b`)

func assertWidthAndNoLetter(t *testing.T, label, rendered string, maxCols int) {
	t.Helper()
	if letterGradePattern.MatchString(rendered) {
		t.Errorf("%s: rendered output mentions a letter grade:\n%s", label, rendered)
	}
	for i, rawLine := range strings.Split(rendered, "\n") {
		plain := ansiSGR.ReplaceAllString(rawLine, "")
		if cols := displayWidth(plain); cols > maxCols {
			t.Errorf("%s: line %d is %d display columns (> %d): %q", label, i+1, cols, maxCols, plain)
		}
	}
}

func loadReportJSON(t *testing.T, path string) report.Doc {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var d report.Doc
	if err := json.Unmarshal(b, &d); err != nil {
		t.Fatal(err)
	}
	return d
}

// UX-6, UX-9, AGT-1: non-TTY result output matches the golden file byte for byte, carries zero ANSI escapes,
// zero key bar, and no letter grade, with every line <= 80 columns.
func TestResultGoldenNonTTY(t *testing.T) {
	vibe := loadReportJSON(t, "../../demo/reports/vibe.json")
	got := renderResult(vibe, "sandprobe-reports/sandprobe-docker-"+vibe.Run.ID, true, termCaps{width: 80})
	if strings.Contains(got, "\x1b") {
		t.Fatalf("non-TTY output contains ESC sequence: %q", got)
	}
	if strings.Contains(got, "[Enter]") || strings.Contains(got, "[q] quit") {
		t.Fatalf("non-TTY output contains interactive key bar:\n%s", got)
	}
	assertWidthAndNoLetter(t, "vibe-golden", got, 80)

	goldenPath := filepath.Join("testdata", "vibe_result.golden")
	if os.Getenv("SANDPROBE_UPDATE_GOLDEN") == "1" {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(goldenPath, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatalf("missing golden file %s: %v", goldenPath, err)
	}
	if got != string(want) {
		t.Fatalf("golden mismatch:\n--- got ---\n%s\n--- want ---\n%s", got, string(want))
	}
}

// UX-6, SCR-2, OUT-4, UX-9: every run state (including wide CJK/emoji box strings) renders accurately and stays <= 80 display columns.
func TestResultStatesAndWidth(t *testing.T) {
	vibe := loadReportJSON(t, "../../demo/reports/vibe.json")
	hardened := loadReportJSON(t, "../../demo/reports/hardened.json")
	canaryDown := loadReportJSON(t, "../../test/reports/canary-down.json")

	noCanary := canaryDown
	noCanary.Run.NoCanary = true

	spritesPath := skipSaved(t, "sprites", host.Options{Excluded: host.SpritesExclusions(), ExcludedKind: obs.SkipProviderTerms})
	spritesDoc := loadReportJSON(t, spritesPath)

	cleanAllProven := doc("A", true, true)
	cleanAllProven.Run.Box.Name = "sandprobe-clean-box"
	cleanAllProven.Identity = &obs.Identity{UID: 1000}
	cleanAllProven.Cleanup.Outcome = "deleted and confirmed gone"

	wideCJK := cleanAllProven
	wideCJK.Run.Box.Name = "サンドプローブ検証コンテナ名前がとても長いテスト環境🧪🔒サンドプローブ検証コンテナ"
	wideCJK.Cleanup.Outcome = "削除確認済み：コンテナとネットワークおよび一時ボリュームを完全に削除しました"

	invalidDoc := doc("", false, false)
	invalidDoc.Grade.Invalid = "probe SHA-256 mismatch on returned observations"
	invalidDoc.Cleanup.Outcome = "deleted and confirmed gone"

	cases := []struct {
		name     string
		d        report.Doc
		cleaned  bool
		mustHave []string
		forbid   []string
	}{
		{
			name:    "valid 1/6 with chain and receipts",
			d:       vibe,
			cleaned: true,
			mustHave: []string{
				"SCORE 1/6  1 of 6 categories green",
				"✗ RED    Secrets",
				"◌ GREEN · NOT PROVEN  Cloud access",
				"CHAIN CHN-1 · CRITICAL",
				"Canary receipts: 6",
				"Fix first:",
				"✓ Cleanup",
			},
		},
		{
			name:    "clean 6/6 all proven",
			d:       cleanAllProven,
			cleaned: true,
			mustHave: []string{
				"SCORE 6/6  6 of 6 categories green",
				"✓ GREEN  Cloud access",
				"No findings across tested checks.",
			},
			forbid: []string{"GREEN · NOT PROVEN", "✗ RED"},
		},
		{
			name:    "wide CJK and emoji wrap within display column budget",
			d:       wideCJK,
			cleaned: true,
			mustHave: []string{
				"SCORE 6/6  6 of 6 categories green",
				"サンドプローブ",
			},
		},
		{
			name:    "hardened 6/6 with Green not proven Cloud access",
			d:       hardened,
			cleaned: true,
			mustHave: []string{
				"SCORE 6/6  6 of 6 categories green",
				"✓ GREEN  Secrets",
				"◌ GREEN · NOT PROVEN  Cloud access",
				"not proven: cloud metadata credentials",
			},
		},
		{
			name:    "x/5 not applicable provider terms",
			d:       spritesDoc,
			cleaned: true,
			mustHave: []string{
				"SCORE 2/5  2 of 5 categories green",
				"Cloud access isn't counted",
				"– N/A    Cloud access",
			},
		},
		{
			name:    "incomplete canary down",
			d:       canaryDown,
			cleaned: true,
			mustHave: []string{
				"Incomplete:",
				"Couldn't prove:",
			},
		},
		{
			name:    "no-canary incomplete",
			d:       noCanary,
			cleaned: true,
			mustHave: []string{
				"Not tested: run without a canary",
				"Run without -no-canary to test exfiltration routes.",
			},
		},
		{
			name:    "invalid run has no score, rows or counts",
			d:       invalidDoc,
			cleaned: true,
			mustHave: []string{
				"SCORE none  Invalid run",
				"probe SHA-256 mismatch",
				"✓ Cleanup",
			},
			forbid: []string{"categories green", "Secrets", "Exfiltration", "checks conclusive"},
		},
		{
			name:    "unconfirmed cleanup loud warning",
			d:       cleanAllProven,
			cleaned: false,
			mustHave: []string{
				"✗ CLEANUP UNCONFIRMED (exit 7)",
			},
		},
	}

	for _, tc := range cases {
		for _, color := range []bool{false, true} {
			for _, width := range []int{80, 64} {
				got := renderResult(tc.d, "sandprobe-reports/sandprobe-test-r1", tc.cleaned, termCaps{color: color, width: width})
				assertWidthAndNoLetter(t, tc.name, got, width)
				plain := ansiSGR.ReplaceAllString(got, "")
				for _, want := range tc.mustHave {
					if !strings.Contains(plain, want) {
						t.Errorf("%s (color=%v width=%d): missing %q in:\n%s", tc.name, color, width, want, plain)
					}
				}
				for _, bad := range tc.forbid {
					if strings.Contains(plain, bad) {
						t.Errorf("%s (color=%v width=%d): unexpected %q in:\n%s", tc.name, color, width, bad, plain)
					}
				}
			}
		}
	}
}

func assertNoControlOrFormatRunes(t *testing.T, label, s string) {
	t.Helper()
	for _, r := range s {
		if r == '\n' {
			continue
		}
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || unicode.Is(unicode.Zl, r) || unicode.Is(unicode.Zp, r) {
			t.Fatalf("%s: unescaped control/format rune U+%04X in output:\n%q", label, r, s)
		}
	}
}

// UX-6, UX-7, UX-9, SCR-3: hostile control characters, ESC sequences, CR/LF, Unicode line/paragraph separators,
// and category Cf format controls (ALM U+061C, zero-width U+200B, LRM U+200E, RLO U+202E, LRI U+2066, PDI U+2069,
// BOM U+FEFF, and supplemental tag U+E0001) are escaped across result, live phase, invalid reason, and walker paths,
// and category rows carry zero box-controlled strings.
func TestTerminalInjectionEscaped(t *testing.T) {
	cfSet := "\u061c\u200b\u200e\u202e\u2066\u2069\ufeff\U000e0001"
	payload := "evil\x1b[2J\x1b]0;pwned\x07\r\nline2\u2028sep\u2029" + cfSet + "end"

	d := doc("D", true, false)
	d.Run.Provider = "docker\x1b[31m\u202e"
	d.Run.Box.Name = payload
	for i := range d.Checks {
		if d.Checks[i].ID == "SEC-1" {
			d.Checks[i].Title = "BOX-SENTINEL-" + payload
			d.Checks[i].Evidence = "BOX-SENTINEL-" + payload
			d.Checks[i].Reason = "BOX-SENTINEL-" + payload
		}
		if d.Checks[i].ID == "AMP-2" {
			d.Checks[i].Reason = "unk-" + payload
			d.Checks[i].Evidence = "ev-" + payload
		}
	}
	d.Findings = []report.Finding{{
		ID:       "SEC-1",
		Severity: "high\x1b[2J\u202e",
		Title:    payload,
		Gets:     payload,
		Fix:      payload,
	}}
	d.Receipts = []obs.Receipt{{Nonce: "n1", Proto: "tcp\x1b[2J\u202e", Port: 443}}
	d.Cleanup.Outcome = payload

	// 1. Result summary path.
	got := renderResult(d, "sandprobe-reports/out\x1b[2J\u202e", false, termCaps{width: 80})
	assertNoControlOrFormatRunes(t, "renderResult", got)
	for _, want := range []string{`\u001b[2J`, `\u2028`, `\u061c`, `\u200b`, `\u200e`, `\u202e`, `\u2066`, `\u2069`, `\ufeff`, `\U000e0001`} {
		if !strings.Contains(got, want) {
			t.Fatalf("renderResult missing escaped %s:\n%s", want, got)
		}
	}
	for _, line := range strings.Split(got, "\n") {
		if strings.Contains(line, "Secrets") && strings.Contains(line, "BOX-SENTINEL") {
			t.Fatalf("box string leaked into category row: %q", line)
		}
	}

	// 2. Invalid run reason path.
	inv := doc("", false, false)
	inv.Grade.Invalid = payload
	invGot := renderResult(inv, "sandprobe-reports/inv\u202e", true, termCaps{width: 80})
	assertNoControlOrFormatRunes(t, "invalid-renderResult", invGot)
	invJoined := strings.ReplaceAll(invGot, "\n          ", "")
	if !strings.Contains(invJoined, `\u202e`) || !strings.Contains(invJoined, `\u061c`) {
		t.Fatalf("invalid output missing escaped Cf runes:\n%s", invGot)
	}

	// 3. Live phase path.
	var phaseErr bytes.Buffer
	lv := newLive(opts{out: "text"}, &phaseErr, "docker\u202e", livePhasesFor("docker", false, false))
	lv.phase("box", "container %s started", payload)
	lv.close(true)
	assertNoControlOrFormatRunes(t, "livePhase", phaseErr.String())
	if !strings.Contains(phaseErr.String(), `\u202e`) || !strings.Contains(phaseErr.String(), `\ufeff`) {
		t.Fatalf("livePhase missing escaped Cf runes:\n%s", phaseErr.String())
	}

	// 4. Walker path (finding item, unknown item, open error path, and explain lookup).
	var walkOut bytes.Buffer
	runKeyLoop(
		&oneKeyReader{keys: []string{"\n", "j", "e", "o", "q"}},
		&walkOut,
		d,
		"missing-\u202e-report",
		true,
		termCaps{tty: true, width: 80},
		walkerHooks{open: func(string) error { return nil }},
	)
	assertNoControlOrFormatRunes(t, "walker", walkOut.String())
	if !strings.Contains(walkOut.String(), `\u202e`) {
		t.Fatalf("walker output missing escaped RLO:\n%s", walkOut.String())
	}
}

// UX-9: NO_COLOR, TERM=dumb, LC_ALL=C (ASCII), and SANDPROBE_REDUCED_MOTION behave deterministically.
func TestModeTable(t *testing.T) {
	vibe := loadReportJSON(t, "../../demo/reports/vibe.json")

	t.Run("NO_COLOR", func(t *testing.T) {
		t.Setenv("NO_COLOR", "1")
		t.Setenv("TERM", "xterm-256color")
		caps := detectTermCaps(os.Stdout, true)
		if caps.color {
			t.Fatal("NO_COLOR=1 left color enabled")
		}
		got := renderResult(vibe, "out/r", true, caps)
		if strings.Contains(got, "\x1b") {
			t.Fatalf("NO_COLOR output contains ANSI escape: %q", got)
		}
	})

	t.Run("TERM=dumb", func(t *testing.T) {
		t.Setenv("NO_COLOR", "")
		t.Setenv("TERM", "dumb")
		caps := detectTermCaps(os.Stdout, true)
		if caps.color || caps.tty || !caps.reducedMotion {
			t.Fatalf("TERM=dumb caps = %+v, want color=false tty=false reducedMotion=true", caps)
		}
	})

	t.Run("LC_ALL=C ASCII", func(t *testing.T) {
		t.Setenv("LC_ALL", "C")
		caps := detectTermCaps(&bytes.Buffer{}, false)
		if !caps.ascii {
			t.Fatal("LC_ALL=C did not enable ASCII mode")
		}
		got := renderResult(vibe, "out/r", true, caps)
		if !strings.Contains(got, "o GREEN . NOT PROVEN  Cloud access") || !strings.Contains(got, "x RED    Secrets") {
			t.Fatalf("ASCII symbols/words missing:\n%s", got)
		}
		for _, r := range got {
			if r > 127 {
				t.Fatalf("non-ASCII rune %q (U+%04X) in LC_ALL=C output:\n%s", r, r, got)
			}
		}
		var cardOut bytes.Buffer
		printCard(opts{stdout: &cardOut}, report.Score(vibe), "")
		if !strings.Contains(cardOut.String(), "o GREEN . NOT PROVEN  Cloud access") {
			t.Fatalf("printCard ASCII missing GREEN . NOT PROVEN:\n%s", cardOut.String())
		}
		for _, r := range cardOut.String() {
			if r > 127 {
				t.Fatalf("non-ASCII rune %q in printCard LC_ALL=C output", r)
			}
		}
	})

	t.Run("SANDPROBE_REDUCED_MOTION", func(t *testing.T) {
		t.Setenv("SANDPROBE_REDUCED_MOTION", "1")
		caps := detectTermCaps(&bytes.Buffer{}, false)
		if !caps.reducedMotion {
			t.Fatal("SANDPROBE_REDUCED_MOTION=1 did not enable reducedMotion")
		}
	})
}

// UX-5: live phases match each adapter's plan (no reset on Nitro/exec/kubernetes; no canary under -no-canary;
// retain on Baseten -keep-sandbox), and non-TTY stderr writes plain append-only lines with escaped text.
func TestLivePhasesFromPlan(t *testing.T) {
	ids := func(ps []livePhase) []string {
		out := make([]string, len(ps))
		for i, p := range ps {
			out[i] = p.ID
		}
		return out
	}
	cases := []struct {
		provider    string
		noCanary    bool
		keepSandbox bool
		want        []string
	}{
		{"docker", false, false, []string{"network", "canary", "box", "probe", "reset", "delete"}},
		{"sprites", false, false, []string{"canary", "box", "probe", "reset", "delete"}},
		{"aws-nitro", false, false, []string{"canary", "box", "probe", "delete"}},
		{"e2b", false, false, []string{"canary", "box", "probe", "delete"}},
		{"kubernetes", false, false, []string{"canary", "box", "probe", "delete"}},
		{"kubernetes", true, false, []string{"box", "probe", "delete"}},
		{"exec", false, false, []string{"canary", "preflight", "probe", "cleanup"}},
		{"exec", true, false, []string{"preflight", "probe", "cleanup"}},
		{"baseten", false, true, []string{"canary", "box", "probe", "retain"}},
	}
	for _, tc := range cases {
		got := ids(livePhasesFor(tc.provider, tc.noCanary, tc.keepSandbox))
		if !slices.Equal(got, tc.want) {
			t.Errorf("%s (noCanary=%v keep=%v): got %v, want %v", tc.provider, tc.noCanary, tc.keepSandbox, got, tc.want)
		}
	}

	var stderr bytes.Buffer
	lv := newLive(opts{out: "text"}, &stderr, "aws-nitro", livePhasesFor("aws-nitro", false, false))
	lv.phase("box", "pod sandprobe-1\x1b[2J ready")
	lv.close(true)
	if strings.Contains(stderr.String(), "\x1b") || !strings.Contains(stderr.String(), `· pod sandprobe-1\u001b[2J ready`) {
		t.Fatalf("non-TTY liveTracker output unsafe or unexpected: %q", stderr.String())
	}

	var jsonStderr bytes.Buffer
	jlv := newLive(opts{out: "json"}, &jsonStderr, "aws-nitro", livePhasesFor("aws-nitro", false, false))
	jlv.phase("box", "quiet")
	jlv.close(true)
	if jsonStderr.Len() != 0 {
		t.Fatalf("-o json emitted progress on stderr: %q", jsonStderr.String())
	}
}

// UX-7, AGT-1: finish never blocks or reads stdin on non-TTY stdout; runKeyLoop steps through findings,
// explains checks, copies fixes, resolves leading-"-" -out paths to absolute paths before opening, and exits on q/Esc.
func TestWalkerKeysNeverHangNonTTY(t *testing.T) {
	vibe := loadReportJSON(t, "../../demo/reports/vibe.json")
	work := t.TempDir()
	t.Chdir(work)

	// Leading-dash output directory: must never pass a "-" argument to open/xdg-open.
	dashDir := "-dash-out"
	var nonTTYOut bytes.Buffer
	code, err := finish(opts{out: "text", stdout: &nonTTYOut}, runFlags{outDir: dashDir, theme: "graphite"}, vibe, true)
	if err != nil || code != exitGraded {
		t.Fatalf("finish non-TTY: code=%d err=%v", code, err)
	}
	if strings.Contains(nonTTYOut.String(), "[Enter]") {
		t.Fatalf("non-TTY finish printed interactive key bar:\n%s", nonTTYOut.String())
	}

	base := filepath.Join(dashDir, "sandprobe-"+vibe.Run.Provider+"-"+vibe.Run.ID)
	var opened, copied string
	hooks := walkerHooks{
		open: func(p string) error { opened = p; return nil },
		copy: func(s string) error { copied = s; return nil },
	}
	var loopOut bytes.Buffer
	runKeyLoop(&oneKeyReader{keys: []string{"\n", "j", "e", "c", "o", "b", "q"}}, &loopOut, vibe, base, true, termCaps{tty: true, width: 80}, hooks)

	got := loopOut.String()
	assertWidthAndNoLetter(t, "walker", got, 80)
	for _, want := range []string{
		"[Enter] walk (16)",
		"[1/16] CHN-1",
		"[2/16] SEC-1",
		"SEC-1 Secret-shaped names in the agent's environment",
		"Copied fix for SEC-1",
		"Opened",
		"SCORE 1/6",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("walker output missing %q:\n%s", want, got)
		}
	}
	if !filepath.IsAbs(opened) || strings.HasPrefix(opened, "-") || !strings.HasSuffix(opened, filepath.Join("-dash-out", "sandprobe-docker-"+vibe.Run.ID+".html")) {
		t.Fatalf("open hook got non-absolute or unsafe path %q", opened)
	}
	if !strings.Contains(copied, "Keep credentials out of the agent's environment") {
		t.Errorf("copy hook got %q", copied)
	}

	// Esc exits immediately too.
	var escOut bytes.Buffer
	runKeyLoop(&oneKeyReader{keys: []string{"\x1b"}}, &escOut, vibe, base, true, termCaps{tty: true, width: 80}, hooks)
	if !strings.Contains(escOut.String(), "[q] quit") {
		t.Errorf("Esc walker did not render initial bar: %q", escOut.String())
	}
}

type oneKeyReader struct {
	keys []string
	i    int
}

func (r *oneKeyReader) Read(p []byte) (int, error) {
	if r.i >= len(r.keys) {
		return 0, os.ErrClosed
	}
	n := copy(p, r.keys[r.i])
	r.i++
	return n, nil
}

// OUT-4: -min accepts 0..6 and full, enforces 7 > 6 > 5 > 0 exit precedence, and refuses retired letter grades.
func TestMinScoreGate(t *testing.T) {
	fiveOfSix := doc("C", true, true) // 5/6 green
	sixOfSix := doc("A", true, true)  // 6/6 green

	// Build a 5/5 clean Sprites doc (Cloud access not applicable).
	fiveOfFive := doc("A", true, true)
	fiveOfFive.Run.Provider = "sprites"
	fiveOfFive.Manifest.SkipKinds = map[string]string{"SEC-4": obs.SkipProviderTerms, "AMP-7": obs.SkipProviderTerms}
	fiveOfFive.Manifest.Skipped = map[string]string{"SEC-4": "terms", "AMP-7": "terms"}
	for i := range fiveOfFive.Checks {
		if fiveOfFive.Checks[i].ID == "SEC-4" || fiveOfFive.Checks[i].ID == "AMP-7" {
			fiveOfFive.Checks[i].Result = obs.Skipped
			fiveOfFive.Checks[i].Reason = "terms"
		}
	}
	if c := report.Score(fiveOfFive); c.Score != 5 || c.Of != 5 {
		t.Fatalf("fiveOfFive setup: got %d/%d", c.Score, c.Of)
	}

	gateCases := []struct {
		name    string
		d       report.Doc
		cleaned bool
		min     string
		want    int
	}{
		{"5/6 meets -min 5", fiveOfSix, true, "5", exitGraded},
		{"5/6 fails -min 6", fiveOfSix, true, "6", exitBelowMin},
		{"5/6 fails -min full", fiveOfSix, true, "full", exitBelowMin},
		{"6/6 meets -min full", sixOfSix, true, "full", exitGraded},
		{"6/6 meets -min FULL", sixOfSix, true, "FULL", exitGraded},
		{"5/5 meets -min full", fiveOfFive, true, "full", exitGraded},
		{"5/5 fails -min 6 in exitFor", fiveOfFive, true, "6", exitBelowMin},
		{"0/6 meets -min 0", doc("F", true, true), true, "0", exitGraded},
		{"incomplete below -min exits 6 over 5", doc("D", true, false), true, "5", exitBelowMin},
		{"incomplete meeting -min exits 5", doc("C", true, false), true, "3", exitPartial},
		{"invalid never exits 6, exits 5", doc("", false, false), true, "6", exitPartial},
		{"unconfirmed cleanup exits 7 over 6", fiveOfSix, false, "6", exitCleanup},
	}
	for _, tc := range gateCases {
		if got := exitFor(tc.d, tc.cleaned, tc.min); got != tc.want {
			t.Errorf("%s: exitFor = %d, want %d", tc.name, got, tc.want)
		}
	}

	// Retired letters and out-of-range values are refused with usage exit 2 before any provider runs.
	for _, bad := range []string{"A", "B", "C", "D", "F", "a", "-1", "7", "10", "all"} {
		var out, errs bytes.Buffer
		code := run([]string{"run", "docker", "unused-img", "-min", bad, "-o", "json"}, &out, &errs)
		if code != exitUsage || !strings.Contains(out.String(), `"error": "usage"`) || !strings.Contains(out.String(), "-min 6") {
			t.Errorf("-min %q: code=%d out=%s", bad, code, out.String())
		}
	}
	// Ensure every catalog check still maps cleanly in explain cards.
	for _, id := range catalog.IDs() {
		card := renderExplainCard(id, 80, tuiStyle{})
		assertWidthAndNoLetter(t, "explain-"+id, card, 80)
	}
}

// OUT-4: -min 6 is refused up front on 5/5 provider-terms adapters pointing to -min full, and -min is explicitly
// documented/tested as a category-count gate only (same-category severity or proven-to-not_found regressions do not trip it).
func TestMinScoreGateLimitations(t *testing.T) {
	for _, prov := range []string{"sprites", "e2b", "baseten", "daytona", "vercel", "cloudflare", "boat", "exe.dev"} {
		var out, errs bytes.Buffer
		code := run([]string{"run", prov, "-min", "6", "-o", "json"}, &out, &errs)
		if code != exitUsage || !strings.Contains(out.String(), "-min full") {
			t.Errorf("%s -min 6: got code=%d, out=%s", prov, code, out.String())
		}
	}

	// 1. Same-category severity increase (low -> critical inside Privilege) keeps Score 5/6 and exits 0 under -min 5.
	lowPriv := doc("A", true, true)
	critPriv := doc("A", true, true)
	for i := range lowPriv.Checks {
		if lowPriv.Checks[i].ID == "AMP-3" {
			lowPriv.Checks[i].Result = obs.Finding
			lowPriv.Checks[i].Severity = "low"
		}
		if critPriv.Checks[i].ID == "AMP-2" {
			critPriv.Checks[i].Result = obs.Finding
			critPriv.Checks[i].Severity = "critical"
		}
	}
	if report.Score(lowPriv).Score != 5 || report.Score(critPriv).Score != 5 {
		t.Fatal("expected both lowPriv and critPriv to score 5/6")
	}
	if exitFor(lowPriv, true, "5") != exitGraded || exitFor(critPriv, true, "5") != exitGraded {
		t.Fatal("expected -min 5 to treat both 5/6 runs identically regardless of severity inside Privilege")
	}

	// 2. Proven pass degrading to find-only not_found (GREEN -> GREEN · NOT PROVEN) keeps Score 6/6 and exits 0 under -min full.
	provenSix := doc("A", true, true)
	unprovenCloud := doc("A", true, true)
	for i := range unprovenCloud.Checks {
		if unprovenCloud.Checks[i].ID == "SEC-4" || unprovenCloud.Checks[i].ID == "AMP-7" {
			unprovenCloud.Checks[i].Result = obs.NotFound
		}
	}
	sc := report.Score(unprovenCloud)
	if sc.Score != 6 || sc.Of != 6 || !sc.Rows[4].GreenNotProven {
		t.Fatalf("expected 6/6 with Cloud access GreenNotProven, got %d/%d %+v", sc.Score, sc.Of, sc.Rows[4])
	}
	if exitFor(provenSix, true, "full") != exitGraded || exitFor(unprovenCloud, true, "full") != exitGraded {
		t.Fatal("expected -min full to exit 0 for both proven 6/6 and GreenNotProven 6/6")
	}
}
