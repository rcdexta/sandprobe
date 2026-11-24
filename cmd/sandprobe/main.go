// sandprobe scores how well an AI agent's sandbox contains it. It creates a throwaway box on a provider, runs the
// probe in it as the agent, asks our canary what got out, resets the box, scores the six exposure categories, deletes
// the box, and writes the report as JSON and as a self-contained web page.
//
//	sandprobe providers                  which providers are ready
//	sandprobe plan <provider>            what a run would create, contact, mark and delete
//	sandprobe run <provider> [-y]        the plan, then the probe, reset and delete
//	sandprobe explain <check>            what a check does, what it means, and its fix
//
// Every command takes -o json (AGT-2). Exit codes are OUT-4's.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"sandprobe/internal/report"
	"sandprobe/recipes"
)

// Version is Sandprobe's own version.
const Version = "0.3.0"

// OUT-4's exit codes.
const (
	exitGraded   = 0
	exitUsage    = 2
	exitApproval = 3
	exitLogin    = 4
	exitPartial  = 5 // incomplete or invalid
	exitBelowMin = 6
	exitCleanup  = 7 // a box or volume Sandprobe created isn't confirmed deleted
)

// cliError is AGT-5: a fixed code, what happened, and what to do.
type cliError struct {
	Code    string `json:"error"`
	Message string `json:"message"`
	Fix     string `json:"fix"`
	exit    int
}

func (e *cliError) Error() string { return e.Message }

func fail(code, msg, fix string, exit int) error {
	return &cliError{Code: code, Message: msg, Fix: fix, exit: exit}
}

// opts are the flags every command shares.
type opts struct {
	out    string // text or json
	yes    bool
	stdout io.Writer
}

func (o opts) json() bool { return o.out == "json" }

// tty says whether a person is at the terminal: no animation, prompt or wait otherwise (AGT-1).
func (o opts) tty() bool { return !o.json() && isTerminal(os.Stdout) && isTerminal(os.Stdin) }

func isTerminal(f *os.File) bool {
	st, err := f.Stat()
	return err == nil && st.Mode()&os.ModeCharDevice != 0
}

func (o opts) emit(v any) {
	enc := json.NewEncoder(o.stdout)
	enc.SetIndent("", "  ")
	enc.Encode(v)
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] == "-h" || args[0] == "help" || args[0] == "--help" {
		fmt.Fprintln(stdout, usage)
		return exitGraded
	}
	cmd, rest := args[0], args[1:]
	if cmd == "feedback" { // FBK-1: its own flags
		return feedback(rest, os.Stdin, feedbackTTY(stdout), stdout, stderr)
	}
	if cmd == "fix" { // FIX-1: its own flags
		return fixCmd(rest, stdout, stderr)
	}
	var passthrough []string // PRV-14: docker run options, after "--", passed through unchanged
	for i, a := range rest {
		if a == "--" {
			rest, passthrough = rest[:i], rest[i+1:]
			break
		}
	}
	fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
	fs.SetOutput(stderr)
	o := opts{stdout: stdout}
	fs.StringVar(&o.out, "o", "text", "output: text or json")
	fs.BoolVar(&o.yes, "y", false, "approve the plan: create, reset and delete without asking (AGT-3)")
	var r runFlags
	r.register(fs)
	positional, err := parse(fs, rest)
	if err != nil {
		return reportErr(o, stderr, fail("usage", err.Error(), "sandprobe help", exitUsage))
	}
	given := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { given[f.Name] = true })
	r.outSet = given["out"]
	r.settleCanary(given) // HCN-5: a canary flag beats every SANDPROBE_CANARY* value
	r.providerEndpointsSet = given["provider-endpoints"]
	docker := (cmd == "run" || cmd == "plan") && len(positional) == 2 && positional[0] == "docker"
	execRun := (cmd == "run" || cmd == "plan") && len(positional) == 1 && positional[0] == "exec"
	if given["block-device-path"] && !execRun {
		return reportErr(o, stderr, fail("usage", "-block-device-path applies only to run exec and plan exec", "sandprobe plan exec -block-device-path /dev/workload/data -- <command>", exitUsage))
	}
	if passthrough != nil && !docker && !execRun {
		return reportErr(o, stderr, fail("usage", "what follows -- goes only to run docker (its docker run options) or run exec (your command)", "sandprobe run exec -y -- docker exec -i mybox sh", exitUsage))
	}
	r.dockerOpts = passthrough
	if o.out != "text" && o.out != "json" {
		return reportErr(o, stderr, fail("usage", "-o takes text or json", "sandprobe "+cmd+" -o json", exitUsage))
	}
	if r.noCanary && !((cmd == "run" || cmd == "plan") && len(positional) == 1 && (positional[0] == "exec" || recipes.Shipped[positional[0]] != "")) {
		return reportErr(o, stderr, fail("usage", "-no-canary applies only to run exec, a recipe such as run kubernetes, and their plans", "sandprobe run exec -no-canary -y -- <command>", exitUsage))
	}
	if r.providerEndpointsSet && !((cmd == "run" || cmd == "plan") && len(positional) == 1 && (positional[0] == "exec" || recipes.Shipped[positional[0]] != "")) {
		return reportErr(o, stderr, fail("usage", "-provider-endpoints applies only to run exec, a recipe such as run kubernetes, and their plans: run docker already runs these checks, and a provider's own PRV row decides them (PRV-15)", "sandprobe run exec -provider-endpoints SEC-4,AMP-7 -y -- <command>", exitUsage))
	}
	if r.tlsInsecure && cmd != "canary" {
		return reportErr(o, stderr, fail("usage", "-tls-insecure applies only to canary check", "sandprobe canary check -tls-insecure -canary-url <url> -canary-pin <pin>", exitUsage))
	}
	if r.requireHTTPMarker && cmd != "canary" {
		return reportErr(o, stderr, fail("usage", "-require-http-marker-v1 applies only to canary check", "sandprobe canary check -require-http-marker-v1", exitUsage))
	}
	if r.setup != "" && !((cmd == "run" || cmd == "plan") && len(positional) == 1 && positional[0] == "sprites") {
		return reportErr(o, stderr, fail("usage", "-setup applies only to a Sprites plan or run", "sandprobe run sprites -setup <file> -y", exitUsage))
	}
	if r.keepSandbox && !((cmd == "run" || cmd == "plan") && len(positional) == 1 && positional[0] == "baseten") {
		return reportErr(o, stderr, fail("usage", "-keep-sandbox applies only to Baseten plan/run", "sandprobe plan baseten -keep-sandbox", exitUsage))
	}
	if r.basetenState != "" && !(cmd == "cleanup" && len(positional) == 1 && positional[0] == "baseten") {
		return reportErr(o, stderr, fail("usage", "-baseten-state applies only to Baseten cleanup", "sandprobe cleanup baseten -baseten-state <journal> -y", exitUsage))
	}
	if r.exedevState != "" && !(cmd == "cleanup" && len(positional) == 1 && positional[0] == "exe.dev") {
		return reportErr(o, stderr, fail("usage", "-exedev-state applies only to exe.dev cleanup", "sandprobe cleanup exe.dev -exedev-state <journal> -y", exitUsage))
	}
	var code int
	switch cmd {
	case "version":
		if o.json() {
			o.emit(map[string]string{"version": Version})
		} else {
			fmt.Fprintln(stdout, "sandprobe", Version)
		}
	case "profile", "compare":
		code, err = offline(o, positional, cmd == "compare")
	case "assess":
		code, err = assessSaved(o, positional)
	case "scorecard":
		code, err = scorecard(o, r, positional)
	case "canary":
		code, err = canaryCheck(o, r, positional, r.tlsInsecure)
	case "cleanup":
		if len(positional) == 1 && positional[0] == "exe.dev" {
			code, err = cleanupExedev(o, r, stderr)
		} else {
			code, err = cleanupBaseten(o, r, positional, stderr)
		}
	case "providers":
		err = providers(o, r)
	case "explain":
		err = explain(o, positional)
	case "plan":
		err = plan(o, r, positional)
	case "run":
		code, err = runCmd(o, r, positional, stderr)
	case "poc":
		if pocCmd == nil {
			err = fail("usage", "this build has no poc command: the Modal proof of concept is built only with -tags poc", "make poc", exitUsage)
			break
		}
		code, err = pocCmd(o, r, positional, stderr)
	default:
		err = fail("usage", "no command "+cmd, "sandprobe help", exitUsage)
	}
	if err != nil {
		return reportErr(o, stderr, err)
	}
	return code
}

// parse reads flags wherever they appear among the positional arguments.
func parse(fs *flag.FlagSet, args []string) ([]string, error) {
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		args = fs.Args()
		if len(args) == 0 {
			return pos, nil
		}
		pos, args = append(pos, args[0]), args[1:]
	}
}

// reportErr prints an error the way AGT-5 says, and returns its exit code.
func reportErr(o opts, stderr io.Writer, err error) int {
	var ce *cliError
	if !errors.As(err, &ce) {
		ce = &cliError{Code: "provider_error", Message: err.Error(), Fix: "see the message; nothing was left behind unless it says so", exit: exitPartial}
	}
	if o.json() {
		o.emit(ce)
	} else {
		fmt.Fprintf(stderr, "sandprobe: %s\n  fix: %s\n", ce.Message, ce.Fix)
	}
	return ce.exit
}

const usage = `sandprobe scores how well an AI agent's sandbox contains it across six categories.

  sandprobe providers              which providers are ready, and how to log in to the rest
  sandprobe plan <provider>        what a run would create, contact, mark and delete
  sandprobe run <provider> -y      the plan, then the probe, the reset and the delete
  sandprobe run docker <image> [-as <user>] -y [-- <docker run options>]
                                   grade a throwaway container from a local image (PRV-14)
  sandprobe run exec [-as <user>] -y -- <command that starts sh in the box>
                                   grade a box you already have, through your own command (PRV-15)
  sandprobe run exec -provider-endpoints SEC-4,AMP-7 -y -- <command>
                                   also test cloud access, attesting your provider's terms allow it on your account
  sandprobe run kubernetes [-as <user>] -y
                                   grade a throwaway pod in your cluster, by recipe; set SANDPROBE_KUBE_CONTEXT (PRV-16)
  sandprobe canary check [-canary-url <url> -canary-pin <pin>]
                                   ask the hosted canary, or one you name, for its signed status; reserves nothing
  sandprobe cleanup baseten -baseten-state <journal> -y  verify/delete a retained sandbox
  sandprobe cleanup exe.dev -exedev-state <journal> -y   reconcile a recorded VM
  sandprobe scorecard <report.json>  the six-category score of a saved report; -out <dir> re-renders its page (offline)
  sandprobe profile <report.json>  five-area coverage of a saved report (offline)
  sandprobe assess <report.json> canary-egress-deny-v1  retrospective six-route assessment (offline)
  sandprobe compare <a> <b>        compare saved findings/coverage (offline)
  sandprobe explain <check>        what a check does, what a finding means, and its fix
  sandprobe fix <report.json> [-provider <name>]
                                   a saved report's fixes, ranked, with each platform's proven settings and the
                                   rerun and compare steps; -provider names the platform of a run exec report (offline)
  sandprobe feedback bug|feature|idea -title <one line> -body-file <file or -> [-report <report.json>]
                                   preview a public issue for summationai/sandprobe and get its code; then, only with
                                   your person's yes, the same command with -confirm <code> files exactly that (FBK-5)

Flags: -o json for agents (AGT-2); -y to approve the plan; -out <dir> for the reports;
-min <0..6|full> to exit 6 below a green-category count (category count only, not severity or proof coverage;
use sandprobe compare or -o json for regression gating in CI); -theme graphite|mission; -allow-local-proxy;
SANDPROBE_NO_KEYS=1 to skip post-run keys on an interactive terminal.
Runs use the hosted canary by default; -canary-url <url> -canary-pin <pin> names a public canary you run, and
-canary <state file> an operator canary from deploy/canary.sh, used only when named. A canary flag sets every
SANDPROBE_CANARY* variable aside. run docker always starts its own canary and takes no canary flag.
run exec and recipes also take -no-canary: no test traffic goes to any canary, so Exfiltration isn't tested.
Attested SEC-4 metadata requests and AMP-7's Kubernetes API handshake still happen, and the plan names them;
EGR-3 doesn't run (HCN-5).
run exec also takes repeatable -block-device-path <absolute path> for an existing custom device mount;
AMP-8.blk checks its type and read permission through metadata, never device I/O.
run exec and recipes keep SEC-4, EGR-3, AMP-6 and AMP-7 off, since they contact your provider's own endpoints;
-provider-endpoints <IDs> turns named ones on, each one you attest your provider's terms allow on your account (PRV-15).
Baseten: -keep-sandbox retains a completed sandbox for inspection until one hour after creation.
E2B: -e2b-key-file <private file>; -e2b-python <venv python with e2b==2.63.0>.
Vercel: -vercel-key-file <private file>; explicit -vercel-team team_... -vercel-project prj_....
Providers: sprites, aws-nitro (-variant isolated or network-isolated), baseten, e2b, vercel, cloudflare, boat,
daytona, exe.dev, kubernetes (a recipe). Exit codes: 0 graded, 2 usage, 3 needs approval, 4 needs login,
5 incomplete or invalid, 6 below -min, 7 a box neither deleted nor intentionally retained.`

// pocCmd is the Modal proof of concept, set only in a -tags poc build (SPEC.md, the Modal section; never shipped).
var pocCmd func(o opts, r runFlags, args []string, stderr io.Writer) (int, error)

// parseMin parses OUT-4's -min flag: "" (unset), "0".."6" (minimum green count), or "full" (every applicable category green).
func parseMin(s string) (want int, full bool, ok bool) {
	if s == "" {
		return 0, false, true
	}
	if strings.EqualFold(s, "full") {
		return 0, true, true
	}
	if len(s) == 1 && s[0] >= '0' && s[0] <= '6' {
		return int(s[0] - '0'), false, true
	}
	return 0, false, false
}

func belowMin(c report.Card, min string) bool {
	if min == "" || !c.Valid {
		return false
	}
	want, full, ok := parseMin(min)
	if !ok {
		return false
	}
	if full {
		return c.Score < c.Of
	}
	return c.Score < want
}
