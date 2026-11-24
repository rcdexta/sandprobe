package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"

	"sandprobe/internal/catalog"
	"sandprobe/internal/host"
	"sandprobe/internal/obs"
	"sandprobe/internal/probes"
	"sandprobe/internal/report"
	"sandprobe/recipes"
)

type runFlags struct {
	exedevKeyFile, exedevState                 string
	boatKeyFile                                string
	daytonaKeyFile, daytonaPython              string
	cloudflareSetup                            string
	vercelKeyFile, vercelTeam, vercelProject   string
	e2bKeyFile, e2bPython                      string
	org, canary, outDir, min, theme, variant   string
	basetenKeyFile, basetenTeam, basetenRegion string
	allowLocalProxy                            bool
	outSet                                     bool     // -out was given explicitly (SCR-3: scorecard writes only then)
	as                                         string   // docker: the agent's user in the box (PRV-14)
	setup                                      string   // sprites: the person's setup script (SPR-1)
	dockerOpts                                 []string // docker: run options after "--" (PRV-14); exec: the person's command (PRV-15)
	scratch, canaryURL, canaryPin              string   // exec: the scratch directory (PRV-15); a public canary and its pin (HCN-5)
	tlsInsecure                                bool     // canary check: accept a staging certificate; trust rests on the pin
	noCanary                                   bool     // exec: run without a canary (HCN-5); Exfiltration isn't tested
	providerEndpoints                          string   // exec and recipes: the checks the person attests (PRV-15)
	providerEndpointsSet                       bool     // -provider-endpoints was given, even empty
	canaryFlags                                bool     // -canary, -canary-url or -canary-pin given as a flag (HCN-5)
	keepSandbox                                bool
	basetenState                               string
}

func (r *runFlags) register(fs *flag.FlagSet) {
	fs.StringVar(&r.exedevKeyFile, "exedev-key-file", os.Getenv("SANDPROBE_EXEDEV_KEY_FILE"), "exe.dev owner-only expiring tag-scoped token file")
	fs.StringVar(&r.exedevState, "exedev-state", "", "exe.dev cleanup journal; never adopt by VM name")
	fs.StringVar(&r.boatKeyFile, "boat-key-file", os.Getenv("SANDPROBE_BOAT_KEY_FILE"), "Boat owner-only API key file")
	fs.StringVar(&r.daytonaKeyFile, "daytona-key-file", os.Getenv("SANDPROBE_DAYTONA_KEY_FILE"), "Daytona owner-only API key file")
	fs.StringVar(&r.daytonaPython, "daytona-python", os.Getenv("SANDPROBE_DAYTONA_PYTHON"), "host Python with pinned daytona0.198.0 SDK")
	fs.StringVar(&r.cloudflareSetup, "cloudflare-setup", os.Getenv("SANDPROBE_CLOUDFLARE_SETUP"), "private one-run Cloudflare controller setup journal")
	fs.StringVar(&r.vercelKeyFile, "vercel-key-file", os.Getenv("SANDPROBE_VERCEL_KEY_FILE"), "Vercel owner-only token file")
	fs.StringVar(&r.vercelTeam, "vercel-team", os.Getenv("VERCEL_TEAM_ID"), "explicit Vercel team ID")
	fs.StringVar(&r.vercelProject, "vercel-project", os.Getenv("VERCEL_PROJECT_ID"), "explicit Vercel test project ID")
	fs.StringVar(&r.e2bKeyFile, "e2b-key-file", os.Getenv("SANDPROBE_E2B_KEY_FILE"), "E2B owner-only API key file; never put a key on the command line")
	fs.StringVar(&r.e2bPython, "e2b-python", os.Getenv("SANDPROBE_E2B_PYTHON"), "host Python 3.11+ interpreter with e2b==2.63.0 installed")
	fs.BoolVar(&r.keepSandbox, "keep-sandbox", false, "Baseten only: retain a completed sandbox for inspection; auto-delete one hour after creation")
	fs.StringVar(&r.basetenState, "baseten-state", "", "Baseten cleanup: private lifecycle journal from a prior run")
	fs.StringVar(&r.basetenKeyFile, "baseten-key-file", os.Getenv("SANDPROBE_BASETEN_KEY_FILE"), "Baseten API key file, owner-only; never put a key on the command line")
	fs.StringVar(&r.basetenTeam, "baseten-team", os.Getenv("BASETEN_TEAM_ID"), "Baseten team ID, required when the key can access several teams")
	fs.StringVar(&r.basetenRegion, "baseten-region", os.Getenv("BASETEN_REGION"), "Baseten region; empty uses the provider default")
	fs.StringVar(&r.org, "org", os.Getenv("SANDPROBE_SPRITES_ORG"), "the Sprites org for the throwaway sprite")
	fs.StringVar(&r.canary, "canary", os.Getenv("SANDPROBE_CANARY"), "an operator canary's state file (deploy/canary.sh), used only when named; the hosted canary otherwise (HCN-5)")
	fs.StringVar(&r.outDir, "out", "sandprobe-reports", "where the JSON and web reports go")
	fs.StringVar(&r.min, "min", "", "exit 6 when green categories are below 0..6, or below full (category count only; use compare or -o json to gate severity or proof regressions)")
	fs.StringVar(&r.theme, "theme", "graphite", "the web report's palette: graphite or mission")
	fs.BoolVar(&r.allowLocalProxy, "allow-local-proxy", false, "docker, aws-nitro, and exec or a recipe with -provider-endpoints EGR-3: let EGR-3 use a proxy on the box's own loopback (UX-4); providers that exclude EGR-3 ignore or refuse it")
	fs.StringVar(&r.setup, "setup", "", "sprites: your sandbox's setup script, run once in the new sprite before the checkpoint (SPR-1)")
	fs.StringVar(&r.as, "as", "", "docker and exec: the agent's user in the box (docker default: the image's own user, else root)")
	fs.StringVar(&r.scratch, "scratch", "", "exec: an absolute directory in the box for the probe's scratch (default /tmp)")
	fs.StringVar(&r.canaryURL, "canary-url", os.Getenv("SANDPROBE_CANARY_URL"), "a public canary you run, https://control.<domain>, instead of the hosted one (HCN-5)")
	fs.BoolVar(&r.noCanary, "no-canary", false, "exec and recipes: run without a canary; Exfiltration isn't tested, so the run stays incomplete (HCN-5)")
	fs.StringVar(&r.providerEndpoints, "provider-endpoints", "", "exec and recipes: turn on named checks that contact your provider's own endpoints (SEC-4, EGR-3, AMP-6, AMP-7), attesting your provider's terms allow each on your own account (PRV-15)")
	fs.BoolVar(&r.tlsInsecure, "tls-insecure", false, "canary check only: accept a Let's Encrypt staging certificate; trust still rests on -canary-pin")
	fs.StringVar(&r.canaryPin, "canary-pin", os.Getenv("SANDPROBE_CANARY_PIN"), "that canary's control-key pin, or two comma-separated during a rotation (HCN-1)")
	fs.StringVar(&r.variant, "variant", "isolated", "aws-nitro: isolated, network-isolated, reference-open or reference-network-isolated")
}

// residual is what Sprites leaves that no check can close (PRV-1).
const residual = "Sprites reaches a sprite only by name, for exec, checkpoint, restore, delete and the checkpoint-list reads. " +
	"Each is checked against the recorded ID right before (and each read on both sides), but a name deleted and recreated " +
	"between a check and its call can't be told apart (PRV-1)."

func configDir() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".config", "sandprobe")
}

// spritesHome is the sprite CLI's HOME for Sandprobe's own login, so the user's own sprite config is never touched.
func spritesHome() string { return filepath.Join(configDir(), "sprites") }

var orgLine = regexp.MustCompile(`^\s+\d+\.\s+(\S+)\s*$`)

// spriteOrgs lists the orgs Sandprobe's own sprite login holds.
func spriteOrgs() ([]string, error) {
	if _, err := exec.LookPath("sprite"); err != nil {
		return nil, fail("cli_missing", "the sprite CLI isn't installed", "install it: curl https://sprites.dev/install.sh | bash", exitLogin)
	}
	cmd := exec.Command("sprite", "org", "list")
	cmd.Env = append(os.Environ(), "HOME="+spritesHome())
	out, _ := cmd.Output()
	var orgs []string
	for _, line := range strings.Split(string(out), "\n") {
		if m := orgLine.FindStringSubmatch(line); m != nil {
			orgs = append(orgs, m[1])
		}
	}
	if len(orgs) == 0 {
		return nil, fail("not_logged_in", "Sandprobe has no Sprites login of its own",
			"HOME="+spritesHome()+" sprite auth setup --token <your token>", exitLogin)
	}
	return orgs, nil
}

// resolve settles the org and the canary a run uses (HCN-5), or says how to get them.
func (r *runFlags) resolve() (string, canaryChoice, error) {
	if r.allowLocalProxy { // EGR-3 is always excluded for Sprites (PRV-5), so the flag would ask for a check that never runs
		return "", canaryChoice{}, fail("usage", "-allow-local-proxy has no effect on Sprites: EGR-3 is excluded there (PRV-5)", "sandprobe run sprites -y", exitUsage)
	}
	choice, err := r.chooseCanary()
	if err != nil {
		return "", canaryChoice{}, err
	}
	orgs, err := spriteOrgs()
	if err != nil {
		return "", canaryChoice{}, err
	}
	org := r.org
	switch {
	case org == "" && len(orgs) == 1:
		org = orgs[0]
	case org == "":
		return "", canaryChoice{}, fail("usage", "Sandprobe's Sprites login holds several orgs: "+strings.Join(orgs, ", "), "add -org <one of them>", exitUsage)
	}
	return org, choice, nil
}

// liveCanary loads the operator canary -canary names (deploy/canary.sh), with no network call. A canary-*.state file
// is never found on its own: a forgotten one would send a run to a canary that may be gone (HCN-5).
func (r *runFlags) liveCanary() (*host.SSMCanary, error) {
	state := r.canary
	if state == "" {
		return nil, fail("usage", "no operator canary is named", "-canary <state file> (deploy/canary.sh)", exitUsage)
	}
	c, err := host.LoadSSMCanary(state)
	if err != nil {
		return nil, fail("not_logged_in", err.Error(), "deploy/canary.sh status", exitLogin)
	}
	return c, nil
}

func providers(o opts, r runFlags) error {
	type provider struct {
		Name     string   `json:"name"`
		Ready    bool     `json:"ready"`
		Orgs     []string `json:"orgs,omitempty"`
		Fix      string   `json:"fix,omitempty"`
		Unbuilt  bool     `json:"not_built_yet,omitempty"`
		Canary   string   `json:"canary,omitempty"`
		CanaryOK bool     `json:"canary_ready"`
	}
	sp := provider{Name: "sprites"}
	if orgs, err := spriteOrgs(); err != nil {
		sp.Fix = err.Error() + "; " + err.(*cliError).Fix
	} else {
		sp.Orgs = orgs
	}
	fixOf := func(err error) string {
		if ce, ok := err.(*cliError); ok {
			return ce.Fix
		}
		return err.Error()
	}
	canaryAt, canaryOK, canaryFix := r.canaryReadiness() // every provider's runs share the canary; it needs no provider login
	sp.Canary, sp.CanaryOK = canaryAt, canaryOK
	if sp.Fix == "" {
		sp.Fix = canaryFix
	}
	sp.Ready = len(sp.Orgs) > 0 && sp.CanaryOK
	list := []provider{sp}
	nitro := provider{Name: "aws-nitro", Canary: canaryAt, CanaryOK: canaryOK, Fix: canaryFix}
	if _, _, err := eksTarget(); err != nil {
		nitro.Fix = fixOf(err)
	} else {
		nitro.Ready = nitro.CanaryOK
	}
	list = append(list, nitro)
	bt := provider{Name: "baseten", Canary: canaryAt, CanaryOK: canaryOK, Fix: canaryFix}
	if client, err := basetenClient(r); err != nil {
		bt.Fix = fixOf(err)
	} else {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		err := client.Available(ctx)
		cancel()
		if err != nil {
			bt.Fix = err.Error()
		} else {
			bt.Ready = bt.CanaryOK
		}
	}
	list = append(list, bt)
	ep := provider{Name: "e2b", Canary: canaryAt, CanaryOK: canaryOK, Fix: canaryFix}
	if client, err := e2bClient(r); err != nil {
		ep.Fix = fixOf(err)
	} else {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		err := client.CheckSDK(ctx)
		if err == nil {
			err = client.Available(ctx)
		}
		cancel()
		if err != nil {
			ep.Fix = err.Error()
		} else {
			ep.Ready = ep.CanaryOK
		}
	}
	list = append(list, ep)
	vp := provider{Name: "vercel", Canary: canaryAt, CanaryOK: canaryOK, Fix: canaryFix}
	if client, err := vercelClient(r); err != nil {
		vp.Fix = fixOf(err)
	} else {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		err := client.Available(ctx)
		cancel()
		if err != nil {
			vp.Fix = err.Error()
		} else {
			vp.Ready = vp.CanaryOK
		}
	}
	list = append(list, vp)
	cp := provider{Name: "cloudflare", Canary: canaryAt, CanaryOK: canaryOK, Fix: canaryFix}
	if _, err := host.NewCloudflareBox(r.cloudflareSetup); err != nil {
		cp.Fix = err.Error()
	} else {
		cp.Ready = cp.CanaryOK
	}
	list = append(list, cp)
	bp := provider{Name: "boat", Canary: canaryAt, CanaryOK: canaryOK, Fix: canaryFix}
	if _, e := boatClient(r); e != nil {
		bp.Fix = e.Error()
	} else {
		bp.Ready = bp.CanaryOK
	}
	list = append(list, bp)
	dp := provider{Name: "daytona", Canary: canaryAt, CanaryOK: canaryOK, Fix: canaryFix}
	if _, e := daytonaClient(r); e != nil {
		dp.Fix = e.Error()
	} else {
		dp.Ready = dp.CanaryOK
	}
	list = append(list, dp)
	xp := provider{Name: "exe.dev", Canary: canaryAt, CanaryOK: canaryOK, Fix: canaryFix}
	if _, e := exedevClient(r); e != nil {
		xp.Fix = e.Error()
	} else {
		xp.Ready = xp.CanaryOK
	}
	list = append(list, xp)
	kp := provider{Name: "kubernetes", Canary: canaryAt, CanaryOK: canaryOK, Fix: canaryFix}
	if rc, err := shippedRecipe("kubernetes"); err != nil {
		kp.Fix = fixOf(err)
	} else {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		_, err := rc.Ready(ctx) // RCP-1: kubectl, SANDPROBE_KUBE_CONTEXT, and create, delete and exec allowed there
		cancel()
		if err != nil {
			kp.Fix = err.Error()
		} else {
			kp.Ready = kp.CanaryOK
		}
	}
	list = append(list, kp)
	for _, n := range []string{"modal"} {
		list = append(list, provider{Name: n, Unbuilt: true, Fix: "not built yet"})
	}
	if o.json() {
		o.emit(list)
		return nil
	}
	for _, p := range list {
		state := "ready"
		if !p.Ready {
			state = "not ready: " + p.Fix
		}
		fmt.Fprintf(o.stdout, "%-10s %s\n", p.Name, state)
	}
	return nil
}

// canaryReadiness is what providers says of the canary the runs would use (HCN-5), with no network call: the hosted
// canary or the one -canary-url names, each asked only by a run, or the operator canary -canary names, once its state
// file loads.
func (r runFlags) canaryReadiness() (at string, ok bool, fix string) {
	fixOf := func(err error) string {
		if ce, ok := err.(*cliError); ok {
			return ce.Message + "; " + ce.Fix
		}
		return err.Error()
	}
	choice, err := r.chooseCanary()
	if err != nil {
		return "", false, fixOf(err)
	}
	if choice.state != "" {
		c, err := r.liveCanary()
		if err != nil {
			return "", false, fixOf(err)
		}
		return c.Addr + " (" + c.Dom + "), the operator canary in " + choice.state, true, ""
	}
	if choice.url == hostedCanaryURL {
		return choice.url + ", the hosted canary run by Summation, asked only by a run", true, ""
	}
	return choice.url + ", the public canary you named, asked only by a run", true, ""
}

// planDoc is UX-4's plan for a Sprites run: everything that will be created, contacted, marked and deleted.
type planDoc struct {
	Provider      string   `json:"provider"`
	NeedsApproval bool     `json:"needs_approval,omitempty"`
	Creates       []string `json:"creates"`
	LaunchPath    string   `json:"launch_path"`
	Probe         string   `json:"probe"`
	Markers       string   `json:"markers"`
	Attested      []string `json:"attested,omitempty"` // PRV-15: each check the person attests, before approval (AGT-3)
	Contacts      []string `json:"contacts"`
	BoxNamed      []string `json:"box_named_destinations"`
	OpensReadOnly []string `json:"opens_read_only"`
	Runs          []string `json:"runs"`
	Reset         string   `json:"reset"`
	Deletes       string   `json:"deletes"`
	LocalProxy    string   `json:"local_proxy"`
	Time          string   `json:"time"`
	Residual      string   `json:"residual"`
}

// readSetup reads SPR-1's setup script before any plan is shown. It opens without blocking (so a pipe put at the path
// can't hang the open), then checks the descriptor it opened, not the path: a regular file of 1 byte to 256 KiB, read
// through that bound. It returns exactly the bytes it checked, and their SHA-256.
func readSetup(path string) ([]byte, string, error) {
	bad := fail("usage", "the setup script must be a regular, non-empty file of at most 256 KiB", "sandprobe run sprites -setup <file> -y", exitUsage)
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, "", bad
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() || st.Size() == 0 || st.Size() > 256<<10 {
		return nil, "", bad
	}
	b, err := io.ReadAll(io.LimitReader(f, 256<<10+1))
	if err != nil || len(b) == 0 || len(b) > 256<<10 {
		return nil, "", bad
	}
	h := sha256.Sum256(b)
	return b, hex.EncodeToString(h[:]), nil
}

// sprPlan is the Sprites plan; setupSum is SPR-1's script's SHA-256, or empty with no -setup.
func sprPlan(org string, c canaryChoice, r runFlags, setupSum string) planDoc {
	sec3, _ := catalog.Get("SEC-3")
	creates := []string{"a sprite named sandprobe-<12 hex> in org " + org + ", default settings", "one checkpoint of it, before the probe runs"}
	launch := "sprite exec, as the sprite's default user"
	runs := []string{"sudo -n -l, which runs no command and may be logged"}
	if setupSum != "" { // SPR-1 and SPR-2: what the approval covers
		creates = []string{"a sprite named sandprobe-<12 hex> in org " + org + ", default settings",
			"your setup script " + filepath.Base(r.setup) + " (sha256 " + setupSum + "), run once in it as its default user, before the checkpoint",
			"one checkpoint of it, before the probe runs"}
		launch = "sprite exec, as the sprite's default user; through /usr/local/bin/agent-exec instead if your setup leaves one (SPR-2)"
		runs = append([]string{"your setup script, through sh -s on its standard input; nothing it prints is kept, only its exit code"}, runs...)
	}
	return planDoc{Provider: "sprites",
		Creates:    creates,
		LaunchPath: launch,
		Probe:      "uploaded to /var/tmp/sandprobe-<12 hex>/probe in the sprite, with its scratch directory; both go with the sprite",
		Markers:    "a file .sandprobe-<run id> in the agent's home, its working directory, /, /tmp and /var/lib/docker; they go with the sprite",
		Contacts:   []string{c.describe, "its DNS names, looked up through the box's own resolver"},
		BoxNamed:   []string{"none: SEC-4, EGR-3, AMP-6 and AMP-7 are excluded, since they'd contact a Fly-owned endpoint (PRV-5)"},
		OpensReadOnly: append(append([]string{}, sec3.Targets...),
			"private SSH keys, /run/secrets (four levels deep) and .env files it finds", "/proc/<pid>/environ and /proc/<pid>/mem of other processes"),
		Runs:       runs,
		Reset:      "restore the checkpoint taken before the probe, proven by the restore's own complete event, the same sprite ID and a changed Current checkpoint",
		Deletes:    "the sprite, by name once its ID is checked (Sprites can't delete by ID), and everything in it",
		LocalProxy: "excluded even with -allow-local-proxy",
		Time:       "about 30 seconds (15 to 21 s measured, create to delete, on 10 Nov 2026)",
		Residual:   withRetention(residual, c),
	}
}

// withRetention adds HCN-4's retention to a plan's residual when the run's canary is a public one (HCN-5).
func withRetention(residual string, c canaryChoice) string {
	if c.retainNote == "" {
		return residual
	}
	return residual + " " + c.retainNote
}

func printPlan(w io.Writer, p planDoc) {
	fmt.Fprintf(w, "The plan for %s\n\n", p.Provider)
	line := func(k string, vs ...string) {
		fmt.Fprintf(w, "  %s\n", k)
		for _, v := range vs {
			fmt.Fprintf(w, "    · %s\n", v)
		}
	}
	line("Creates", p.Creates...)
	line("Runs the probe through", p.LaunchPath)
	line("Puts the probe", p.Probe)
	line("Marks", p.Markers)
	if len(p.Attested) > 0 {
		line("Turns on, on your attestation (-provider-endpoints, PRV-15)", p.Attested...)
	}
	line("Contacts", p.Contacts...)
	line("Contacts only what the box names", p.BoxNamed...)
	line("Opens read-only, never reading a value", p.OpensReadOnly...)
	line("Runs", p.Runs...)
	line("Resets", p.Reset)
	line("Deletes", p.Deletes)
	line("Local proxy", p.LocalProxy)
	line("Takes", p.Time)
	line("Leaves", p.Residual)
}

func plan(o opts, r runFlags, args []string) error {
	if len(args) == 1 && args[0] == "exec" {
		_, e := runExec(o, r, true, nil)
		return e
	}
	if len(args) == 1 && recipes.Shipped[args[0]] != "" {
		_, e := runRecipe(o, r, args[0], true, nil)
		return e
	}
	if len(args) == 2 && args[0] == "docker" {
		_, e := runDocker(o, r, args[1], true, nil)
		return e
	}
	if len(args) == 1 && args[0] == "exe.dev" {
		_, e := runExedev(o, r, true, nil)
		return e
	}
	if len(args) == 1 && args[0] == "boat" {
		_, e := runBoat(o, r, true, nil)
		return e
	}
	if len(args) == 1 && args[0] == "daytona" {
		_, e := runDaytona(o, r, true, nil)
		return e
	}
	if len(args) == 1 && args[0] == "cloudflare" {
		_, err := runCloudflare(o, r, true, nil)
		return err
	}
	if len(args) == 1 && args[0] == "vercel" {
		_, err := runVercel(o, r, true, nil)
		return err
	}
	if len(args) == 1 && args[0] == "e2b" {
		_, err := runE2B(o, r, true, nil)
		return err
	}
	if len(args) == 1 && args[0] == "baseten" {
		_, err := runBaseten(o, r, true, nil)
		return err
	}
	if len(args) == 1 && args[0] == "aws-nitro" {
		_, err := runNitro(o, r, true, nil)
		return err
	}
	if len(args) != 1 || args[0] != "sprites" {
		return fail("usage", "plan takes one provider: sprites, aws-nitro, baseten, e2b, vercel or cloudflare (the others aren't built yet)", "sandprobe plan sprites", exitUsage)
	}
	org, choice, err := r.resolve()
	if err != nil {
		return err
	}
	setupSum := ""
	if r.setup != "" {
		if _, setupSum, err = readSetup(r.setup); err != nil {
			return err
		}
	}
	p := sprPlan(org, choice, r, setupSum)
	if o.json() {
		o.emit(p)
	} else {
		printPlan(o.stdout, p)
	}
	return nil
}

func runCmd(o opts, r runFlags, args []string, stderr io.Writer) (int, error) {
	wantMin, fullMin, ok := parseMin(r.min)
	if !ok {
		return 0, fail("usage", "-min takes a score from 0 to 6, or full", "-min 6 or -min full", exitUsage)
	}
	if !fullMin && wantMin == 6 && len(args) > 0 {
		if pol := report.PolicyKinds(args[0]); pol["SEC-4"] == obs.SkipProviderTerms && pol["AMP-7"] == obs.SkipProviderTerms {
			return 0, fail("usage", "-min 6 can never pass on "+args[0]+": Cloud access is not applicable under the provider's terms, so the score is out of 5", "use -min full (every applicable category green) or -min 5", exitUsage)
		}
	}
	if len(args) == 1 && args[0] == "exec" {
		return runExec(o, r, false, stderr)
	}
	if len(args) == 1 && recipes.Shipped[args[0]] != "" {
		return runRecipe(o, r, args[0], false, stderr)
	}
	if len(args) == 2 && args[0] == "docker" {
		return runDocker(o, r, args[1], false, stderr)
	}
	if len(args) == 1 && args[0] == "exe.dev" {
		return runExedev(o, r, false, stderr)
	}
	if len(args) == 1 && args[0] == "boat" {
		return runBoat(o, r, false, stderr)
	}
	if len(args) == 1 && args[0] == "daytona" {
		return runDaytona(o, r, false, stderr)
	}
	if len(args) == 1 && args[0] == "baseten" {
		return runBaseten(o, r, false, stderr)
	}
	if len(args) == 1 && args[0] == "e2b" {
		return runE2B(o, r, false, stderr)
	}
	if len(args) == 1 && args[0] == "cloudflare" {
		return runCloudflare(o, r, false, stderr)
	}
	if len(args) == 1 && args[0] == "vercel" {
		return runVercel(o, r, false, stderr)
	}
	if len(args) == 1 && args[0] == "aws-nitro" {
		return runNitro(o, r, false, stderr)
	}
	if len(args) != 1 || args[0] != "sprites" {
		return 0, fail("usage", "run takes one provider: sprites, aws-nitro, baseten, e2b, vercel or cloudflare (the others aren't built yet)", "sandprobe run sprites -y", exitUsage)
	}
	org, choice, err := r.resolve()
	if err != nil {
		return 0, err
	}
	var setup []byte // SPR-1: read and hashed before the plan, so the approval names exactly what runs
	setupSum := ""
	if r.setup != "" {
		if setup, setupSum, err = readSetup(r.setup); err != nil {
			return 0, err
		}
	}
	p := sprPlan(org, choice, r, setupSum)
	switch {
	case o.yes:
	case o.tty():
		printPlan(o.stdout, p)
		fmt.Fprint(o.stdout, "\nCreate the sprite, run, reset and delete it? [y/N] ")
		answer, _ := bufio.NewReader(os.Stdin).ReadString('\n')
		if a := strings.ToLower(strings.TrimSpace(answer)); a != "y" && a != "yes" {
			return exitApproval, fail("needs_approval", "nothing was created: the plan wasn't approved", "sandprobe run sprites -y", exitApproval)
		}
	default: // AGT-3: outside a terminal, the plan comes back for approval, as the only output, and nothing is created
		p.NeedsApproval = true
		if o.json() {
			o.emit(p)
		} else {
			printPlan(o.stdout, p)
			fmt.Fprintln(stderr, "\nsandprobe: nothing was created. Show your person this plan, then run again with -y.")
		}
		return exitApproval, nil
	}
	bin, sum, err := probes.Probe("amd64") // sprites run on x86_64
	if err != nil {
		return 0, fail("usage", err.Error(), "make", exitUsage)
	}
	lv := newLive(o, stderr, "sprites", livePhasesFor("sprites", false, false))
	defer lv.close(false)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	c, public, err := r.openCanary(ctx, choice, lv.stepFunc("canary")) // HCN-5: proven, and its slot reserved, before the sprite exists
	if err != nil {
		return 0, err
	}
	defer closeCanary(public, stderr)
	start := time.Now()
	lv.phase("box", "creating a sprite in %s", org)
	s, err := host.CreateSprite(ctx, spritesHome(), org)
	var run *host.Run
	cleanup, cleaned := "the sprite was destroyed, the provider confirming it gone", true
	teardown := func() {
		tctx, tcancel := context.WithTimeout(context.Background(), 3*time.Minute) // even after Ctrl-C
		defer tcancel()
		lv.phase("delete", "destroying sprite %s", s.Name)
		var terr error
		if run != nil {
			terr = host.Teardown(tctx, run)
		} else {
			terr = s.Destroy(tctx)
		}
		lv.close(terr == nil)
		if terr != nil { // the report gets a fixed sentence; the error, which can carry CLI output, stays on this terminal
			cleanup, cleaned = fmt.Sprintf("NOT confirmed deleted: delete sprite %s (%s) in org %s by hand", s.Name, s.SpriteID, org), false
			fmt.Fprintf(stderr, "sandprobe: %s\n  %v\n", cleanup, terr)
		}
	}
	if err != nil {
		teardown()
		return 0, fail("provider_error", err.Error(), "sprite list -o "+org, failExit(cleaned))
	}
	lv.phase("box", "sprite %s (%s); uploading the probe", s.Name, s.SpriteID)
	err = s.Upload(ctx, bin)
	if err == nil && setup != nil {
		lv.phase("box", "running your setup script %s (sha256 %s)", filepath.Base(r.setup), setupSum[:12])
		if err = s.Setup(ctx, setup); err == nil && s.Launcher != "" {
			lv.phase("box", "your setup left the agent's launcher: the probe runs through %s", s.Launcher)
		}
	}
	if err == nil {
		lv.phase("box", "taking a checkpoint")
		err = s.Checkpoint(ctx)
	}
	if err == nil {
		lv.phase("probe", "running the probe as the agent, then the reset and recheck")
		run, err = host.Execute(ctx, s, c, host.Options{Mode: "exec", ProbeSHA256: sum, Excluded: host.SpritesExclusions(), ExcludedKind: obs.SkipProviderTerms})
		if err == nil && lv.inPlace {
			lv.phase("reset", "checkpoint restored and markers rechecked")
		}
	}
	teardown()
	if err != nil {
		return 0, fail("provider_error", err.Error(), "see the message; the sprite's cleanup is above", failExit(cleaned))
	}

	boxName := s.Name
	if setup != nil {
		boxName += " (setup " + filepath.Base(r.setup) + ", sha256 " + setupSum[:12] + ")"
	}
	d := report.Build(run, report.Meta{Version: Version, Provider: "sprites", BoxName: boxName, CreatedBySandprobe: true,
		StartedAt: start, Duration: time.Since(start), Calls: s.Calls, Cleanup: cleanup, Residual: residual})
	return finish(o, r, d, cleaned)
}

// failExit is a failed run's exit code: 7 when the box isn't confirmed deleted, which outranks the failure itself.
func failExit(cleaned bool) int {
	if !cleaned {
		return exitCleanup
	}
	return exitPartial
}

// finish writes both reports, whatever the outcome, prints the result, and picks OUT-4's exit code.
func finish(o opts, r runFlags, d report.Doc, cleaned bool) (int, error) {
	page, err := report.HTML(d, r.theme)
	if err != nil {
		return 0, err
	}
	if err := os.MkdirAll(r.outDir, 0o755); err != nil {
		return 0, err
	}
	base := filepath.Join(r.outDir, "sandprobe-"+d.Run.Provider+"-"+d.Run.ID)
	jb, _ := jsonIndent(d)
	if err := os.WriteFile(base+".json", jb, 0o644); err != nil {
		return 0, err
	}
	if err := os.WriteFile(base+".html", page, 0o644); err != nil {
		return 0, err
	}
	if o.json() {
		o.emit(d)
	} else {
		caps := detectTermCaps(o.stdout, shouldInteract(o))
		fmt.Fprint(o.stdout, renderResult(d, base, cleaned, caps))
		if caps.tty {
			interactResult(o, d, base, cleaned, caps)
		}
	}
	return exitFor(d, cleaned, r.min), nil
}

// exitFor is OUT-4 after a run: 7 over 6, 6 over 5, 5 over 0.
func exitFor(d report.Doc, cleaned bool, min string) int {
	switch {
	case !cleaned:
		return exitCleanup
	case d.Grade.Valid && belowMin(report.Score(d), min):
		return exitBelowMin
	case !d.Grade.Valid || !d.Grade.Complete:
		return exitPartial
	}
	return exitGraded
}
