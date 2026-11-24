package fix

// Entry is one row of the action table (FIX-3): a change a person can make to the sandbox's own config or code, the
// checks whose finding offers it, and, per platform, what a rerun proved it clears there (FIX-4).
type Entry struct {
	ID, Title string
	Triggers  []string           // the checks whose finding offers it; each red-capable check triggers exactly one entry
	Unknowns  bool               // it also addresses TWN-4's unknowns: those only root's capabilities leave undecided
	Proven    map[string]Snippet // platform → what a rerun proved there
}

// Snippet is what a rerun proved on one platform (FIX-4). Only what a rerun showed is here.
type Snippet struct {
	Apply   []string // what to change, one line each
	Proves  []string // the checks the rerun cleared, triggers or not
	After   string   // proven with this entry already in place
	Costs   []string // what it costs, fixed text (FIX-5)
	Proof   string   // where and how a rerun proved it
	Options []string // run docker: exactly the docker run options it adds, which FIX-9 applies
	Image   bool     // run docker: an image change rather than an option, which FIX-9 makes by building a variant
}

const (
	modalRounds = "run exec on Modal, 24 November 2026, one throwaway sandbox per round " +
		"(python:3.12-slim-bookworm, commands through Sandbox.exec)"
	dockerProof = "run docker, alone from a baseline where its checks were red (FIX-9)"
	setpriv     = "setpriv --reuid=1000 --regid=1000 --init-groups --inh-caps=-all --ambient-caps=-all --no-new-privs"
	modelAPI    = "The agent loses its network, its model API included: its model calls must go through something " +
		"outside the box, such as a broker."
	notProven = "DNS (EGR-1) and UDP 53 (EGR-5.53u) then have no receipt, which isn't proof: Exfiltration turns green " +
		"with a \"not proven: DNS, UDP 53\" line."
)

var egress = []string{"EGR-1", "EGR-2", "EGR-5.22", "EGR-5.80", "EGR-5.8080", "EGR-5.53u"}

// Table is FIX-3's one table, in tie-break order (FIX-6).
var Table = []Entry{
	{ID: "run-as-user", Title: "Run the agent as its own unprivileged user, with no capabilities",
		Triggers: []string{"AMP-2"}, Unknowns: true, Proven: map[string]Snippet{
			"modal": {
				Apply: []string{"In the image: useradd -m -u 1000 -s /bin/bash agent",
					"Run the agent's commands through: " + setpriv + " <command>"},
				Proves: []string{"AMP-2", "SEC-3", "SEC-5", "PER-2", "AMP-8.sys"},
				Proof:  modalRounds + ", round 0 to round 1, applied with block-network."},
			"docker": {
				Apply: []string{"docker run options: --user 1000:1000 --cap-drop ALL (1000 is the agent user's uid " +
					"and gid in the test image; use your agent user's), and no --privileged or --cap-add"},
				Proves:  []string{"AMP-2", "SEC-3", "PER-2"},
				Options: []string{"--user", "1000:1000", "--cap-drop", "ALL"},
				Proof:   dockerProof + "; also from a root agent holding CAP_SYS_PTRACE, whose unknowns it decided."},
		}},
	{ID: "no-new-privileges", Title: "Stop the agent gaining privileges from setuid programs",
		Triggers: []string{"AMP-3"}, Proven: map[string]Snippet{
			"docker": {
				Apply:   []string{"docker run option: --security-opt no-new-privileges"},
				Proves:  []string{"AMP-3"},
				Options: []string{"--security-opt", "no-new-privileges"},
				Proof:   dockerProof + "."},
		}},
	{ID: "block-network", Title: "Cut the box off the network", Triggers: egress, Proven: map[string]Snippet{
		"modal": {
			Apply:  []string{"Create the sandbox with modal.Sandbox.create(..., block_network=True)"},
			Proves: egress,
			Costs: []string{modelAPI, notProven, "It is the only egress setting proven on Modal: Modal's domain and " +
				"CIDR allowlists weren't tested in this loop, so fix makes no claim about them."},
			Proof: modalRounds + ", round 0 to round 1, applied with run-as-user."},
		"docker": {
			Apply:   []string{"docker run option: --network none"},
			Proves:  egress,
			Costs:   []string{modelAPI, notProven},
			Options: []string{"--network", "none"},
			Proof:   dockerProof + "."},
	}},
	{ID: "protect-home", Title: "Make the agent's startup files and settings read-only to it",
		Triggers: []string{"PER-1", "PER-2", "PER-3", "PER-4"}, Proven: map[string]Snippet{
			"modal": {
				Apply: []string{"In the image: chown -R root:root /home/agent; chmod 0755 /home/agent; " +
					"mkdir -p /work; chown agent:agent /work",
					"Run the agent's commands with workdir=\"/work\" on exec"},
				Proves: []string{"PER-1", "PER-3", "PER-4"},
				After:  "run-as-user",
				Costs:  []string{"The agent can't change its own dotfiles: its work goes in /work."},
				Proof:  modalRounds + ", round 1 to round 2, applied with clean-env."},
			"docker": {
				Apply:   []string{"docker run options: --read-only --tmpfs /tmp"},
				Proves:  []string{"PER-1", "PER-2", "PER-3", "PER-4"},
				Options: []string{"--read-only", "--tmpfs", "/tmp"},
				Costs: []string{"The whole root filesystem is read-only: the agent writes only to /tmp and to what you " +
					"mount for it, such as a work volume outside its home."},
				Proof: dockerProof + ", as root and as the agent's user."},
		}},
	{ID: "clean-env", Title: "Start the agent with a minimal environment that holds no keys",
		Triggers: []string{"SEC-1"}, Proven: map[string]Snippet{
			"modal": {
				Apply:  []string{"Add --reset-env to the setpriv that runs the agent's commands: " + setpriv + " --reset-env <command>"},
				Proves: []string{"SEC-1"},
				After:  "run-as-user",
				Costs:  []string{"The agent's own variables go too: pass back only what it needs, never a key."},
				Proof:  modalRounds + ", round 1 to round 2, applied with protect-home."},
			"docker": {
				Apply: []string{"In the Dockerfile, delete the ENV line that holds the key, and pass no key with -e " +
					"or --env-file; a broker outside the box holds it"},
				Proves: []string{"SEC-1"},
				Image:  true,
				Costs: []string{"Never unset it with a bare -e NAME instead: on a machine that exports NAME, that passes " +
					"your own value into the box."},
				Proof: dockerProof + ", with the image rebuilt without the line."},
		}},
	{ID: "isolate-processes", Title: "Keep the box's other processes out of the agent's reach",
		Triggers: []string{"SEC-2", "SEC-5"}, Proven: map[string]Snippet{
			"docker": {
				Apply: []string{"Run the container's own processes as another user (docker run option --user 1001:1001, " +
					"any uid that isn't the agent's), and the agent as its own through docker exec -u <agent user> " +
					"(-as <agent user> in run docker)"},
				Proves:  []string{"SEC-2", "SEC-5"},
				Options: []string{"--user", "1001:1001"},
				Proof:   dockerProof + ", with the image's own long-running process started by --entrypoint."},
		}},
	{ID: "remove-credential-files", Title: "Take credential files out of the agent's reach", Triggers: []string{"SEC-3"}},
	{ID: "remove-sudo", Title: "Take away the agent's passwordless sudo", Triggers: []string{"AMP-1"}},
	{ID: "close-host-access", Title: "Take the host's controls out of the box: sockets, daemons, devices and kernel settings",
		Triggers: []string{"AMP-4", "AMP-5", "AMP-6", "AMP-8.sys", "AMP-8.blk"}},
	{ID: "cloud-identity", Title: "Keep the box away from your cloud identity", Triggers: []string{"SEC-4", "AMP-7"}},
	{ID: "narrow-proxy", Title: "Narrow the box's proxy and allowlist", Triggers: []string{"EGR-3", "EGR-6"}},
	{ID: "reset-storage", Title: "Reset every writable filesystem the agent can reach", Triggers: []string{"PER-5"}},
}

// entry finds a table row by its ID.
func entry(id string) (Entry, bool) {
	for _, e := range Table {
		if e.ID == id {
			return e, true
		}
	}
	return Entry{}, false
}
