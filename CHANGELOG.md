# Changelog

Every release lists what changed for someone using Sandprobe. Dates are in Pacific Time. Each release's files and
their build attestations are on [GitHub Releases](https://github.com/summationai/sandprobe/releases).

## Unreleased

- Add `sandprobe fix <report.json>`: a saved report's red checks as a short, ranked list of changes to the sandbox's
  own config or code, with the rerun and compare steps for the loop. It gives a platform's own setting only where a
  rerun proved it there (Docker, from a fixture test that applies each one; Modal, from three rounds by hand), and the
  check's own fix, labelled general advice, everywhere else. Every action is a prediction until a rerun shows it;
  `-provider` names a `run exec` report's platform; `-o json` gives agents the same (FIX-1 to FIX-9). The run summary's
  `Fix first` now ends "Run sandprobe fix <report.json> for every fix, in order." `examples/modal/bridge.py` probes your
  own Modal sandbox through `run exec`.

- `compare` now says what got better, so a fix loop (run, fix, run again, compare) shows its progress: each check that
  was a finding or unknown and now passes with proof or is verified absent; separate lists, never counted as better,
  for checks that no longer apply (nothing left for them to check) and for findings that are only no longer found;
  and the score of each report, such as `Score: 1/6 → 6/6`. When the agent's identity changed, it still warns that
  the pair isn't like-for-like and adds that this is expected when the fix was to change the agent's user. Each check
  reads `Secrets › <question>`, the words wrap within 80 columns, and a C or POSIX locale gets ASCII. `-o json` adds
  `got_better`, `no_longer_applicable`, `no_longer_found_not_proven`, `score_before` and `score_after` under
  `sandprobe.compare/1`. Exit codes don't change: a complete, matched pair with anything worse still exits 6, and an
  incomplete or unmatched pair still exits 5 (CMP-2).

- `run exec` no longer turns Secrets red because of its own transport. SEC-2 and SEC-5 used to find the shell that
  `run exec`'s script ran in, on every box, and no agent could fix that. Now that shell replaces itself (`exec`) with
  Sandprobe's own wrapper before any check runs, so the shell, with its memory and the environment it started with,
  is gone. The wrapper starts the probe with its environment passed through unchanged, frames the run and removes
  the scratch. SEC-2 and SEC-5 skip only the probe's direct parent, and only while the kernel shows that it runs the
  probe's own file. Any doubt counts that process, or leaves the check unknown. Every other process is still counted,
  ancestors such as ssh's session process included. `run kubernetes` and recipes get the same fix; `run docker` never
  had the shell (LNC-1 to LNC-5).

## 0.3.0 (2026-11-24)

- `run docker` starts the container with Sandprobe's own idle process as its entrypoint and the image's health check
  off, so an image whose entrypoint exits without a task or a terminal runs as it is, and SEC-2 and SEC-5 don't count
  that process (DKR-1, DKR-2). A
  container that stops early says what stopped and how, with a fix that runs as pasted (DKR-3); a read-only root gets
  Sandprobe's own scratch tmpfs (DKR-4); and the plan says PER-5 marks nothing and resets nothing on `run docker`
  (DKR-5). Pass `--entrypoint` to run a process of your own; the vibe demo now does.

- Add `sandprobe feedback bug|feature|idea`, so agents and people can file feedback as a public issue on
  summationai/sandprobe, only with the person's explicit yes to the exact issue. A preview shows the title, body and
  labels, says the issue is public, names the gh account, and prints a code that hashes exactly what would be
  posted. The person types `yes`, or the agent runs again with `-confirm <code>` after their yes; any change voids
  the code. There is no `-y`. Without gh, a confirmed run prints a prefilled form link. It sends only your text, a
  fixed environment block and, with `-report`, a summary of fixed values from a saved report. It refuses credentials
  at any length and on any line, including inside YAML and JSON, and home-directory paths. A new feature-request
  form backs the link. The YAML parser `go.yaml.in/yaml/v3`, the YAML organization's maintained module, is the one
  new dependency (FBK-1 to FBK-7).

- A green category with no conclusive check, such as Cloud access when SEC-4 and AMP-7 both end `not_found`, now reads "Green · not proven" rather than plain green: a dashed `GREEN · NOT PROVEN` badge in the web report and the workload exposure page, `◌ GREEN · NOT PROVEN` in the terminal, and `green_not_proven: true` in `scorecard -o json`. It still counts toward the score (SCR-2).

- Require pinned block-device type and stable path identity for AMP-8.blk permission evidence; unsupported metadata permission calls remain unknown.

- Add `-block-device-path <path>` to `run exec` and `plan exec`, repeatable up to 32 times, so AMP-8.blk can assess a
  block device at a custom path as well as the ones sysfs names. The check stays metadata-only, with no device I/O. A
  declared path that is missing or of the wrong type stays unknown, and the grader refuses a `scoped_out` result when
  a path was declared (EVD-13).

- The web report's per-category "tests run" counts no longer count skipped or scoped-out checks as run, as they
  already didn't count missing ones; unknown and not-found checks still count as run, never as passes. Scores are
  unchanged (SCR-6).

- A persistence reset recheck (PER-5) that stops on a marker mismatch now says whether the inode, the length or both
  differed. It is still unknown, and a mismatch returns before the marker is ever opened for reading (TWN-3).

- An unexpected HTTP reply from the canary exchange is now labelled by its status class (1xx to 5xx), keeping the
  specific 403 and 407 labels. Response text is still discarded, and no label counts as delivery or denial.

- Managed Daytona runs: a missing or non-executable local SDK interpreter now reports `local_sdk_unavailable` instead of
  a generic provider error, each SDK call is recorded once rather than twice, and a workload preparation failure names
  its stage (source read, upload, worker run or readiness) with only fixed labels, never raw errors or paths.

- Retain optional, own-sandbox-bound organization network-policy context for managed Daytona runs without treating configuration as observed denial.

- Stop HTTP-opted managed Nitro and Daytona runs before paid resources when the shared canary capability is unavailable.
- Add private canary maintenance admission controls and a deployment/rollback runbook; shared-service updates remain explicit.

- Add explicit HTTP TCP/80 measurement selection with same-pin canary capability verification. Reports using it declare `sandprobe/4`; legacy requests and grading remain unchanged.

- Add bounded HTTP/1.1 nonce echo support on the canary’s existing TCP/80 listener, alongside the legacy protocol. Probe selection and grading remain unchanged until client capability/calibration support lands.

- Escape Unicode format controls in saved-report terminal text so bidi and zero-width characters cannot reorder or hide displayed evidence.

### Terminal, score and CI gate

- **Breaking (`-min`):** `-min` now takes a green-category count (`0` to `6`) or `full` (`Score == Of`, every applicable
  category green), exiting 6 when a valid run scores below it (OUT-4). Retired letter thresholds (`-min A` to `-min F`)
  and `-min 6` on native adapters whose score is out of 5 are refused before creation with usage exit 2. `-min` gates
  only the green-category count: use `sandprobe compare` or validated `-o json` output to gate CI on severity increases
  inside an already-red category or proof-coverage regressions.
- `sandprobe run` prints a compact 80-column score summary with `SCORE x/y` (or `SCORE none` on an invalid run, with no
  category rows or counts), coverage counts, the six exposure categories, the top chain or finding with canary receipt
  routes and `Fix first`, explicit cleanup confirmation (or a loud `CLEANUP UNCONFIRMED (exit 7)` warning), and the
  HTML report path, with no letter grade in terminal text (UX-6, SCR-3). `grade.letter` in `OUT-1` JSON is unchanged.
- Interactive runs update plan-derived host phases (`network`, `canary`, `box`, `probe`, `reset` where applicable, and
  `delete`/`cleanup`/`retain`) in place on TTY `stderr` for every provider, the native adapters (E2B, Vercel, Daytona,
  Cloudflare, Boat, exe.dev, Baseten) included. A phase is ticked only when it finished: one cut short reads `did not
  finish`, one never started `not run`, and an unconfirmed cleanup `not confirmed` (UX-5). Runs offer single-key
  post-run actions (`Enter`/`j`/`k` to walk findings and unknowns, `e` to explain a check, `c` to copy a fix, `o` to
  open the HTML report, `b`/`Esc` back to the summary, `q`, or `Esc` on the summary, to quit) on foreground TTYs when `CI` and `SANDPROBE_NO_KEYS` are unset, auto-exiting after 15 seconds if untouched and restoring
  terminal state on `EOF` and termination/suspension signals (UX-5, UX-7, AGT-1).
- The run summary's top finding and each finding in the walker say whether it is `proof` or `a sign we saw, not
  confirmed` (UX-6, UX-7).
- `sandprobe scorecard` keeps every line within 80 columns, its coverage sentence, statement and saved-report note
  included; it honors `NO_COLOR` and `TERM=dumb`, and uses ASCII row symbols under a `C` or `POSIX` locale (UX-9).
- Terminal output escapes Unicode `Cf` format characters (bidi overrides/isolates, ALM, zero-width characters, BOM) in
  addition to control characters and line separators, accounts for wide East Asian and emoji display widths when
  wrapping to 80 columns, and honors `NO_COLOR`, `TERM=dumb`, ASCII `C`/`POSIX` locales and
  `SANDPROBE_REDUCED_MOTION=1` (UX-9).

## 0.3.0-rc.2 (2026-11-23)

The second release candidate for 0.3.0: the web report's new layout. Checks and grading are unchanged from rc.1.

### Web report

- The HTML report takes the site's look: a near-black page, hairline panels, and Geist, named but never loaded (UX-8,
  OUT-2). The sandbox score is now the largest thing on the page, with one line saying what it means, and the page
  shows no letter grade; its title carries the score instead. An incomplete run says so beside the score ("Incomplete:
  6 checks unknown"), and an invalid run says it has no score, with the reason. "What to fix" lists every test once:
  failures by severity, each chain's sentence first in its own, then the unknowns, then the rest folded away. Each of
  the six categories links to its tests. The JSON report, the terminal output, `-min` and the exit codes keep the
  grade (SCR-3). ([#45](https://github.com/summationai/sandprobe/pull/45))

## 0.3.0-rc.1 (2026-11-23)

The first release candidate for 0.3.0. Provider statuses are still being validated.

### Fixed: false passes in 0.2.1

0.2.1 could pass a check it hadn't proven. If you ran 0.2.1, don't trust the passes below: re-run the box with this
version. A saved 0.2.1 report keeps its old results: `scorecard`, `compare`, `profile` and `assess` read the results
saved in it and never grade its observations again (ANL-1).

- **Write and read checks (TWN-4).** 0.2.1 counted a refusal as a pass even when the agent could undo it: by changing
  the mode of a file or directory it owns on the path, or with a capability it holds, permitted or effective, such as
  `CAP_FOWNER`, `CAP_CHOWN`, `CAP_SETUID`, `CAP_SETGID` or `CAP_DAC_READ_SEARCH`. Confirmed: an agent holding only
  `CAP_FOWNER`, or owning a 0555 directory above a root-owned startup file, passed PER-1 to PER-4; and an agent's own
  credential file at mode 0000 passed SEC-3. The write checks now report such a path as a finding, or unknown when
  the probe can't see past a closed directory, and SEC-3 reports it unknown. The rule now covers every write and read
  check. Re-run before you trust a 0.2.1 pass on PER-1 to PER-4 or SEC-3, in particular where the agent owns a file or
  directory on the checked path or the report's `identity.cap_prm` isn't all zeros.
  ([#17](https://github.com/summationai/sandprobe/pull/17))
- **AMP-2, root or capabilities.** 0.2.1 graded AMP-2 from the effective capability set alone, so an agent holding a
  capability only in its permitted set passed, though a process can raise a permitted capability into its effective
  set at will. Confirmed: `CAP_DAC_READ_SEARCH`, permitted but not effective, passed; it's now a Critical finding.
  AMP-2 now counts the permitted and ambient sets as well. 0.2.1 also ignored the inheritable set. With `NoNewPrivs`
  0, an exec of a file whose file capabilities name an inheritable capability makes it permitted, and the probe
  doesn't look for such files; so while `NoNewPrivs` is 0, an inheritable capability now leaves AMP-2 unknown. A 0.2.1
  AMP-2 pass can't be trusted if the report's `identity.cap_prm` isn't all zeros, or if `identity.no_new_privs` is 0
  and `identity.cap_inh` isn't all zeros. ([#34](https://github.com/summationai/sandprobe/pull/34))
- **AMP-3, new privileges.** With `NoNewPrivs` 0, 0.2.1 passed AMP-3 whenever it found no setuid-root file in the
  system binary directories. It never looked for files with file capabilities, or for setuid-root files elsewhere,
  and running either can raise the agent's privilege. Confirmed: an agent with every capability set empty gained
  `CAP_DAC_OVERRIDE` by running a file with that file capability, and 0.2.1 passed both AMP-2 and AMP-3. AMP-3 now
  passes only under no-new-privileges. A 0.2.1 AMP-3 pass can't be trusted if the report's `identity.no_new_privs`
  is 0; a pass with 1 still holds. On a box without no-new-privileges, Docker's default among them, a re-run ends
  AMP-3 unknown and the run incomplete unless setuid-root files make it a finding; set no-new-privileges to settle
  it. ([#40](https://github.com/summationai/sandprobe/pull/40))
- **Paths, symlinks and PATH (SBX-2, TWN-4, AMP-1, PER-2).** 0.2.1 worked some paths out from their text instead of
  walking them as the kernel does, and missed some entries the agent could move, so a check could judge a different
  file from the one the agent reaches. Each case was reproduced on the code before the fix, and 0.2.1 handles paths
  the same way:
  - A write check (PER-1 to PER-4) passed on a path through a symlink the agent could replace, such as its own link in
    root's sticky `/tmp`, or through a nested Btrfs subvolume, which the agent could rename but which was taken for a
    mount point.
  - A symlink to `../target` reached through a directory link was resolved from the path's text, not from the real
    directory holding the link, so the write and read checks judged a different file from the kernel's.
  - HOME and PATH entries were cleaned before checking. With `HOME` and a PATH entry of `/x/link/..`, where `link`
    leads elsewhere, PER-1 and SEC-3 passed and AMP-1 reported sudo absent, though the kernel let the agent write
    `~/.bashrc`, read `~/.netrc` and reach a `sudo`.
  - An empty PATH was ignored, though `execvp` then searches the working directory. With a writable working
    directory holding `sudo`, PER-2 passed and AMP-1 reported sudo absent. With PATH unset, the probe can't tell
    where the agent's launcher looks, so PER-2 now ends unknown unless it finds a writable directory anyway, and AMP-1
    unknown unless a sudo at a fixed path settles it.
  - SEC-3's read check resolved paths the same way, so it had the mirror cases.

  No field in a saved 0.2.1 report tells these cases apart, so re-run before you trust a 0.2.1 pass on PER-1 to PER-4
  or SEC-3, or an AMP-1 "absent". ([#37](https://github.com/summationai/sandprobe/pull/37))

### Canary and score

- Every run but `run docker` and the Modal proof of concept uses the hosted canary by default, the native provider
  adapters included; the proof of concept needs `-canary <state file>`. A canary state file from `deploy/canary.sh`
  is used only when `-canary` names it, any canary flag sets every `SANDPROBE_CANARY*` variable aside, and
  `run docker` refuses canary flags (HCN-5).
- With no canary named, by flag or `SANDPROBE_CANARY*` variable, `sandprobe canary check` asks the hosted canary under
  the pin this release ships, the one every run but `run docker` and the Modal proof of concept uses by default, and
  names it in its output. `-canary-url` with `-canary-pin` still checks a canary you name. An operator canary
  (`-canary` or `SANDPROBE_CANARY`) is refused, since it answers only over SSM, and `-tls-insecure` now needs
  `-canary-url` (HCN-7).
- With no cluster, `plan aws-nitro` and `providers` print `PROFILE="$AWS_PROFILE" deploy/eks.sh up`, a command that
  runs as pasted; every other `deploy/eks.sh` fix names `PROFILE` the same way.
- `-no-canary`'s plan and help say only that no test traffic goes to any canary. When `-provider-endpoints` turns on
  checks that don't need a canary, the plan names each connection they still make: SEC-4's metadata addresses and
  AMP-7's TLS handshake. EGR-3 needs a canary, so it doesn't run (HCN-5).
- Cloud access now asks whether the agent can use your own cloud identity. On a native adapter whose provider's terms
  exclude its metadata and Kubernetes endpoints, Cloud access is not applicable and the score is out of five.
  `run exec` and recipes leave it "Not tested" (SCR-2). Reports that carry skip kinds declare the schema
  `sandprobe/2` (AGT-6).
- The score shows measurement coverage beside it: which checks have usable or conclusive results, and which stayed
  skipped, missing, scoped out, unknown or unproven (SCR-5).

### Checks

- `run exec` and `run kubernetes` take `-provider-endpoints`, which turns on named provider-endpoint checks, such as
  `SEC-4,AMP-7` for cloud access, each one attested as allowed by your provider's terms (PRV-15).
- Plans name all three SEC-4 metadata addresses the probe dials (UX-4).
- AMP-1 grades sudo-rs installs instead of ending unknown, and PER-5 names why each root is a gap.
- Write and read checks no longer pass a refusal the agent could undo through ownership or capabilities (TWN-4).
- The write, read and sudo checks resolve every path in one walk, as the kernel does: one component at a time on
  directory descriptors, each path as given, never cleaned, with `..` taken by the kernel. One budget of 8 links
  covers the whole path, a directory's links included; past it the path is unknown (SBX-2).
- An entry counts as a mount point, which can't be renamed, only when `statx` reports `STATX_ATTR_MOUNT_ROOT` for it;
  a change of device alone, which a Btrfs subvolume also shows, no longer spares it (TWN-4).
- An ACL the probe fails to read, other than as absent or unsupported, counts as an ACL, so a refusal under a power
  to change identity or mode is unknown (TWN-4).
- AMP-1 also looks for sudo in relative and empty PATH entries, from the working directory; it used to skip them. A
  relative entry with no working directory is unknown.
- AMP-2 counts every capability the agent holds, permitted and ambient as well as effective, since a process raises a
  permitted capability at will. While `NoNewPrivs` is 0, an inheritable capability it doesn't otherwise hold leaves
  AMP-2 unknown. The evidence names each capability.
- AMP-3 passes only with `NoNewPrivs` 1. With `NoNewPrivs` 0, setuid-root files in the system binary directories are
  still a finding; otherwise AMP-3 is unknown, since the probe can't rule out a setuid-root file elsewhere or a file
  with file capabilities anywhere, either of which an exec could gain privilege through. Set no-new-privileges to settle
  it. A box without it and without setuid-root files used to pass AMP-3 and now ends incomplete. AMP-2's pass covers
  only the capabilities held now.

### Saved reports

- A saved `sandprobe/2` report with a field present but empty or null is refused (AGT-6).
- An invalid report keeps its attested rows, and they stay not graded (GRD-5, PRV-15).

### Web report

- The HTML report takes the landing page's look: a graphite room, raised panels, Inter Tight headings, and results
  as keys. A failure is a light key with a red legend; an unknown is a dashed key, never green. `graphite` is the
  default palette and `mission` the alternative. `-theme modern`, the retired cyan palette, renders `graphite`, and a
  page that remembered `modern` opens in `graphite` (UX-8). The page still fetches nothing, fonts included (OUT-2).

### AWS Nitro on EKS

- `deploy/eks.sh up` checks that AWS answers as your profile before it records anything, and exits 3 if it doesn't,
  so an expired session no longer leaves a state file that blocks the next `up`. A state file that records no create
  makes `status` and `up` print the exact `down` command that retires it, and that `down` makes no AWS call (CLN-2).
- The AWS Nitro page says a run on the `isolated` or `network-isolated` pod is expected to end incomplete with exit 5,
  and how a script tells that apart from an invalid run. It also says the cluster costs money for as long as it's up,
  with a link to AWS's pricing, and how to grade a Nitro cluster you already run with `run kubernetes` or `run exec`.
- On 23 Nov 2026 the `network-isolated` pod's container had no `/dev/vsock`, so AMP-6 was skipped. The pages now say
  AMP-6 only checks for a vsock device and connects to nothing.

### Research harnesses

- The managed Nitro and Daytona coding evaluations moved to `experiments/`, with the TUI prototype. They aren't part
  of the product. They gained a host-controller mode, persistent workspaces, bounded TLS measurement of approved
  workload hosts, and more failure diagnostics.
- Both evaluations use the hosted canary and the same starting environment, check the receiver's pinned TLS key with
  a native client, and can run a matched pair on regional Ministral 8B. A repair turn gets validated feedback from the
  public test cases, and a completed assessment with unmet configuration requirements is told apart from one that
  didn't complete. A Daytona replacement create rejected before it returned an ID no longer blocks cleanup: the
  rejection is proven from bound audit evidence, and nothing is adopted or deleted by name.
- The managed Nitro evaluation counts its cluster as never created, with cleanup confirmed, when `eks.sh up` exits 3
  and left no state file (CLN-2).

### Documentation

- The README leads with install, verifying a download, and a 30-second demo.
- `docs/providers/` gives each provider's status, setup, command, skipped checks and terms.
- Boat and exe.dev: a live run needs the operator's informed authorization (Boat, PRV-11) or own clearance (exe.dev,
  PRV-13), never represented as provider-written permission.
- New: CONTRIBUTING.md, CODE_OF_CONDUCT.md, issue forms (including a false-pass report), a pull request template and
  this changelog.
- `SANDPROBE_KUBE_OVERRIDES` is the path to a file holding a JSON merge patch, not inline JSON; the Kubernetes page
  has an example for AWS Nitro Sandboxes' `isolated-sandbox` runtime class, and says to set `KUBECONFIG` when your
  cluster's context is in another file.
- The `run exec` and `run kubernetes` examples set `AGENT_USER` and pass `-as "$AGENT_USER"`. `-as` checks the user
  your command runs as and never switches to it; a user the box doesn't have stops the run before any check.
- Every command in the README and on the `run exec`, Kubernetes and AWS Nitro pages runs as pasted, with no
  `<placeholder>` for the shell to read as a redirection.
- The AWS Nitro page quotes AWS's penetration testing policy and Acceptable Use Policy, read 23 Nov 2026. Amazon EKS
  isn't on the list of services customers may test without prior approval.

### Releases

- A release version is `x.y.z`, or `x.y.z-rc.N` for a release candidate. A release candidate publishes as a GitHub
  pre-release, never marked Latest; `x.y.z` publishes as a full release (REL-2).

## 0.2.1 (2026-11-21)

- Releases are reproducible and attested. `make release` builds the four binaries; the release workflow builds them
  twice on separate runners and publishes only when every file matches byte for byte (REL-1, REL-2). Each `.gz` and
  both checksum files carry a build attestation, and the release notes give the `gh attestation verify` command
  (REL-3).
- A release is authentic when its files verify, never because its tag exists (REL-3).
- SEC-3 checks the credential files of six AI coding tools: Claude Code, Codex, Gemini CLI, Aider, Cline and Goose.
- Every test runs on public data: saved reports come from local Docker boxes.

## 0.2.0 (2026-11-21)

The first open-source version, under the MIT license. It was published as source only, with no tag and no GitHub
release.

- `run exec` checks a box you already have, through your own command (PRV-15).
- `run docker` grades a throwaway container from a local image, beside its own local canary (PRV-14).
- `run kubernetes` grades a throwaway pod in your cluster, through the first shipped recipe (PRV-16).
- Native adapters for Fly Sprites, AWS Nitro on EKS, Baseten, E2B, Vercel Sandbox, Cloudflare Sandbox, Daytona, Boat
  and exe.dev, each run beside a canary you deploy with `deploy/canary.sh`.
- A Modal proof of concept, built only with `make poc`.
- The hosted canary for `run exec` and recipes, and `-no-canary` to send no test traffic to any canary.
- A six-category score beside the letter grade, a JSON report and a self-contained HTML page, and the offline
  `scorecard`, `profile`, `assess` and `compare` commands.
