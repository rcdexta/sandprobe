# Sandprobe

Sandprobe answers one question about an AI agent's sandbox: **what could a hijacked agent reach?**

A small, read-only probe runs inside the box, as the agent. In about a minute it checks four things: secrets it can
read, ways out, persistence that survives a reset, and amplifiers such as sudo, capabilities and control sockets.
The host then grades the box from what was proven, and writes a JSON report and a self-contained HTML page.

**No false passes.** A check passes only on a negative proof, such as a refusal next to an allowed twin. Anything that
failed quietly is "unknown", never a pass. The probe never reads a secret's value.

> Early days: version 0.x. The rules are in [SPEC.md](SPEC.md), and every behaviour traces to a rule ID there.

## Install

On macOS or Linux, arm64 or x86_64:

```sh
curl -fsSL https://probe.agent.cloud/install.sh | sh
```

The installer downloads the build for your machine, checks it against `SHA256SUMS`, and installs `sandprobe` into
`~/.local/bin`, or `SANDPROBE_INSTALL_DIR`. If the download or the checksum fails, an earlier install stays as it was.

Or let a coding agent do it. Paste this into one:

```text
Run curl -fsSL https://probe.agent.cloud/agents.md and follow it to install Sandprobe.
```

Then:

```sh
sandprobe version
sandprobe providers         # what's ready on this machine, and how to set up the rest
sandprobe explain EGR-2     # what a check does, what a finding means, and the fix
```

To build from source instead, you need Go 1.25: clone this repository and run `make`, which builds the Linux probes,
then `bin/sandprobe` with them embedded.

## Verify a download

Every release is on [GitHub Releases](https://github.com/summationai/sandprobe/releases): four gzipped binaries (macOS
and Linux, arm64 and amd64), `SHA256SUMS` for the `.gz` files and `SHA256SUMS-binaries` for the binaries. A checksum
shows that a file arrived intact, not who built it. So each of those files also carries a build attestation, which
binds it to this repository's release workflow, on `main`, at the release's commit (REL-3). Verify the `.gz` before
you unpack it:

```sh
gh release view -R summationai/sandprobe     # its notes give the verify command with the commit filled in
RELEASE_COMMIT=                              # set it to the full commit SHA those notes name
gh release download -R summationai/sandprobe -p sandprobe-darwin-arm64.gz
gh attestation verify sandprobe-darwin-arm64.gz --repo summationai/sandprobe \
  --signer-workflow summationai/sandprobe/.github/workflows/release.yml \
  --source-ref refs/heads/main --source-digest "$RELEASE_COMMIT" --deny-self-hosted-runners
gunzip sandprobe-darwin-arm64.gz && chmod +x sandprobe-darwin-arm64
```

Keep every flag: `--repo` alone is only the minimum identity check. Verify `SHA256SUMS` the same way before you trust
a checksum from it. A release is authentic when its files verify, never because its tag exists. To rebuild a release
and compare it byte for byte, check out its commit and run `make release` with Go 1.25.14 (REL-1).

## Try it in 30 seconds

Three demo boxes, made from a vibe-coded booking app. They run in Docker on your machine, every key in them is the
fake value `sandprobe-fake`, and a local canary stands in for an attacker's server. No provider is contacted. You
need Docker and `sandprobe`.

```sh
git clone https://github.com/summationai/sandprobe && cd sandprobe/demo/boxes
for box in vibe hardened regressed; do docker build -q -t sandprobe-demo/$box -f $box.Dockerfile .; done
cd "$(mktemp -d)"
sandprobe run docker sandprobe-demo/vibe -as agent -y -out vibe -- --entrypoint /opt/app/entry.sh
sandprobe run docker sandprobe-demo/hardened -as agent -y -out hardened -- \
  --read-only --cap-drop ALL --security-opt no-new-privileges --network none --tmpfs /tmp
sandprobe run docker sandprobe-demo/regressed -as agent -y -out regressed -- \
  --read-only --cap-drop ALL --security-opt no-new-privileges --network none --tmpfs /tmp
sandprobe compare hardened/*.json regressed/*.json
```

Once the images are built, each run takes under 10 seconds:

- **vibe scores 1/6.** Its `.env` holds the Stripe, OpenAI, Resend and Supabase keys, the dev server runs with every
  key in its environment, a stand-in Docker socket is mounted, and the network is open.
- **hardened scores 6/6.** The keys are gone, and five Docker options lock the box down.
- **regressed scores 5/6.** Someone committed a `.env` again. `compare` says "Got worse" under Secrets and exits 6,
  so a CI gate fails.

Each run names its `.html` report. [demo/README.md](demo/README.md) walks through all three, and `demo/reports/`
holds their reports.

## Check a sandbox

**A box you already have.** Give Sandprobe any command that opens a shell in it:

```sh
AGENT_USER=agent   # set it to the user your agent runs as in the box
sandprobe run exec -as "$AGENT_USER" -y -- docker exec -i my-agent-box sh
sandprobe run exec -as "$AGENT_USER" -y -- kubectl exec -i pod/agent -c agent -- sh
sandprobe run exec -as "$AGENT_USER" -y -- ssh "$AGENT_USER@devbox" sh
```

`-as` names the user your agent really runs as in the box. It checks that user, and doesn't switch to it: the run
stops before any check if your command runs as anyone else, or if the box has no such user. Many images, debian
and amazonlinux among them, have no `agent` user and run as root. Sandprobe creates nothing in your box but a
scratch directory, which it removes, and never resets or deletes the box.

**A throwaway copy.** Sandprobe creates the box, probes it and deletes it:

```sh
AGENT_USER=agent                                                                 # the user your agent runs as
sandprobe run docker my-agent-image -as "$AGENT_USER" -y                         # a local Docker image
SANDPROBE_KUBE_CONTEXT=my-cluster sandprobe run kubernetes -as "$AGENT_USER" -y  # a pod in your cluster
sandprobe run sprites -y                                                         # a provider adapter
```

Every run shows its plan first: what it will create, contact, mark and delete. Without `-y`, or a yes at the prompt,
nothing runs. A box Sandprobe creates is deleted by the ID its create returned. A few providers address boxes only by
name; there Sandprobe checks before each call that the name still holds the box its create returned, and the report
says what that check can't rule out. If the provider can't confirm a box gone, the run says so and exits 7.

## Where it runs

| Sandbox | How | [Status](docs/providers/README.md) |
|-|-|-|
| [Anything with a shell](docs/providers/exec.md) | `run exec` | Stable target |
| [Local Docker](docs/providers/docker.md) | `run docker` | Stable target |
| [Kubernetes, any cluster](docs/providers/kubernetes.md) | `run kubernetes`, a [recipe](recipes/kubernetes.sh) | Stable target |
| [E2B](docs/providers/e2b.md), [Daytona](docs/providers/daytona.md), [Vercel Sandbox](docs/providers/vercel.md), [Cloudflare Sandbox](docs/providers/cloudflare.md), [Fly Sprites](docs/providers/sprites.md), [AWS Nitro on EKS](docs/providers/aws-nitro.md) | `run <provider>`, native adapters | Stable target |
| [Baseten](docs/providers/baseten.md) | `run baseten`, a native adapter | Beta |
| [Modal](docs/providers/modal.md) | a proof of concept (`make poc`), not in the release build | Beta |
| [Boat](docs/providers/boat.md), [exe.dev](docs/providers/exedev.md) | `run boat`, `run exe.dev`, native adapters | Experimental: a live run needs the operator's informed authorization (Boat, PRV-11) or own clearance (exe.dev, PRV-13), never represented as provider-written permission |

The status is for 0.3.0 and is being validated. [docs/providers](docs/providers/README.md) is the single source for
it, with each provider's setup, the exact command, what it skips and why, and its terms.

Read your provider's terms before you probe: some require consent for security testing, and Sandprobe never presents
a run as a provider's permission. Each native adapter skips the checks its provider's terms rule out, as its PRV row
in SPEC.md says. `run exec` and recipes keep four checks off by default: SEC-4, EGR-3 and AMP-7, which would contact
a provider's own endpoints (cloud metadata, the box's proxy and the Kubernetes API), and AMP-6, which only checks for
a vsock device and connects to nothing. **New in 0.3.0:** if your provider's
terms allow one on your own account, turn it on by name, for example `-provider-endpoints SEC-4,AMP-7`; the plan
lists each one with your attestation before anything runs, and the report records it beside the check.

## What leaves your machine

- **Test traffic, to a canary.** The probe sends DNS lookups and HTTPS, TCP and UDP attempts that carry only this
  run's random nonces. A way out counts only when the canary logs the nonce, and the host gets that receipt from the
  canary directly, never through the box.
  - Every run but `run docker` and the Modal proof of concept uses the hosted canary at `control.pub.probe.ac0.dev`
    by default. It is run by Summation and trusted only under the control key this release pins. It sees two
    addresses. The box's public address, with the nonces its test traffic carries, is kept only for the run's
    lifetime, at most 30 minutes. The public address of the machine running Sandprobe, which reserves and arms the
    run, is kept in a rate counter for at most an hour. Both stay in memory: the canary writes no access log and
    stores nothing. `sandprobe canary check` asks it for its signed status and reserves nothing.
  - `run docker` always starts its own canary container on your machine, and refuses a canary flag.
  - The Modal proof of concept needs `-canary <state file>`, naming a canary you deployed with `deploy/canary.sh`.
  - To use a canary you run yourself, name it: `-canary-url <url> -canary-pin <pin>` for a public canary, or
    `-canary <state file>` for one deployed with `deploy/canary.sh`. Sandprobe never picks one up on its own.
- **No canary traffic, with `-no-canary`** (`run exec` and recipes): the probe sends no test traffic to any canary,
  and no canary is contacted. Exfiltration is then reported as not tested, and the run finishes incomplete (exit 5). Checks you
  turn on with `-provider-endpoints` that don't need a canary still make the connections the plan names: SEC-4's
  requests to the cloud metadata addresses and AMP-7's TLS handshake with the Kubernetes API. EGR-3 doesn't run, since
  it needs a canary, and AMP-6 only checks for a vsock device and connects to nothing. Your own command, or the
  provider's API, still reaches the box.
- **Your reports stay with you.** Sandprobe uploads no report and has no telemetry.
- **Feedback, only when you approve the exact issue.** `sandprobe feedback` first asks your own `gh`, read-only,
  which account is signed in to GitHub and whether it may label issues. Only after your yes to that exact preview,
  typed or given as its `-confirm` code, does it post the issue to
  [summationai/sandprobe](https://github.com/summationai/sandprobe/issues) through gh, or print a link you open
  yourself. It sends nothing else.
- **Your provider's own API**, when Sandprobe creates or reaches a box for you, with your own credentials.

## How it works

```
 host: laptop, CI or an agent's shell                  the box under test
 ┌──────────────────────────────────────┐   create,    ┌─────────────────────────────────┐
 │ sandprobe                            │   copy, exec │ sandprobe-probe (static Go)     │
 │  plan:  what it creates and contacts ├─────────────▶│  runs as the agent              │
 │  grade: trusts nothing from the box  │◀─────────────┤  observations only, no grade    │
 │  report: JSON + HTML; then delete    │ observations └───────────────┬─────────────────┘
 └──────────────────┬───────────────────┘                              │ attempts carrying
                    │ receipts for this run's nonces                   │ this run's nonces
                    └───────────────▶ the canary ◀─────────────────────┘
```

The grader trusts nothing the box returns. A box that deceives the probe can fabricate its own observations, so the
report says what was proven, what is only an indicator, and what wasn't tested.

## What it checks

| Area | IDs | Examples |
|-|-|-|
| Secrets | SEC-1 to SEC-5 | secret-shaped variable names, other processes' environments and memory, credential files, cloud metadata credentials |
| Ways out | EGR-1 to EGR-6 | DNS to the canary's name server, HTTPS straight out or through a proxy, other ports, TLS interception |
| Persistence | PER-1 to PER-5 | writable startup, PATH, schedule and access files; storage that survives the provider's reset |
| Amplifiers | AMP-1 to AMP-8 | passwordless sudo, root or capabilities, setuid and file capabilities, control sockets, local daemons, vsock, the Kubernetes API, kernel settings |

The report leads with a score out of six (Secrets, Exfiltration, Containment, Privilege, Cloud access, Persistence).
A category is green only when something in it was tested, nothing in it was left unknown,
and nothing above Info was found; when none of its checks is conclusive, it reads "Green · not proven".

Cloud access asks whether the agent can use your cloud identity: your own cloud roles, your own cloud's metadata
service, your own Kubernetes API. On a hosted provider whose terms rule out probing its own metadata and Kubernetes
endpoints, the box holds no cloud identity of yours to check, so Cloud access is not applicable: it is never green,
the score is out of five, and a line under the score says why. A credential of yours put into the box is still caught
under Secrets. `run exec` and recipes leave Cloud access "Not tested", since there those endpoints may be yours.

The score sits beside measurement coverage (SCR-5): which checks have usable or conclusive results, and which stayed
skipped, missing, scoped out, unknown or unproven. They answer different questions: six green categories don't mean
every check was conclusive. Reading a saved report (`scorecard`, `profile`, `assess`, `compare`) checks its structure
only: it can't re-verify the run or tell an edited report apart, and each says so.

Exit codes: 0 graded, 2 usage, 3 needs approval, 4 needs login, 5 incomplete or invalid, 6 green-category score below `-min` (`0`–`6` or `full`), 7 a box not
confirmed deleted. `-min` gates only the green-category count (not finding severity inside an already-red category or proof coverage); use `sandprobe compare` or `-o json` to fail CI on severity or proof regressions. `-o json` gives agents the plan, the report and every error as JSON, and `SANDPROBE_NO_KEYS=1` skips post-run keys in interactive terminals.

Research harnesses, such as the managed Nitro and Daytona coding evaluations, live in
[experiments/](experiments/README.md). They aren't part of the product. Their run records stay local and must not be
committed here.

## Fix loop

A run ends with a score. `sandprobe fix` turns the saved report into changes you can make to the sandbox's own config
or code, most effective first, and the steps to check each one:

```sh
sandprobe run docker my-agent-image -as agent -y -out round-1
sandprobe fix round-1/*.json
# apply the top action, for example --network none, then:
sandprobe run docker my-agent-image -as agent -y -out round-2 -- --network none
sandprobe compare round-1/*.json round-2/*.json
sandprobe fix round-2/*.json
```

Each action names the checks it should clear and the categories that could turn green. Where a rerun proved a setting
on that platform, it gives that setting and what it costs: today Docker, from a fixture test, and Modal, from a run
by hand ([docs/providers/modal.md](docs/providers/modal.md)). Everywhere else it gives the check's own fix, labelled
general advice. Every action is a prediction: only the rerun and `compare` show it worked. `fix` reads the report
offline and changes nothing. For a `run exec` report, `-platform <name>` says which platform the box runs on.

An action is offered for the checks it was written for. When a setting proven elsewhere may also clear other checks,
the action lists them under "May also clear", and each of those checks keeps its own action: dropping root may close
`/etc/shadow` while a key in the agent's home stays readable. When the report is incomplete, `fix` says so first,
still gives its plan, and exits 5, as `scorecard` does.

On Docker the loop reaches 6/6 from a root box with a key in its environment and an open network, in five rounds:
`--network none`, `--read-only --tmpfs /tmp`, `--user 1000:1000 --cap-drop ALL`, `--security-opt no-new-privileges`,
and the image rebuilt without the key. Read that 6/6 for what it is:

- The box has no network at all, so the agent has no model API either. No egress setting short of that is proven.
- Two greens rest on checks that can't prove a negative: Cloud access reads "Green · not proven", and Exfiltration
  carries "not proven: DNS, UDP 53".
- On a bare box only Sandprobe's idle process runs, so SEC-2 and SEC-5 have no other process to find. With the image's
  own process running, they find it. The loop then reaches 6/6 in five rounds too, with the container's processes as
  another user (`--user 1001:1001`) and the agent through `-as agent` in place of `--user 1000:1000 --cap-drop ALL`.

**For agents:** run, then `sandprobe fix <report.json> -o json`, and show your person the top action: its title, the
checks, the setting and its costs. Apply it to the sandbox's own config or code only with their OK; never apply a
change without it. Rerun into a new `-out` folder, `sandprobe compare` the two reports, and repeat until `fix` has
nothing actionable or your person stops. Exit 5 with `complete: false` still carries a plan: say the report is
incomplete when you show it. Never add `-platform` to `fix`, or `-provider` to a run, yourself: pass one only when
your person names the platform. Something under "Not an action for an agent" is never yours to change, Cloud access
left untested included.

## Send feedback

Found a bug, or want something? Sandprobe files it as a public issue on
[summationai/sandprobe](https://github.com/summationai/sandprobe/issues), and only with your explicit yes to the exact
issue. First, preview it:

```sh
sandprobe feedback bug -title "run docker waits 30s while Docker starts" -body-file notes.md
```

The preview says the issue is PUBLIC and names the GitHub account it would be filed as, through your own signed-in
[`gh`](https://cli.github.com). It prints the exact title, label and body, sends nothing, and ends with a
confirmation code. In a terminal it asks you to type `yes`. Otherwise you run the same command again with that code:

```sh
sandprobe feedback bug -title "run docker waits 30s while Docker starts" -body-file notes.md -confirm 3f9a1c0b7d2e
```

The code is a hash of exactly what would be posted: the title, body, labels, account and repository. If anything
changes after the preview, the code no longer matches and nothing is filed. There is no `-y`. Without gh, a confirmed
run prints a link that opens GitHub's form already filled in, for you to submit. A preview never prints that link,
since opening it sends the draft to GitHub. `-o json` gives agents the preview, the code and the result as JSON.
`feature` and `idea` work the same way, and `-provider <name>` and `-report <report.json>` add context.

**For agents:** show your person the exact title and body, say the issue is public, name the account, and ask
("May I file this public issue as @login?"). Run again with `-confirm <code>` only after a clear yes in the
conversation, without changing anything in between. Never answer the terminal prompt yourself, and never file on your
own judgement.

It sends your title and text, the Sandprobe and Go versions, your OS and CPU, and `-provider` when you name one. The
title starts with the kind; the label comes from the form on the link, or from gh when your account can label issues.
`-report` adds only a summary of a saved report: the score, whether the run was valid and complete, and each check's
ID with its result. It never sends the report's paths, names, evidence or receipts. It refuses to send anything that
looks like a credential, at any length and on any line: cloud, GitHub, Anthropic, OpenAI and Slack keys and tokens,
private keys, JWTs, Authorization headers and Bearer or Basic values, URLs with a password, and any field or flag
named like a credential (`token:`, `password=`, `"refresh_token":`, `--token`), on its line or the next, or anywhere
in a YAML or JSON body or code block, unless its whole value is a placeholder such as `<token>` or `$TOKEN`. A value
runs to the end of its line, commas and backticks included, so write one key a line, outside inline code. It also
refuses long hex or base64 strings and home-directory paths, and names the line to fix (FBK-1 to FBK-7 in SPEC.md).
When in doubt it refuses: rewrite the line, preview again, and ask again.

A check that passed when it shouldn't have is a
[false pass](https://github.com/summationai/sandprobe/issues/new?template=false-pass.yml), with its own form. A
vulnerability in Sandprobe goes privately, as [SECURITY.md](SECURITY.md) says. A suspected flaw in a provider never
goes in an issue: stop, delete the boxes, and report it privately to the provider.

## Contributing

Start with [CONTRIBUTING.md](CONTRIBUTING.md). [AGENTS.md](AGENTS.md) has the build, the layout and the hard rules,
for people and coding agents alike. A behaviour change starts in [SPEC.md](SPEC.md) under a rule ID, and comes with
its test. The most useful report you can file is a
[false pass](https://github.com/summationai/sandprobe/issues/new?template=false-pass.yml): a check that passed when
it shouldn't have. Changes are listed in [CHANGELOG.md](CHANGELOG.md).

## Security

To report a vulnerability in Sandprobe, see [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE). Copyright (c) 2026 Summation.
