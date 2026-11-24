# AGENTS.md

Sandprobe answers one question about an AI agent's sandbox: what could a hijacked agent reach? A small read-only
probe runs inside the box, as the agent. It checks readable secrets, ways out, persistence across a reset, and
amplifiers such as sudo, capabilities and control sockets. The host then grades the box.

**Read first:** [SPEC.md](SPEC.md), the rules. Every behaviour traces to a rule ID such as SBX-1, GRD-5 or PRV-1.

## Build and test

Go 1.25. The probe is a static Linux binary embedded in the CLI.

```sh
make            # Linux probes (amd64, arm64), then bin/sandprobe with them embedded; run it before make test
make test       # go vet ./... && go test ./...
make poc        # bin/sandprobe-poc: the Modal proof of concept, built with -tags poc; never a release
SANDPROBE_FIXTURES=1 go test ./internal/host   # adds the Docker fixture and exec tests
sh test/probe.sh                               # probe contract tests as root and nobody, without network
deploy/canary_test.sh; deploy/eks_test.sh      # tests for the deploy scripts (no cloud account needed)
cd experiments/proto/tui && go run .           # the UX prototype on demo data (its own module)
```

Every test runs on public data: saved reports come from `demo/reports` and `test/reports` (runs of local Docker boxes;
`test/reports/README.md` rebuilds them).

## Layout

| Path | What it is |
|-|-|
| `cmd/sandprobe` | the CLI: survey, plan, run, explain; `poc_*.go` only with `-tags poc` |
| `cmd/sandprobe-probe` | the in-box probe: observations only, no grade |
| `cmd/sandprobe-canary` | the canary server: TLS echo with a pinned key, TCP and UDP ports, an authoritative DNS server, a signed public control, receipts kept in memory |
| `cmd/sandprobe-aux` | the Modal proof of concept's sidecar relay and look helper |
| `cmd/sandprobe-agent-grade`, `cmd/sandprobe-daytona-workload` | the managed-workload evaluations, with `experiments/eks-agent` and `experiments/daytona-agent`; they need `SANDPROBE_AWS_ACCOUNT` and `SANDPROBE_AWS_PROFILE` |
| `internal/probe` | the checks themselves (SEC, EGR, PER, AMP) |
| `internal/grade` | the grader. It trusts nothing the box returns (GRD-5) |
| `internal/host` | provider adapters, `run exec`'s transport (`exec.go`) and the recipe runner (`recipe.go`) |
| `internal/report` | JSON (OUT-1) and a self-contained HTML page (OUT-2) |
| `internal/catalog` | the check catalog and each check's guide |
| `internal/fix` | `sandprobe fix`'s action table: each fix, its trigger checks, and the snippets a rerun proved per platform (FIX-1 to FIX-9) |
| `recipes/` | shipped recipes: POSIX sh files that create, reach and delete a box (RCP-1 to RCP-4) |
| `deploy/` | `canary.sh` (EC2 and Cloudflare DNS) and `eks.sh` (EKS Auto Mode for AWS Nitro); both need `PROFILE`, your AWS CLI profile |
| `test/` | Docker fixtures, each with an expected result, and the probe and calibration scripts |
| `demo/` | three demo boxes (vibe, hardened, regressed) and their reports |
| `docs/providers/` | each provider's status, setup, command and skipped checks |
| `examples/` | small scripts that reach a sandbox for `run exec`, such as `examples/modal/bridge.py` |
| `experiments/` | research harnesses, not part of the product: the EKS and Daytona agent evaluations and the TUI prototype ([README](experiments/README.md)) |

## Hard rules

These are not style preferences. Breaking one can produce a false result or harm a provider relationship.

1. **No false passes.** A check passes only on a negative proof. Anything that failed quietly is unknown, never a
   pass (KND, TWN).
2. **Spec first.** A behaviour change starts in SPEC.md under a rule ID, and the code cites that rule. Every rule has
   a test listed in SPEC.md's "Tests" table; add the test with the rule.
3. **Never read a secret's value, and never print or log a credential.** Provider and tool errors are sanitized
   before they reach any output.
4. **Only boxes a run may touch:** throwaway boxes created in the same run, deleted by the immutable ID their create
   returned (PRV-1), with only the reviewed exceptions SPEC names (a name-addressed provider checked before each call,
   PRV-13 and RCP-2; a box retained for inspection, PRV-7); or, through `run exec`, the person's own existing box,
   which is never reset or deleted (PRV-15). Never production (PRV-2).
5. **Read the provider's terms before any probe:** its security-research, bug-bounty, penetration-testing and
   acceptable-use terms. If they require consent, get it first.
6. **Test traffic goes only to the canary,** or to names the probe only resolves, with MEAS-6's explicit,
   bounded TLS-only workload-host measurement as the exception. Checks a provider's rules exclude are skipped,
   with the reason recorded. This does not authorize provider-control or infrastructure probing.
7. **Stop and report.** If a check suggests a real provider-side vulnerability, stop that line at once, and don't
   confirm, repeat or widen it. Delete the boxes, keep only minimal evidence, keep it out of every report and every
   public issue, and report it privately to the provider.
8. **Anything that costs money is managed only by its script,** which records exact IDs in
   `~/.config/sandprobe/*.state`. Never delete by name or by guess.
9. **Never commit run data, reports, credentials, kubeconfigs or `~/.config/sandprobe` state.** Reports hold names
   and paths, never a secret's value, but they describe real accounts.

## Conventions

- Every change goes through a pull request.
- Commit subjects are short and say what changed, often naming the rule, for example `Nitro: name recorded before create`.
- Run `gofmt` on everything, and `shellcheck -s sh` on recipes.
