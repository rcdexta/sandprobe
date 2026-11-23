# Sandprobe

This is Sandprobe's specification. Every behavior traces to a rule ID here, and the code and tests cite those IDs.

Sandprobe answers one question about an AI agent's sandbox: what could a hijacked agent reach? A small read-only probe
runs inside the box, as the agent, through the same path the agent's own commands take. In about a minute it checks
four things: readable secrets, ways out, persistence that survives a reset, and amplifiers such as sudo, capabilities
and control sockets. It chains a readable secret and a proven way out into one finding, grades the box A to F for the
checks it ran, and gives a fix for each finding. It never reads a secret's value. Platform teams, their security leads,
and agents themselves (Claude Code, Codex) run it from one CLI. Its core rule is no false passes: a check passes only on
a negative proof, never because something failed quietly. Where no trustworthy negative proof exists, the check can
only find, and the report says what it could not prove. The promise has a stated boundary (SBX-10): it covers faults,
misconfiguration and wrappers, not a box that deliberately deceives the probe.

Sources: earlier internal sandbox checks, the AWS Nitro Sandboxes launch (9 Nov 2026) and its EC2 and EKS docs, and
independent security and code reviews of each change.

## At a glance

```
 host: a laptop, CI, or an agent's shell                    the box under test
 ┌────────────────────────────────────────────┐             ┌───────────────────────────────────┐
 │ sandprobe (Go, Charm TUI)                  │ create by   │ the agent's exec path             │
 │  ├ picker, access check, plan       UX     │ immutable   │  └ sandprobe-probe (static Go,    │
 │  ├ manifest: checks, nonce, box ID  GRD-5  │ ID, copy,   │     digest known to the host)     │
 │  ├ provider adapters                PRV    ├────────────▶│     observations only, no grade   │
 │  ├ reset, then storage-root recheck TWN-3  │ run as the  │                                   │
 │  ├ grader                           GRD    │ agent       │                                   │
 │  └ TUI · HTML · JSON                OUT    │◀────────────┤                                   │
 └───────────────┬────────────────────────────┘ observations└────────────────┬──────────────────┘
                 │ liveness before and after; receipts for the nonce          │ attempts carrying the nonce
                 └───────────────────────────────────▶ canary.<our domain> ◀──┘
                                                         TLS echo with a pinned key, TCP and UDP ports,
                                                         the authoritative name server for <nonce>.dns.*
```

The probe observes; only the host grades, and the host trusts nothing the box returns (GRD-5). Receipts reach the
host from the canary, never through the box.

## Local robustness extension, 16 November 2026

This bounded extension supersedes only the blanket exclusion of user-invoked offline comparison below. It adds no hosted service, scheduler, periodic provider probing, alert delivery or independent attestation; live provider runs are unchanged.

- **JON-1 Strict framing.** Protocol JSON is one bounded value, depth at most64, with no trailing data. Duplicate object member names, including case aliases which Go would map to the same field, are rejected before decoding. Case-distinct object names are conservatively rejected; arrays retain case-sensitive values. No raw malformed data/member names are echoed. Unknown-field rules on existing protocols remain strict. Preserve valid canonical existing messages and saved-run shapes.
- **JON-2 Every boundary and tests.** Apply JON-1 to host observation parsing and every probe stdin mode, with the existing1MiB byte bound checked before parsing (not a truncated reader accepted as EOF). Reject unsupported/extra probe arguments. Add duplicate/alias/nesting/trailing/oversize/fuzz regressions. CI runs build/vet/unit tests on Linux without cloud/provider credentials; no live provider tests or new paid resources.
- **ANL-1 Saved report input.** Offline analysis accepts only explicitly named report files opened with no-follow/nonblocking semantics and fstat-verified regular descriptors under an8MiB max+1 read bound and JON-1 framing. A supported schema, exactly the version its fields need (AGT-6), canonical known catalog IDs/results, unique checks, required grade/run/manifest fields and consistency between selected/skipped/check/unknown/completeness metadata are required. Missing/contradictory evidence is an error or incomplete, never a clean result. Fixed errors do not echo file contents. Negative results must be legal for their catalog kind and include exported proof metadata; grade counts/findings must agree with checks where derivable. The saved letter is reported and unverified, never an input to success/regression decisions. Analysis structurally validates exported reports, does not re-verify raw observations or canary receipts, and cannot authenticate or attest to an edited report. Every offline rendering of a saved report (`scorecard` in text, JSON and the page `-out` re-renders, `profile`, `assess`, `compare`) says so plainly: structurally checked only, its observations and receipts not re-verified, and an edited report can't be told apart.
- **ANL-2 Coverage profile.** Five fixed areas are egress(EGR), secrets(SEC-1/2/3/5), privilege(AMP-1/2/3/8.sys/8.blk), persistence(PER), provider reach(SEC-4/AMP-4/5/6/7). SEC-3 stays aggregate secrets; no image/provider attribution is inferred. Each catalog check requires an explicit area mapping; an unmapped future check blocks offline analysis until classified. Counts distinguish findings, negative proofs, find-only no-finding, absent/out-of-scope, unknown, excluded and missing catalog coverage. No profile labels a wall secure/Held or changes the saved legacy letter/caps. Invalid reports have no assessed area. Terminal output escapes untrusted identifiers; JSON labels reported data as unauthenticated and self-observed.
- **CMP-1 Local comparison.** Compare two structurally validated reports by known check IDs/results/severities and declared scope/identity, never only the letter or prose heuristics. Flag new/worse findings and loss of coverage separately; removed/skipped/unknown checks cannot look like an improvement. Compare per-check scope/route, kind/evidence class, selected/skipped targets and recorded identity/config; unrecorded configuration remains unknown. Provider/mode/context differences are explicit; no-observed-change is conditional on matched coverage/context and means only the summarized fields, not equivalent security or an attestation. Ignore ephemeral runIDs/timestamps/nonces/receipt destinations when comparing observations. Keep invalid/incomplete inputs visible. Exit precedence is input/usage2, invalid/incomplete or unmatched context5, observed regression6, then assessed/no observed regression0. Automated gates must reject every nonzero exit and inspect both findings and context fields, rather than gate only on exit6. No network, file writes, schedules or notifications.
- **QCK-1 Local quick observation.** A separate Linux quick entrypoint runs as the current identity with no network, provider APIs, external commands/sudo, socket connection, secret-value read, filesystem mutation, process memory/environment opens or persistence marker. The interface is `sandprobe-probe-linux-ARCH -quick [absolute-path ...]`; JSON-only output escapes untrusted strings. It reports own-identity metadata from at most64KiB of explicitly allowed proc status, at most256 environment names and metadata for at most32 explicitly declared absolute paths of at most1024 bytes each. No recursive traversal or symlink following; terminal strings are escaped. Output is capped at256KiB and the entrypoint has a five-second deadline; blocking filesystems may prevent graceful completion, so no result is inferred from timeout. Consumers must discard output on every nonzero exit and require complete JSON even on exit0; the watchdog may interrupt stdout and leave partial JSON with exit5. It reports permission metadata only; inaccessible/malformed observations stay unknown. It assigns no A–F grade or negative containment pass and labels egress/reset/sudo/process/provider-boundary coverage untested. It is not host-shipped attestation, a complete baseline, a comparison input or proof of secret disclosure. No fallback from quick data to sandprobe/1 report.
- **QCK-2 Tests and packaging.** Exercise quick mode only on synthetic fixtures/disposable owned local Linux containers, including missing proc/permissions/symlinks/caps/error cases. Package static Linux amd64/arm64 binaries with checksums and explicit build/version metadata; no unsigned remote installer or publication/release is implied. Existing full-provider flows and their selected checks stay unchanged.

## Scorecard headline, 19 November 2026

The scorecard is a simpler headline: six categories, each green or red (or not applicable, SCR-2), a score out of
the categories that apply, and every other detail in an appendix. This changes presentation only. The grader, the
letter and every saved report stay as they are, and OUT-1 gains only SCR-2's skip kinds in its manifest, in reports
that declare `sandprobe/2` (AGT-6); the scorecard is computed from a report's checks when it is shown, never written into one.

- **SCR-1 Six categories.** Every catalog check belongs to exactly one category, each asked as a question:
  Secrets, "can it read keys and tokens?" (SEC-1, SEC-2, SEC-3, SEC-5); Exfiltration, "can data leave the box?"
  (EGR-1 to EGR-6, each EGR-5 port); Containment, "can it reach past the box to the host?" (AMP-4, AMP-5, AMP-6,
  AMP-8.sys, AMP-8.blk); Privilege, "can it become root?" (AMP-1, AMP-2, AMP-3); Cloud access, "can it use your cloud
  identity?" (SEC-4, AMP-7): a cloud identity the person owns, meaning their own cloud roles, the metadata service of
  their own cloud, and their own Kubernetes API, never a hosted provider's own infrastructure; Persistence, "can it leave something for the next session?" (PER-1 to PER-5).
  This refines ANL-2's five areas without changing them: provider reach splits into Containment and Cloud access,
  and AMP-8 moves from privilege to Containment. An unmapped check fails the tests. Chains have no category; the
  checks they join already turn their own categories red.
- **SCR-2 Green needs proof.** A category is green only when at least one of its checks was tested (any result but
  skipped), none is unknown, and none has a finding above Info: the bar GRD-1 sets for an A. Anything else is red, and
  its reason says which: found, couldn't prove, or not tested. When every unknown in a category comes from HCN-5's
  no-canary choice, the reason reads "not tested: run without a canary" (a host reason, never a box string), and the
  category stays red.
  A category is not applicable only when every one of its checks was skipped and each skip's kind is `provider_terms`:
  a native adapter's PRV row excludes that provider-owned endpoint because the provider's terms do (PRV-5). In
  practice that is Cloud access (SEC-4 and AMP-7) on a hosted provider. Provider terms limit what Sandprobe measures,
  not whether a risk exists, so this rests on SCR-1's narrowed contract: on a hosted sandbox the metadata service and
  any Kubernetes API belong to the provider, and the box holds no cloud identity of the person's that these checks
  could reach. A credential of the person's own injected into the box (an environment variable, a key file) is still
  Secrets' to catch (SEC-1, SEC-3), never Cloud access's. The row reads "Not applicable: this box holds no cloud
  identity of yours that Sandprobe checks here; the provider's own endpoints weren't tested (their terms)", fixed
  text, and the line beside the score names the category with that provider's exclusion reasons from this binary's
  own PRV rows, never the report's text. A kind is never taken on the report's word: the scorecard derives each
  check's kind from this binary's own policy for the provider the run names (a native adapter's PRV-row exclusions are
  `provider_terms`; `run exec`'s and a shipped recipe's defaults are `opt_in`; any other provider has none), uses it
  only when the manifest records the same, and ANL-1 refuses a saved report whose recorded kinds disagree with it, so
  editing `SkipKinds` alone changes nothing. Only the host writes a kind, and only for a check it excluded
  under GRD-3's provider-endpoint gate (`SkipKinds` in the manifest, never in the probe's input); a skip without one
  (a report from before this rule, a survey-driven skip such as "no vsock device", the managed workload runners'
  exclusions) is plain "Not tested". The managed workload runners record no kind, so their exposure cards (SCR-4)
  stay out of six: the Nitro runner's exclusions are RUN-8's audit scope, not a provider's terms, and the Daytona
  workload runner, though it uses PRV-12's exclusions, keeps the common Nitro and Daytona ranking and the deploy
  runners' six-category check; `run daytona` itself reads out of five. Nothing the box returns, no unknown, and no `-no-canary` run makes a category
  not applicable: HCN-5's checks stay unknown, so their category stays "not tested: run without a canary", red, and
  the run incomplete. PRV-15's and RCP-4's default exclusions (`run exec`, `run kubernetes`) are kind `opt_in`, since
  the person may lift them, and on a Kubernetes cluster Cloud access is the category that matters most: when none of
  a category's checks was tested and its skips are `opt_in`, it stays red, and the reason reads "Not tested: opt in
  with -provider-endpoints SEC-4,AMP-7 if your provider's terms allow", naming those checks from the catalog
  (PRV-15's opt-in). The score is the number of green categories out of the
  applicable ones. A not-applicable row is never green and never counted as passed: it leaves the denominator, so a
  run with one reads at most 5/5 and is never shown or serialized as 6/6. Coverage still counts its checks as
  skipped (SCR-5), so the card keeps the unmeasured endpoints visible. The letter doesn't change: GRD-3's skips already never touch GRD-1 or
  GRD-2. `compare` reports a changed set of `provider_terms` skips as a changed setup (CMP-1's declared
  configuration), so a newly not-applicable category is never read as like-for-like, and a check that goes from
  tested to skipped stays coverage loss. An `opt_in` skip and one with no kind both read "Not tested", so a report
  from before this rule and a new `opt_in` one of the same box compare as a matched pair.
  A green row that rests on a check with no finding but no negative proof says so in one line ("not proven: DNS"),
  since that is KND-2's not proven, never a refusal; a check whose findings are only ever Info is left out of it. An invalid run (GRD-5) has no score. A full score therefore means
  no finding above Info and nothing unknown in the categories it counts, and is still bounded by GRD-4 and SBX-10.
- **SCR-5 Exposure and measurement coverage are separate.** Preserve SCR-2's RC
  score, but attach deterministic catalog-wide coverage to every valid scorecard.
  Partition each category's checks into proven pass/absence, findings (including
  Info), unproven not-found, unknown, scoped-out, skipped and missing. Only
  pass/absence, finding and not-found results contribute usable-result coverage;
  unknown, scoped-out, skipped and missing entries do not. An unknown check may
  have executed but stayed inconclusive. Complete coverage
  requires a pass/absence or finding for every check; a finding is a completed
  observation, never a security pass. List all gaps by fixed catalog ID. State
  category/check usable-result and completion counts beside the score in JSON,
  terminal and HTML, including workload scorecards. A green category and a full
  score never imply complete coverage, and coverage still counts all six categories,
  a not-applicable one's checks as skipped (SCR-2). Invalid runs claim no coverage; historical
  scorecards without coverage remain readable and never gain an invented complete
  status. Derive coverage only from graded checks and grading unknowns, never a
  provider flag, supplied counter, workload pass or configuration declaration.
  This adds no network checks, credential reads or provider-infrastructure probes,
  changes no scope exclusion, and changes no RC exposure verdict. Only synthetic
  public fixtures enter tests; private saved runs and accounts remain outside git.
- **SCR-3 Headline first, details in the appendix.** OUT-2's page, the terminal summary after a run, and the offline
  `sandprobe scorecard <report.json>` lead with the score and the six rows: name, question, green, red or not
  applicable (SCR-2), and a short reason built only from catalog IDs and titles, never from box strings (a
  not-applicable row's reason is the host's own skip reason). GRD-4's statement stays beside the score.
  Below the rows, "What we tested" gives each category a table headed "x/y tests run", with columns Severity,
  Details (the test as a plain question, what was seen, and the fix when it failed) and Result. Fail (a finding above
  Info; an indicator says it is a sign, not a confirmation) and Unknown sit on top, worst first. Pass (a refusal or an
  absence only, per rule 1), Info, N/A (nothing to test), No finding (which proves nothing) and Not run (with its
  reason) fold behind one accordion. For a test that didn't fail, Severity is what a failure would have been. One plain
  sentence per chain comes first. A canary receipt is described from the catalog, never from the grader's evidence text. The letter, the map,
  how the probe ran and what the grade covers follow in a technical appendix. The terminal keeps one appendix line
  pointing at the page, and `compare`'s text names each changed check by its category and question (its JSON and exit
  codes are unchanged). `scorecard` reads one saved report under ANL-1's input rules, makes no network call, writes
  the re-rendered page only inside the `-out` directory (named from the report's provider and run ID only when both
  are plain names, else `sandprobe-report.html`, and never through a symlink already there), escapes every control
  character of the report's text before it reaches a terminal, and exits as `profile` does (5 when invalid or
  incomplete).

## Auxiliary workload architecture, 19 November 2026

- **ARC-1 Image-compatible scheduling.** Receiver and control pods explicitly select kubernetes.io/arch=amd64,
  matching the tested linux/amd64 image in both local-build and CI-image modes. The agent's dedicated NodePool
  already selects amd64. This changes scheduling only; retain existing identity, network and cleanup controls.
  Test both auxiliary pod types in deploy/eks-agent/test_runner.py before live provisioning.

## Auto Mode DNS and execution diagnostics, 19 November 2026

- **GAT-3 Identity token lifetime.** Require the exact intended projected-token audience and path, but
  validate requested expiration as an integer from3600 through86400 seconds rather than exactly86400.
  The observed EKS admission value86360 is shorter than the prior one-day maximum; the one-hour minimum
  covers this bounded task's45-minute active deadline. Reject booleans, nonintegers, missing/extra fields,
  changed audiences/paths and values outside the range. Do not read token contents or grant a security pass.
  Replay credential-free, normalized live structural metadata offline through the existing exact guard;
  test lower/upper bounds and rejection cases before another run.

- **CLI-1 Supported client skew.** Pin the managed evaluation cluster to Kubernetes1.37 and check the
  local kubectl client before any cloud create. Require major1 and minor36..38, following the Kubernetes
  one-minor client/server skew policy (https://kubernetes.io/releases/version-skew-policy/). Record only
  canonical major/minor metadata. Reject missing, malformed or unsupported versions; explicitly pass the
  pinned server version to the cluster helper and verify the described cluster version. Do not replace
  the operator's global client; use a checksum-verified official binary in a task-specific tool cache.
- **CMD-1 Safe kubectl failure categories.** Preserve only fixed categories for recognizable kubectl
  authentication-exec failures, API unavailability or request timeouts, without exporting their raw error
  text. Unknown errors remain command_failed. This adds diagnostics, not mutation retries, credential
  fallback or a security pass. Test supported/unsupported skew, pre-create rejection, explicit helper
  version binding and error classification without exposing synthetic private error details.

- **GAT-2 Nitro runtime placement.** The live isolated-sandbox RuntimeClass declares the scheduling selector
  eks.amazonaws.com/nitro-sandbox=true; Kubernetes adds it to the submitted Pod. Explicitly include that
  exact selector together with the dedicated karpenter.sh/nodepool selector in the submitted task and
  expected returned structure. Reject missing, changed or extra selector entries. Preserve the dedicated
  node and DefaultDeny checks; do not accept arbitrary RuntimeClass additions. Persist specific guard
  rejection categories only from an explicit source-literal allowlist, never raw external error text.
  Test both required entries, unexpected additions and allowlisted versus external failure messages.

- **GAT-1 Readiness and diagnostics.** Before releasing model execution, journal fixed configuration,
  structure, environment, token-metadata, node and image guard stages. Retry only idempotent host reads
  (Kubernetes GET projections/templates/scalars and the fixed token os.stat command) up to3 attempts,
  with1-second pauses, and only for the existing sanitized command_failed category. Never retry mutations,
  host-release creation or model calls. Every required check must still return its exact expected result;
  exhausted retries fail closed and retain the guard stage. This does not establish the cause of the
  previous generic gate failure or turn missing evidence into a pass.
- **CLN-1 Update-in-progress teardown.** After checking the journaled cluster ownership marker, retry
  DeleteCluster only for ResourceInUseException explicitly reporting an update in progress. Bound this
  wait to60 attempts with the existing10-second interval and recheck ownership before each attempt.
  Other errors and exhausted waits retain state and fail with fixed messages. Existing caller deadline,
  cluster-deleted wait, exact node inventory and role cleanup guards remain in force. Test transient,
  persistent and unrelated errors with a fake AWS CLI; no new cluster is implied by these fixes.

- **IDN-1 Association idempotency.** CreatePodIdentityAssociation requires a33..126-character client request
  token (confirmed by the run-owned InvalidParameterException audit event). Derive a deterministic64-character
  SHA256 hex token from a fixed operation domain plus the16-character run ID, retain identical inputs on
  retry, and keep it distinct across runs. This token is an operation identifier, never an AWS credential.
- **IDN-2 Cluster-owned association cleanup.** An association belongs to its exact cluster. If a create did
  not return an association ID, never guess an association to delete. Defer that unresolved child while
  deleting the journaled cluster through its existing identity guards; after that parent is confirmed gone,
  mark the child deleted_with_cluster. A retained parent must leave the child unresolved and cleanup failed.
  On cleanup retry with a previously deleted parent, independently re-confirm that exact cluster name is
  absent before resolving the unknown association; an existing/replacement cluster or API error fails closed.
  Tests cover token bounds/determinism/operation use and parent success/failure/retry with an unknown child.

- **DNS-1 Auto Mode resolver.** For an AWS-described IPv4 Auto Mode cluster, derive its node-local
  CoreDNS address as serviceIpv4Cidr network address plus10, as documented at
  https://docs.aws.amazon.com/eks/latest/userguide/auto-net-pol.html (Determining the CoreDNS IP address).
  Require computeConfig.enabled=true and a canonical RFC1918 service CIDR with AWS-supported /12..24
  prefix. Allow only that resolver /32 on TCP/UDP53. Do not require a kube-dns Service, install a new DNS
  addon or broaden network access. Missing/malformed cluster metadata fails closed. Non-Auto Mode is unsupported.
- **RUN-7 Execution diagnostics.** Persist fixed stage labels before image preparation, cluster creation,
  node configuration, registry publication/validation, DNS selection and task setup/execution. On failure
  preserve only the stage and a fixed failure category; never subprocess/SDK output, credential contents
  or raw exception text. Export stage/category in incomplete reports after managed cleanup. Missing evidence
  still cannot earn a pass. Tests cover canonical/invalid CIDRs, missing Auto Mode flag, exact DNS /32 and
  failure-stage retention. This repairs setup/observability only; live runs require user authorization.

## Verified CI image transport, 19 November 2026

- **IMG-6 Current-main availability.** Build and retain the verified image artifact on every main push,
  including documentation-only commits, because daemonless preflight requires the exact clean HEAD SHA.
  Keep pull-request path filtering, private one-day retention, pinned actions, offline-only validation and
  no cloud credentials/live tests in CI. Do not weaken source matching or accept an ancestor/dispatch
  artifact as a fallback. Verify the resulting main-push artifact and read-only preflight after merge;
  runtime code and the completed live result remain unchanged.

- **IMG-1 Daemonless option.** Add an explicit --image-run-id mode using gh and Skopeo instead of a local
  Docker daemon. Pin all GitHub API requests to github.com regardless of GH_HOST. Accept only a successful
  completed push-to-main run of this repository's networked-agent
  workflow whose exact source SHA matches the clean local checkout. No fork/PR/dispatch run, arbitrary URL,
  image tag or external repository is accepted. This changes image transport only, not the sandbox/model scope.
- **IMG-2 Artifact provenance.** CI exports its tested linux/amd64 image as a Docker archive with a bounded
  manifest containing source SHA, successful run attempt, image/config digest, archive SHA256 and size.
  Bind the exact immutable artifact ID/name to that run/attempt, with the API's outer ZIP digest and size.
  Stream with compressed/unpacked byte and deadline limits; do not use generic ZIP extraction.
  Upload privately with one-day retention only on main pushes. Before any cloud create, download the exact expected artifact, reject extra/
  symlink/nonregular files, bound archive size to512MiB, verify source/hash/size and read the single image's
  bounded config without extracting layers. Config bytes must match the recorded image ID and linux/amd64.
  This is authenticated CI provenance and integrity checking, not hardware attestation or a security grade.
- **IMG-3 Registry and cleanup.** Copy only that verified archive into the run-owned ECR repository. Pipe the
  normal ECR login password directly to Skopeo with an explicit private per-run auth file; never expose its
  value, use a global credential store or forward operator credentials into CI/the workload. Remove the auth
  file after push on success/failure and remove the per-run image download during managed cleanup. Preserve
  exact ECR lifecycle guards and all model/account/approval/pod/measurement requirements.
- **IMG-4 Tests.** Cover run metadata mismatch/fork/event/failure, malformed/oversized archives, config/source/
  archive digest/platform mismatch and nonregular/extra paths. CI verifies an archive of the actual tested
  image before upload. A missing/expired/mismatched artifact fails before creating paid resources. Existing
  local Docker build mode remains supported. Map to deploy/eks-agent/test_image_artifact.py and test_runner.py.
- **IMG-5 Darwin transport.** macOS Skopeo cannot repeatedly open a shared-offset /dev/fd archive.
  On Darwin only, use the exact archive pathname beneath the run's owner-only0700 directories, retaining
  its verified read-only descriptor. Before and after each source operation require an owner-matching
  regular0400 single-link file, matching path/descriptor identity, size/timestamps and approved archive hash.
  These detect changes within a trusted host-user boundary, not immutability against a malicious same-UID
  host process. Linux retains descriptor transport. Before scheduling any workload, inspect the destination
  manifest at the returned ECR digest and require its config digest to match the verified CI image ID.
  Mismatch fails closed into managed cleanup. Test transport selection, replacement/symlink/content changes
  and destination-config mismatch; also exercise the actual archive with local Darwin Skopeo before retrying.

## Lightweight Bedrock model compatibility, 19 November 2026

- **MOD-4 Native response contract.** For exactly mistral.ministral-3-3b-instruct, request Converse
  outputConfig.textFormat JSON Schema with one required solution.py string and additionalProperties=false.
  Preserve strict local response/source validation, size bounds, nine checks, two-call/2048-token limits
  and all credential/network policy restrictions. No unstructured or alternate-endpoint fallback. Other
  supported models retain their request shape. Set the fixed client read timeout to120 seconds to cover
  AWS's documented initial grammar compilation of up to90 seconds; retries remain disabled. Follow
  https://docs.aws.amazon.com/bedrock/latest/userguide/structured-output.html and the model's AWS card.
- **MOD-5 Failure-stage metadata.** A failed guest task may report only a strict failure object with
  schema sandprobe.agent-task-failure/1 and one fixed stage: client_initialization, model_request,
  response_format, artifact_write, functional_checks or execution. Never serialize exception text,
  credentials, model responses or generated source as diagnostics. Historical failed task=null remains
  accepted. These are untrusted guest diagnostics, never a security pass or a provider grade. Test API
  request-schema compatibility, model-specific selection, failure privacy and malformed stage objects.

- **MOD-1 Model choice.** The coding workload does not require Claude or Codex. Add the explicitly supported
  direct regional model mistral.ministral-3-3b-instruct alongside the existing Claude model syntax. Preserve
  one exact foundation-model IAM resource and all existing account, agreement, region, identity, endpoint and
  lifecycle checks. Do not allow inference-profile/ARN/wildcard IDs or automatically subscribe to a model.
- **MOD-2 Response framing.** Accept one bounded JSON response either directly or inside one exact whole-response
  json code fence (or unlabelled code fence). No leading/trailing prose, multiple values, duplicate/extra keys,
  arbitrary language fences or source-only fallback. The same solution.py key, source digest binding and fixed
  functional checks apply. A format/model failure stays a workload failure, never a security pass.
- **MOD-3 Scope and tests.** A live run is one managed disposable run with the small already-enabled model and
  existing call/token bounds, and needs the operator's recorded approval, which is not an independent AWS Support
  verification. Unit tests cover allowed model/exact IAM scope, rejected IDs and direct/fenced/malformed responses.
  Existing Linux coding and receiver calibration remains required before merging and running. Retries after a
  failed setup are serial, of the same model/task/account profile, each cleaned up before the next. Preserve call/
  token/deadline/resource limits, with no security-probe expansion.

## Managed networked-agent evaluation, 19 November 2026

This implements the previously prepared profile. AWS testing-approval requirements remain; authorization to
implement or merge is not proof of third-party approval. No CI job uses cloud credentials.

- **RUN-1 Managed lifecycle.** Add a Python runner with preflight, run and cleanup commands. Live preflight
  requires a caller-recorded AWS EKS testing-approval reference, the exact disposable account the operator names,
  an already-enabled regional on-demand Claude model/agreement, Docker and working CLI tools. No subscriptions,
  inference-profile fallback, additional accounts/regions or production resources. A private locked journal records
  resource intent before create and create-returned identities immediately afterward. Require no-follow regular
  files owned by the caller, private modes, atomic durable writes and a private exclusive lock. Unknown create outcomes are
  retained for reconciliation, never silently cleared or deleted by a guessed name. Delegate the dedicated cluster
  lifecycle to deploy/eks.sh using a unique journal. Every failure enters bounded cleanup; incomplete cleanup is
  explicit, retained and makes the evaluation incomplete. Do not print subprocess output/errors or credentials.
- **RUN-2 Scoped resources.** Create a run-owned ECR repository/task image, IAM role with exact cluster/ns/SA
  Pod Identity trust and one-model permission, association, fresh namespaces and Kubernetes resources. Use
  create-only requests and UID-preconditioned deletes. Check RoleId, association ID and ECR creation fingerprint/
  tags before teardown; disclose name-addressed API residual races. Configure a new NodeClass/NodePool with
  DefaultDeny and force the agent onto it; enable the network-policy controller before task scheduling. Verify
  host-resolved model addresses and actual cluster DNS, image digest and narrow returned pod fields. No broad
  environment/credential-object dumps. The workload's Pod Identity mount is intentional and checked by presence.
- **RUN-3 Representative coding task.** Supersede NET-1's three-record aggregation with a small synthetic
  coding project: Claude returns only a bounded JSON solution.py, the sandbox runs fixed functional tests, and
  may request one bounded repair if they fail. Compare exact bounded results against independent expected
  cases outside the generated module interpreter; missing completion/output or exit0 alone cannot pass. Only the predetermined Python test command runs, never model
  shell commands; no generated code runs on the host. Output is at most16KiB per response,2048tokens/call,
  two requests/process, five seconds/test attempt and a bounded Job. Kill/reap the generated process group
  on every completion/timeout; detached descendants remain a risk until container teardown, so do not use
  same-container negative measurements to certify containment. Child output is captured/discarded rather
  than logged; the child receives a minimal environment without SDK credentials. The intended Pod Identity file
  is still in the same sandbox, so this is not a credential-separation claim. Report task success, attempted model
  calls, functional-test result and artifact digest; failure is visible independently of security assessment.
- **RUN-4 Controlled measurements.** Use only run-owned synthetic fixtures: an agent-owned writable workspace,
  a root-owned unreadable synthetic file built into the task image, an image-root write attempt at a dedicated
  nonexistent fixture path, own identity/capability metadata and a run-owned TCP receiver with a known nonce.
  A separate control must reach that exact receiver before and after the agent's attempt. Use distinct
  host-issued nonces for agent and controls and host-fetched exact-run receiver receipts. A receiver-recorded
  agent nonce is a policy violation. Explicit permission/refusal errors with healthy controls are a bounded refusal;
  timeout, missing/malformed control or arbitrary errors remain inconclusive. No host escape, provider metadata,
  credential discovery, real secret reads, other-process inspection or arbitrary destination probing is added.
- **RUN-5 Versioned scoped assessment.** Emit sandprobe.agent-evaluation/1 with source/run/config identity,
  independently visible workload status, fixed required properties and passed/failed/inconclusive outcomes.
  This is a configuration/workload assessment, not a provider-wide letter, attestation or a host/hypervisor test.
  Required security properties include bounded observed identity, synthetic protected-file refusal, writable
  workspace, image-root write refusal and controlled receiver egress denial. Any observed security violation
  produces scoped F with uncertainty retained only when supported by host-collected receiver evidence;
  workload failure alone produces no security letter. Guest measurements share a trust boundary with generated
  code and are self-reported/inconclusive, even when they claim a refusal. This version cannot assign A.
  A requires a future independently protected measurement channel and calibration, not guest success flags.
  Bind evidence to exact run/pod/image/config/nonces; reject missing/duplicate/unknown properties and forged
  cleanup or receiver claims. Cleanup status comes only from the host lifecycle, not workload output. DNS is
  intentionally allowed, other destinations and reset/cross-tenant/hypervisor protections remain unassessed and
  listed. Do not reinterpret old reports or change legacy grades/gates. Calibrate this fixed policy on independent
  allowed/refused/unknown/forged-input and broken-control cases before live use; a timeout can never earn A.
- **RUN-8 Same-workload standard grading.** The managed Nitro runner holds the original workload
  container alive after its bounded model/file/test task, including a reported task failure. It runs the
  shipped Linux probe as the same uid in that same namespace/pod UID/image/configuration, before stopping
  the Job. No replacement pod or process-topology change may improve the score. A host-only bridge binds
  the recorded cluster endpoint, run label, original Job UID and pod UID, image digest and configuration
  digest before upload. Endpoint, namespace, original Job/pod UID, image/configuration and zero-restart guards apply to every upload/probe invocation. Report the normal
  `host.Execute` / `grade.GradeBytes` / `report.Build` result without altered thresholds, alongside the
  separately reported workload outcome. Missing evidence remains unknown under the standard grader;
  A is never a target achieved by hiding necessary workload access. This grades a tested configuration,
  not every configuration offered by a provider.
  A fresh standard canary is managed by `deploy/canary.sh` in the private run folder with fresh `agent-<runID>.probe.ac0.dev` DNS, with durable exact-ID
  state and pre-create intents; unresolved outcomes retain the deployment and block address release; existing canaries/DNS are never adopted. Its control and health evidence use the existing SSM
  adapter and standard signed receipts. The workload policy is unchanged for grading: model TLS, intended
  Pod Identity and cluster DNS remain available; the canary is not added to the allowlist. Probe traffic
  targets only that run-owned canary. SEC-4, AMP-6, AMP-7 and EGR-3 are explicitly excluded from this
  defensive configuration-audit scope to avoid provider-owned endpoints; PER-5 remains skipped because
  no reset is performed. Exclusions are printed, never counted as negative proofs. Native DNS canary
  receipts may demonstrate the risk of permitted DNS, and the unchanged grader may return F.
  Workload readiness and grading have finite deadlines inside the Job deadline. Any bridge/collection
  failure is reported as missing standard assessment and cannot fall back to a reassuring custom grade.
  Cleanup still executes on all paths and independently covers the run-owned canary, releasing it only after the probe cluster is confirmed gone. Standard reports
  initially record cleanup pending; the host records final cleanup separately, never claiming it early.
  Tests: namespace/UID/Job/image/config/endpoint binding rejection; same-pod grading ordering and task-failure
  handling; standard grading artifacts and honest failure reporting; durable canary state and cleanup.

- **RUN-6 Tests and rollout.** Unit-test lifecycle failures/unknown creates, exact-identity cleanup, restrictive
  manifests/trust, functional task/repair/error budgets and assessment uncertainty. Execute known-good and
  deliberately-broken synthetic local containers plus controlled receiver tests in credential-free Linux CI.
  Stub model replies are labeled and never become live model/Nitro results. Map to deploy/eks-agent/test_*.py
  and .github/workflows/networked-agent.yml. Independent security and code reviews cover spec and code before
  merging; run data is credential-scanned and kept internal. No unattended continuous provider probing.

## Network-enabled agent reference preparation, 19 November 2026

The workload is a useful network-enabled task rather than total network isolation. This extension prepares
artifacts and local tests; it does not authorize a live EKS security assessment or assign a replacement grade.

- **NET-1 Usable workload.** Prepare a non-root Nitro Job whose task process calls Claude through Bedrock Converse once,
  asks it to aggregate fixed nonsecret records, independently verifies the returned JSON totals, and writes the
  result in ephemeral `/workspace`. Bound model output to128tokens/4096bytes, connection5s/read45s and
  Job180s; disable SDK model retries, Job retries/restarts and parallel execution. The future live runner must
  enforce a run budget; one call per process is not a global exactly-once guarantee under Job replacement. Reject duplicate/extra JSON
  keys, trailing values, booleans/floats and wrong totals. No generated commands are executed.
  A model failure, malformed response,
  incorrect totals or missing output fails the task; no synthetic answer substitutes for a failed live call.
- **NET-2 Scoped connectivity.** Keep networking enabled. A namespace-scoped default-deny policy allows only
  pinned, host-resolved Bedrock runtime IPv4 addresses on443, the recorded cluster DNS address or kube-system CoreDNS pods on53 TCP/UDP,
  and the documented Pod Identity credential surrogate169.254.170.23 on80. Fix the SDK endpoint to
  bedrock-runtime.us-west-2.amazonaws.com with certificate verification and no custom proxy/endpoint fallback.
  Record caller-supplied addresses as unverified; the live runner must verify and record hostname/IP provenance.
  DNS queries are permitted and can
  carry information; this is not a no-exfiltration profile. DNS or endpoint-address changes require regenerating
  the plan, never falling back to unrestricted egress. These Kubernetes rules need a live enabled/enforcing
  network-policy controller and startup enforcement; rendered configuration alone proves nothing about enforcement.
- **NET-3 Identity and isolation.** Use a new run-owned service account and a dedicated Pod Identity role with
  only bedrock:InvokeModel on one exact regional foundation-model ARN, with trust scoped to the exact cluster,
  namespace and service account. Require pre-enabled model access/agreement and direct regional on-demand
  support. Do not subscribe, broaden IAM or switch to cross-region inference to make it work.
  Never inject operator credentials.
  The intended workload-role credential is authorized access, not an unexpected credential leak. Disable ordinary
  Kubernetes API-token automount. The sole credential-use exception is SDK protocol use of its own injected
  Pod Identity token/credentials, without logging/export. Require the expected injection and only the SDK
  container-credential provider; disable environment/shared-file/instance-metadata credential fallback.
  Keep UID/GID10001, no privilege escalation, dropALL, read-only root,
  RuntimeDefault seccomp, no host namespaces/mounts, fixed limits and ephemeral tmp/workspace. Use a pinned
  image containing the task and locked SDK dependencies. No runtime package install, shell/model-code execution,
  secret-value logging or broad credential inspection. Errors use fixed messages.
- **NET-4 Plan and lifecycle.** Render Kubernetes manifests and a proposed model IAM permission policy to stdout only.
  Require a fresh run-owned namespace and absence of additive allow policies before live deployment.
  Rendering performs no API calls or deployments. Reject unsafe names, mutable image references, broad model
  selectors, private/link-local/malformed Bedrock addresses, wildcard resources and absent endpoint/DNS context.
  The deployment must use the existing dedicated Sandprobe EKS lifecycle, track every extra IAM/Pod Identity
  resource by create-returned ID, and confirm UID-checked cleanup. Until that managed runner and AWS testing
  authorization are available, do not apply the manifests, create resources or describe this preparation as live-tested.
- **NET-5 Evidence and grading.** Require successful model/file work plus independently controlled allowed and
  forbidden tests. A healthy receiver plus timeout alone is not negative proof; require trustworthy refusal/deny
  evidence or report inconclusive. Test only our disposable resources and synthetic data. Do not contact arbitrary
  forbidden external services or probe AWS control endpoints. A model failure cannot be hidden behind good
  security results. Preserve all legacy grades and explain their context limitations; do not assign A from
  manifests, IAM intent, unavailable tests or mocked model replies. Further protected-resource/reset measurements
  and grading calibration remain required.
- **NET-6 Offline tests.** Test render validation, exact egress/identity/resource configuration, scoped IAM,
  and workload success/error/wrong-answer cases using a stub SDK. A CI-only local container check uses the
  same pinned image and a stub model, no cloud credentials or external traffic. Stub success is explicitly not a
  live model result or Nitro security pass. Map to deploy/eks-agent/test_profile.py and test_task.py.

## Workload-aware grading, 20 November 2026

Repeatedly reproducing the legacy F is not the goal: the benchmark
must distinguish permitted workload capabilities from violations of the sandbox's boundary.

- **WGR-1 Fixed benchmark contract.** The host declares `networked-coding-v1` BEFORE the
  workload is released (and remains immutable through the probe), bound to the original box UID, immutable image, configuration digest and run.
  Its boundary is the verified private agent container. Its own processes, ephemeral
  `/workspace` writes and the exact one-model identity projection are permitted capabilities,
  not proof of access to another principal. Root/capabilities remain a failed configuration
  requirement, not by themselves proof of a VM/host escape. Required direct canary TCP
  routes443/22/80/8080 are forbidden; DNS resolver access is allowed but explicitly broad
  DNS is a residual-exposure warning. This profile cannot earn A while that exposure exists.
  The fixed protected resource is the image's root-owned0400 synthetic marker
  `/opt/sandprobe/protected-marker`, outside the allowed workspace. Existence/ownership
  and private-container/identity context must be verified by the host gate, not inferred
  from an arbitrary path, UID or a user-supplied saved report. An unconstrained caller may
  not allowlist arbitrary secrets, drop required controls or edit policy after observations.
- **WGR-2 Structured evidence.** Preserve all target records and twin results on local
  finding observations as well as passes. This retains the distinction between readable
  intended credentials and a protected resource; never parse prose to assign trust roles.
  Add the fixed protected marker to SEC-3's pre-run plan. File-open evidence carries
  pinned FD device/inode metadata; expected identity and protected-fixture attribution
  requires the exact frozen match. Mixed finding proofs still validate every refusal
  errno, absence and both twins, so permitted positives cannot mask instrumentation faults. A missing file, missing target,
  broken allowed/refused twin, malformed proof or unsupported ownership context is unknown,
  never a protection pass. Credential contents are never read; only openability is tested.
  Expected identity paths are only the exact verified token projection and its pre-release
  canonical alias, bound by device/inode and verified read-only projection. Directory or
  timestamp-pattern allowlists are forbidden; a rotated/unbound alias stays unknown. Unexpected readable credential paths remain unattributed/unknown,
  not silently permitted and not automatically called protected-secret theft.
- **WGR-3 Versioned conditional configuration grade.** This is a fixed-workload
  configuration-conformance benchmark under SBX-10's honest host-shipped probe assumption,
  not a measured containment/attestation grade against actively malicious same-UID code.
  Every output prominently separates `configuration_grade` from
  `security_assurance: not_established_against_active_guest_tampering`. A/B never mean
  safe deployment or verified resistance to forged in-guest observations. A/B require
  successful workload and all valid required proofs and host/IAM/fixture guards. This
  deliberately does not upgrade RUN-5's self-reports into security assurance.
  Implement the host's workload grade in Go beside the legacy
  grader, not in a Python exception list. Revalidate the underlying observations/manifest
  and normal canary evidence; ignore any supplied legacy letter. Grade the strongest proven
  violation: F only protected synthetic-resource access plus forbidden canary delivery;
  D protected-resource access or proven forbidden canary delivery alone;
  F describes combined synthetic exposures, never proof secret contents were read/exfiltrated; C a failed required
  privilege/write guardrail or required evidence missing; B all required negative proofs
  with the explicitly permitted broad-DNS exposure; A requires all required proofs and no
  such exposure, and is unavailable in this initial broad-DNS profile. Missing evidence
  caps a better result at C but never hides D/F. Successful workload execution is reported
  separately and required for an acceptable benchmark outcome. A failed/missing workload
  cannot produce an acceptable A/B outcome. All grades name their profile, coverage and
  assumptions; none certifies host/hypervisor isolation or an entire provider.
  Required controls are marker access refusal; AMP-2/3 (non-root, zero effective/permitted/inheritable/bounding/ambient capabilities, and no-new-privileges),
  PER-2 (PATH integrity), AMP-8.sys (kernel write permissions), and four direct TCP routes.
  Writable ephemeral home/config files and agent-owned process access are reported as
  allowed capabilities. Names-only SEC-1 indicators do not establish stolen secrets.
  Unattributed control sockets, privilege amplifiers or unrecognized credential surfaces
  require explicit review/unknown coverage; they cannot disappear into an A/B grade.
  Every catalog row is explicit: required controls as above; SEC-1 names are indicators
  (unknown unrecognized names need review); SEC-2/5 and AMP-5 concern the verified private
  agent container's own processes/services; PER-1/3/4 are permitted only for home/workspace
  targets, otherwise review; SEC-3 permits only the bound identity projection while requiring
  the protected fixture; EGR-1 is permitted broad-DNS exposure; AMP-1/4/8.blk are review
  surfaces when found, with absent/scoped-out results disclosed. SEC-4, EGR-3/4/6,
  EGR-5.53u, PER-5 and AMP-6/7 are outside this fixed baseline and explicitly listed as
  not assessed; their observations remain visible. Nothing implies untested provider
  boundaries held. Unknown required/context/review evidence prevents conformant A/B.
- **WGR-4 Host verification and output.** Before releasing the workload and again before
  grading, verify the exact role's only inline policy equals the single-model policy and
  no attached/extra inline policies exist. This verifies requested identity configuration,
  not all effective AWS permissions, resource-policy grants or organizational controls. Bind the protected marker's expected owner/mode
  and nonempty regular-file device/inode metadata to the verified image. The primary managed result is
  the versioned workload assessment, with legacy raw findings/letter retained separately
  for diagnosis. Never rewrite historical F reports as authenticated new grades. Saved-run
  replay is explicitly retrospective/unauthenticated and cannot establish a live A/B.
- **WGR-5 Calibration before another provider run.** Test a permitted own-process/identity/
  workspace case without F; protected-resource exposure with/without forbidden egress;
  allowed DNS versus forbidden TCP; root configuration mismatch without assumed escape;
  missing/absent/forged marker/twin/identity/nonce/coverage; workload failure; unchanged
  legacy grading; and immutable pre-run contract. Use synthetic, credential-free fixtures.
  Complete independent spec/code/security review and offline calibration first. No new
  provider-wide claims or cloud reruns are justified just to reproduce the old letter.

- **WGR-6 Report-format compatibility watch.** A credential-free, offline report compatibility check runs
  against a retained collection of a recorded managed run. That collection is a real provider's, so the check runs
  where the operators keep their records, not in this repository's CI. Rebuild the report with
  the current formatter, validate the literal JSON keys/types consumed by the managed
  collector, preserve the frozen contract/raw evidence bindings, then feed the serialized
  result through the current workload finalizer. It must retain conditional configuration B,
  separate legacy F and the assurance/input-verification labels for that fixture. No live
  cloud/provider calls, model calls or raw credential inputs are used. Layout, colors and
  incidental HTML wording are not pinned by this guard. Intentional protocol changes need
  an explicit consumer/schema migration; silently dropping context or reintroducing a
  single misleading headline grade fails CI. This is a persistent PR regression check,
  not a claim of continuous human review or a guarantee against every possible conflict.

- **WGR-7 Portable workload identity declaration.** A second-provider run must not
  fabricate an EKS identity projection or change the benchmark after observing its
  results. The existing version1 contract remains Nitro-only with its exact UID/GID10001
  and token bindings. A version2 contract may declare `provider=daytona`,
  `identity_mode=host_controller_no_guest_credentials`, and frozen positive non-root
  `agent_uid`/`agent_gid` values. The model controller stays outside the guest; model
  management credentials are not injected into the sandbox. This is a distinct agent
  deployment pattern and is disclosed beside any comparison with in-guest Nitro inference.
  Version2 requires empty token path/device/inode fields, the same immutable image digest,
  run/box/configuration/identity-policy and protected-fixture bindings, and all existing
  host-verification flags. The identity-policy digest binds the host's pre-run no-guest-
  credentials declaration; it is not an IAM-policy verification or attestation.
  Provider/mode/UID/GID are forbidden in version1, and unsupported provider/mode/schema,
  root principals, missing image digest or mixed token modes are rejected. A changed
  observed UID/GID is a guardrail failure. Zero capabilities (all five sets), seccomp,
  no-new-privileges, protected-resource proof, required route proofs, workload success
  and all other WGR-3 coverage rules remain unchanged. No version2 credential path is
  implicitly permitted; credential-shaped AWS variable names become review/unknown
  rather than inheriting Nitro's intended-identity allowance. Image public-key name
  GPG_KEY remains an indicator, with no secret-content claim. Missing native provider
  verification or required evidence prevents A/B; no historical report is upgraded.
  This change only adds offline contract/grader support. A separate reviewed managed
  runner, scoped account access and cleanup verification are required before live use.

- **WGR-8 Native snapshot evidence gaps.** Version2 may bind a Daytona snapshot UUID
  in `snapshot_id` while `image` is empty and `image_content_verified=false`. This
  records the selected native artifact honestly when the API exposes only mutable
  tagged registry references. It never substitutes a hash of a tag/name for an image
  digest. A required `image-content-binding` control remains unknown, preventing A/B.
  Verified version2 image content requires an actual OCI digest and the explicit
  verification flag; version1 keeps its existing exact digest requirement and rejects
  both portable-only wire fields. All other version2 contract, proof, grading and
  assurance rules remain unchanged. Snapshot identity does not establish image bytes.
- **RUN-10 Managed Daytona workload.** One own disposable Daytona workload/configuration
  run, with an owner-only key file. Use the pinned SDK and original-ID/creation/organization/run-label lifecycle guards,
  one create with no automatic retry, fixed US CPU snapshot resolved by UUID before
  create, private ephemeral sandbox, no secrets/volumes and15-minute idle stop.
  Read back the selected snapshot and network allow list before/after execution.
  Management API credentials stay on the host. Trusted management setup may run as
  root solely to prepare root-owned synthetic fixtures and launch the workload as
  UID/GID10001 with empty capability sets and no-new-privileges via setpriv. Never
  attempt to acquire privileges from the agent principal. Provider-default seccomp
  and filesystem configuration are measured, not invented. Missing native configuration
  verification stays unknown. The API's `public=false` alone is not proof of a private
  process namespace; do not set the corresponding host-verification flag from it.
  Freeze and sync the contract before the first model request. Model calls use the
  existing fixed regional Bedrock Ministral3B on the host (maximum2 calls), while the
  identical CSV task and9 independent cases run only inside the original sandbox.
  A TLS handshake to the fixed regional model hostname verifies intended guest network
  connectivity separately; no guest model credential is injected. This external-controller
  deployment pattern differs from Nitro's in-guest inference and must remain explicit.
  The workload and probe use the same principal/wrapper and unchanged network policy.
  Scope the existing probe to guest configuration, owned synthetic fixtures and our
  run-owned canary. Exclude metadata/proxy/vsock/Kubernetes/public-upload checks and
  reset persistence; no provider-control request, exploit, real secret read or other
  tenant. A dedicated canary is created and cleaned only by the existing managed script
  with its own state/domain and a strict optional `SANDPROBE_CANARY_NAME` namespace
  (`sandprobe-canary-` plus the16hex run ID), never an existing operator canary.
  The existing default namespace and guard remain unchanged for other callers. The operator's fixed AWS
  account (`SANDPROBE_AWS_ACCOUNT`), region and profile (`SANDPROBE_AWS_PROFILE`, and `PROFILE` for the deploy
  scripts; neither has a default) guards apply to canary and model calls.
  A new managed wrapper journals intent before provisioning, retains ambiguous creates,
  guarantees bounded cleanup on ordinary failures/signals, and offers cleanup recovery
  by recorded IDs. Verify original sandbox absence/terminal state and canary/DNS cleanup.
  Export raw observations, contract, workload, legacy diagnostics and our primary workload
  assessment after a credential scan; do not substitute the six-category generic score (SCR-1).
  Exit5 retains incomplete execution/assessment/cleanup; D/F exits6; exit0 requires
  passing benchmark requirements and confirmed cleanup, not a security certification.
  Scope: targeted own guest configuration/functional tests and owned-canary traffic only;
  PRV-12's exclusions stay in force. Nothing here is a provider waiver or permission to test
  Daytona's infrastructure.

- **RUN-11 Preparation diagnostics and reviewed retry.** A preparation that returns no
  workload/probe assessment is retained as a failure record, never called a graded run.
  The native API represents mutually exclusive network modes with nullable booleans:
  an exact nonempty requested IPv4 allow list may coexist with an unset `networkBlockAll`.
  Reject explicit block-all, different/missing allow lists and unexpected domain filters;
  do not require an explicit false for the unused mode. This verifies configuration only.
  Persist fixed host execution stages, create-attempt status, safe error categories,
  provider-call success metadata and boolean native-policy comparisons on every exit,
  before cleanup where applicable. Never persist command text, arbitrary SDK errors,
  environment values or credentials. Split root preparation into fixed observable steps.
  A positive completed host status stating create was never attempted may resolve an
  absent journal; missing journal/status after a launch remains ambiguous and retains
  the receiver. Interrupted processes cannot fabricate a completed no-create status.
  One reviewed preparation retry is permitted after the prior attempt's confirmed cleanup.
  It is a bounded continuation of the still-unrun workload, not an automatic SDK retry
  or additional security-testing scope. The guest TLS check connects to one frozen model endpoint IP while still
  verifying the fixed regional hostname, avoiding a second resolver selecting a
  different address outside the declared allow list. Stop after any completed workload/assessment,
  retain every attempt and all existing original-ID/cleanup/probe-exclusion rules.

- **RUN-12 Verify manager prerequisites and model client before provisioning.** A
  preparation that stops at the guest prerequisite gate must not infer which prerequisite failed.
  Record source-fixed, typed readiness metadata (actual manager UID/GID and executable
  availability) before enforcing prerequisites. The API's requested user is not a
  measurement of the toolbox process UID. Trusted management may use the image's
  intentionally configured noninteractive guest administrator path (`/usr/bin/sudo -n`)
  when its SDK process is not root, only to perform setup and invoke the existing
  privilege-drop wrapper. Confirm that path actually runs as UID0 first; refuse it
  when the manager already has the benchmark agent UID10001. This is normal authenticated
  administration of our own guest, never an agent privilege-acquisition test. All
  workload/model-generated code and the probe still run as10001 with the same clean
  environment, dropped groups/capabilities and no-new-privileges. No sudo from the
  agent principal, root-generated workload execution or weakened grading is allowed.
  The installed AWS CLI lacks the native response-schema request field. Use the exact
  existing hash-locked Nitro boto3/botocore model client in a separate host interpreter,
  verify its version/request shape offline before receiver creation, and bind its STS
  account to the fixed experiment account before any model call. Preserve fixed region,
  model, timeouts, maximum2 requests and disabled SDK retries; no subscriptions or
  provider/region fallback. A finite final preparation continuation after
  cleaned, ungraded failures is permitted to complete a still-unrun benchmark.
  Stop on any further prerequisite failure, completed assessment or cleanup uncertainty;
  preserve all attempts. New prerequisites are checked before provisioning where possible.

- **RUN-13 Offline repair after the final bounded attempt.** EGR-6 is never passed
  as a provider exclusion, which Execute rejects: Plan already skips unapproved public-upload
  checks. A repair never reuses a staging file made0444 after the first upload, which a
  non-root manager can't replace. Use fresh, unpredictable,
  strictly validated staging paths for each solution upload. Staging belongs to trusted
  management, not necessarily root. Agent workspace writes retain UID10001 and all
  existing ownership/no-follow/link-count checks. Exercise consecutive uploads with a
  nonroot filesystem principal and the exact collector options offline.

- **RUN-14 Renewed Daytona workload continuation.** A continuation may fix issues and
  rerun until the same model workload used for Nitro can be evaluated on Daytona,
  within provider terms and scope restrictions. Preserve the identical prompt/parser/nine cases,
  fixed regional model and maximum2 requests per attempt. Each managed invocation
  retains a fresh run ID and original-ID ownership journal; do not retry ambiguous
  creates or continue while cleanup is uncertain. After a runner failure, retain
  evidence, correct the spec/code with independent code/security review and offline
  validation, and use a new clean reviewed source commit for the next attempt.
  No weakening of workload checks, required controls or grading is permitted.
  All existing endpoint exclusions, agent/management role separation and cleanup
  verification remain. Stop on a completed workload/assessment, suspected provider
  vulnerability or uncertain cleanup; no repetition to obtain a better grade.

- **SCR-4 Workload exposure headline.** The six-category scorecard (SCR-1)
  is the common exposure ranking for Nitro and Daytona workload runs. Compute it from
  the same standard observations and proofs using SCR-2, never from a supplied
  letter or workload-context permission override. Retain a separate versioned
  exposure-scorecard artifact, make it the headline of new workload HTML, and
  include it in the managed evaluation. Keep the existing workload configuration
  assessment, completeness, unknowns, not-proven observations and assurance limits
  visible alongside it. A numeric score cannot waive missing proof, certify a
  provider or become an A–F conversion. Unchanged legacy rendering entry points
  preserve historical output. Shared summary recomputation and the native Daytona
  runner must use identical score rules. Existing exit/cleanup gates remain.

- **RUN-15 Protected startup configuration, writable project.** Improve the
  configuration shared by the Nitro and Daytona workload runs: HOME points to an
  owner-root0555 directory under the owned /opt/sandprobe fixture, with protected
  ancestors. Project writes and cache writes remain available under /workspace;
  temporary files remain available under /tmp. The real workload, generated-code
  verifier and static probe use the same declared HOME. The host checks owned-home
  metadata/identity before and after the workload. Do not weaken mandatory checks,
  hide writable paths, remove required model identity or change prompt/nine cases.
  Record the changed execution configuration and validate both refusal of startup
  writes and successful project/cache writes with the unchanged functional task.
  This improves a configuration surface, not reset persistence or host isolation.
  A live evaluation runs one fresh managed workload/assessment per provider,
  serially, from the exact clean merged source. Retain scorecard scores, unknown/not-proven
  checks, separate workload conformance and all cleanup results. Use the existing
  scripts, original-ID journals, fixed account/region/model and request budgets;
  endpoint exclusions stay unchanged.
  Stop each line after the completed assessment, unexpected protected delivery or
  cleanup uncertainty. Do not repeat a completed run to obtain a higher score.

- **RUN-16 Isolated receiver lifecycle and pre-create proof.** Nitro must use the
  same per-run receiver namespace pattern as Daytona, never adopt or delete an
  existing shared receiver. Before delegate startup, durably bind an outcome
  record to run, nonce, exact delegate digest and original state path. The delegate
  must durably mark mutation possible before its first cloud mutation; failure to
  write that barrier prevents mutation. Only the supervisor, after child completion
  and verified absence of create-capable descendants, including normal/error
  exits, may seal a terminal outcome. A completed direct child alone is insufficient;
  uncertain descendant quiescence leaves the outcome nonterminal. Process-group
  checks rely on the reviewed trusted non-detaching delegate and host toolchain;
  they are not arbitrary hostile descendant-tree containment. Serialized barriers
  reject late updates after terminal sealing. Teardown for new outcome-bearing
  records requires bound terminal quiescence proof; legacy recovery stays separate. A bound
  terminal failure in the pre-create phase proves no cloud create; missing,
  malformed, nonterminal, mismatched or mutation-entered records stay ambiguous.
  Lost create responses never become no-create proof. Preserve legacy original-ID
  cleanup and all namespace/tag/birth guards. Test rejection, interruption around
  the barrier, lost responses, malformed records and existing-receiver preservation.
  A failed run whose exact source shows the following can support a separate trusted-host
  retrospective reconciliation (an operator-only tool, outside the public tree): its only
  cloud intent is canary creation; every mutation follows durable delegate-state
  initialization; the quiescent original worker's private directory contains
  neither that state nor a teardown archive, with no external removal/rollback.
  Record `reconciled_no_cloud_create`, original failure, source/evidence and the
  trusted-host assumptions. Do not label it deleted or independently inventoried
  cloud absence, and do not generalize absent journals into cleanup passes. The
  existing receiver merely corroborates a guard-refusal hypothesis. No completed
  grade is repeated to improve scores.

- **EVD-1 Portable evidence coverage.** The published scorecard (SCR-1, https://probe.ac0.app/)
  describes six exposure questions: Secrets, Exfiltration, Containment, Privilege,
  Cloud access and Persistence. Keep these categories in the workload evidence view,
  without substituting that view for the SCR score or changing WGR's grade. Export
  a separate versioned evidence-coverage record and opt-in HTML view that distinguishes
  findings, permitted exposures, unknowns and unassessed controls. Context guards stay
  separate from the six categories. Group related unknowns by the actual missing
  measurement: image binding, private-process context and its dependent controls,
  identity/fixture guards, network proof and final receiver collection. Name evidence
  source and next measurement. Missing adapter evidence is not proof the provider
  lacks the feature, and no unavailable/unimplemented check earns a pass. The same
  diagnostic is available to Nitro and Daytona; historical assessments and wire
  contracts are unchanged. The view makes no numeric score or security assurance claim.
- **EVD-2 Preserve exchange diagnostics.** A TCP connection is not successful
  marker delivery. Retain optional, fixed-enum application stage/outcome metadata
  when the canary exchange runs, including TLS handshake, marker send and reply
  receive failures. Never retain response bodies, raw errors or credentials.
  Existing kernel refusal and host receipt requirements remain authoritative:
  completed exchange does not independently prove delivery, and failed exchange
  or silence never proves blocking. Malformed diagnostic fields cannot change a
  verdict or become report-controlled prose. Older records need no new fields.
- **EVD-3 Credential-file portability.** Reuse the independently reviewed
  SEC-3 correction (SBX-2): when an owned regular file's read-only reopen fails
  solely with EPERM while requesting O_NOATIME, retry that same pinned descriptor
  without O_NOATIME. Only the retry's result counts. Open and close unread; do not
  touch original path resolution or weaken real EACCES/EPERM denials. Keep unrelated
  Docker lifecycle changes out of this correction.
- **EVD-4 Bounded validation of the accuracy changes.** One fresh managed Daytona
  workload/configuration validation may follow the reviewed accuracy changes once they
  pass CI and merge. Preserve the same model/prompt/nine cases,
  principal, endpoint exclusions, fixed account/region and cleanup guards. Retain
  exchange diagnostics, coverage and original observations. This is measurement
  validation, not a retry to improve the letter. Stop after a completed assessment,
  cleanup uncertainty or suspected provider issue. Do not enable metadata/proxy,
  host/other-tenant or newly disallowed checks merely because the public page lists
  their category. Missing evidence stays unknown; provider documentation is not a
  substitute for measured isolation or authorization.

- **EVD-5 Configuration evidence parity.** Retain a provider-independent, versioned
  configuration evidence artifact before model execution, bound to managed run,
  original box and frozen configuration hash. Distinguish image runtime-status
  readback from snapshot metadata and private-container configuration readback from
  API visibility. Nitro may record its existing control-plane guards; Daytona must
  record runtime image/private-process evidence as unavailable with fixed reasons.
  A tagged or digest-shaped snapshot reference is not runtime-image verification.
  Runtime image identity must parse as an exact supported OCI digest identity;
  substring matches, suffixes, malformed or unrelated identities fail the Nitro
  execution guard. Shared cross-language fixtures cover canonical and deceptive
  identities. Keep historical grades, grading thresholds and existing scope
  unchanged. The artifact is host configuration evidence, not attestation; missing
  provider support stays unknown. No cloud run is needed for this offline change.

- **EVD-6 Bounded network failure classification.** Shared marker clients may retain
  fixed labels for exact HTTP403/407 status lines, other HTTP status replies,
  connection reset, broken pipe and non-TLS record failures. Read at most256bytes;
  do not retain response text, headers, bodies, certificates or raw error strings.
  The labels identify observed protocol behavior, never provider attribution or an
  authenticated policy denial. Preserve pinned TLS, nonce acknowledgement, kernel
  refusal and host receipt rules. These diagnostics cannot alter any verdict,
  complete an unknown, or create an additional request/target. Historical records
  remain unchanged. Verify real probe paths against owned local fixtures and run
  a grading-invariance regression over all accepted labels. No live run is needed.

- **MEAS-1 Shared receiver measurement.** Measurement definitions, nonce protocol,
  calibration ordering, evidence validation and grading are provider-independent.
  Provider adapters supply original resource identity, the existing agent execution
  path, receiver transport/control access and confirmed shutdown. The core contains
  no provider-name grading branches. A host-only receiver binding (managed run,
  original box, receiver identity/key pin, owned endpoint, scope and three unique
  nonces) is hashed into the workload declaration before the first model request.
  Only the middle nonce and the owned endpoint/pin enter the guest; positive-control
  nonces remain host-only until evidence is published. Missing adapter support is
  explicit unknown evidence, never a pass or a claim that the provider lacks it.
- **MEAS-2 Calibrated final collection.** Arm a separate run-owned receiver session,
  send and verify a host-side positive control, invoke the shipped receiver attempt
  through the same agent path without changing workload/network configuration, and
  collect a second host control and final receipts only after original-ID guest
  shutdown is confirmed. Bind all control answers to receiver identity, pin, run and
  nonce/protocol/port; overload, failed collection or missing controls remain unknown.
  Grade a versioned `receiver-calibration` record against the pre-workload hash and
  original box. A bound middle-nonce receipt remains positive evidence even if guest
  output is invalid; stop and preserve restricted evidence on unexpected delivery.
  No middle delivery observed is not_found, never a refusal/pass. Public and private
  endpoint scope remain explicit; no public target is called a private-cluster test.
  Legacy `private-receiver` records and historical grades remain unchanged.
- **MEAS-3 Shared exchange validation.** Bound canary reply reads to256bytes and
  require the expected nonce acknowledgement before describing a completed exchange.
  Retain fixed `unexpected_reply` diagnostics without response text. TLS key pinning
  and host receipt/kernel refusal requirements remain. Wrong replies and silence do
  not prove denial, and guest acknowledgement does not replace host delivery evidence.
- **MEAS-4 Adapter integration and validation.** Integrate the shared engine first
  with the existing Daytona owned sandbox and managed canary. SSM and Docker receiver
  transports implement the same interface; generic fixtures exercise replay, changed
  receiver/box, failed controls, missing shutdown, invalid guest output and positive
  delivery. Stop/delete the original Daytona guest before final receiver collection,
  retain the cleanup proof and let recovery reuse recorded IDs. Do not change allow
  lists, agent privilege, image/process verification flags, model or nine-case task.
  After reviewed changes pass CI and merge, one fresh managed Daytona
  workload/assessment may run; retain
  every result and verify sandbox/receiver cleanup. Do not retry a completed grade.
  Unavailable image-content/private-process evidence and inconclusive network checks
  stay unknown; documentation or a tag is not runtime verification. No new metadata,
  provider-control, host/other-tenant or reset probes are authorized by this change.

## Pre-run boundary context, 19 November 2026

This is the first prerequisite for a future versioned boundary assessment. It does not replace legacy grades.

- **BND-1 Host declaration.** Before the full probe runs, opt-in AWS reference variants record a structured
  `sandprobe.boundary-contract/1` object in the host manifest, not probe stdin. Record the fixed file-workload
  profile `aws-reference-file-v1`, requested pinned image, Kubernetes-reported imageID (at most256bytes),
  requested UID/GID10001, network expectation
  (`unrestricted` or `deny-canary-six-routes`), reset model `none`, and protected-resource attribution
  `unestablished`. Derive the network expectation from the selected reference variant and imageID from the
  same REF-3-verified pod. The network field is the operator's reference-test requirement, not a provider promise or
  evidence that it is enforced. Configuration and imageID are API-reported, not attested. Do not infer protected
  principals from a UID, PID, path, or legacy finding; the current reference workload has no protected fixture.
- **BND-2 Validation and scope.** Accept only this initial fixed workload, supported version, pinned reference
  image, bounded digest-bearing imageID and exact identity/reset/attribution/enumeration values. Reject malformed
  declarations before executing the probe, without echoing their contents. Parsing inherits JON-1 strict
  framing and unknown-field rejection. Copy declarations into the manifest
  by value. The declaration neither changes probe selection nor suppresses findings, validates observations,
  establishes negative proof, or affects legacy letters and gates. Old/default runs carry no declaration and
  none is reconstructed for saved runs. Absence is missing context, never proof of containment.
- **BND-3 Offline use.** ANL-1 validates any recorded declaration and rejects unsupported/malformed versions.
  Offline assessment exports it as declared context only, with an explicit unauthenticated/non-attribution limit.
  Comparison reports any declaration change, including addition/removal, as a context change. Matching declared
  context alone does not establish matching enforcement, protected-role attribution, or equivalent security.
- **BND-4 Remaining calibration.** Before a new overall grade, add independently executed synthetic resources
  with known agent-owned/protected roles and allowed/refused counterparts, bind observations to those exact
  resources, and calibrate false-negative and false-positive cases. Ordinary same-user process access must not
  be relabeled protected-secret theft; unrelated harmless-marker delivery must not be relabeled secret theft.
  Missing protected-role or reset evidence stays inconclusive. BND-1 does not satisfy these measurements.
- **BND-5 Tests.** Validate malformed/version/image/identity/policy declarations, old-report compatibility,
  pre-execution rejection, immutable plan copy, pair differences and changed/missing offline context. Map to
  `internal/obs/boundary_test.go`, `internal/host/boundary_test.go`,
  `internal/analysis/boundary_test.go` and `cmd/sandprobe/nitro_reference_test.go`.

## Single-provider grading calibration, 18 November 2026

One-provider investigation and calibration come before more provider runs. AWS's saved open-network
and network-isolated runs are the first case study. This extension adds a narrow
retrospective assessment, not an alternative overall sandbox letter or a declaration of provider-policy compliance.

- **CAL-1 Fixed question.** `sandprobe assess <report.json> canary-egress-deny-v1 [-o json]` asks whether the saved
  results satisfy a hypothetical requirement to deny six specific agent-to-canary routes: EGR-1 (resolver DNS),
  EGR-2 (direct HTTPS), EGR-5.22, EGR-5.80, EGR-5.8080 (direct TCP), EGR-5.53u (direct UDP). All six are mandatory;
  the caller cannot drop an inconvenient route. This is not a claim that a provider promised this policy, nor a test
  of arbitrary destinations, proxies, host isolation, actual secret exfiltration or all egress.
- **CAL-2 Evidence and uncertainty.** Use ANL-1 loading/validation, then check each required route's catalog kind,
  selection, exported proof/result consistency and expected scope port/route. Require a nonempty valid destination
  IP matching the manifest endpoint and a recorded per-check nonce. A saved two-sided `pass` with
  canary proof is `reported_refusal`; a saved proof-class `finding` with canary proof is `reported_delivery`.
  Inputs rejected by ANL-1 remain input errors. Otherwise missing, unknown, skipped, absent, scoped-out, find-only
  not_found, wrong scope or missing proof is `inconclusive`,
  never a refusal. Invalid runs assess no route. No new security pass is established: raw observations, canary
  receipts, health controls and operator configuration cannot be reverified from this offline result.
- **CAL-3 Bounded outcome.** Output version `sandprobe.assessment/1`, fixed profile ID, source provider/run ID,
  unauthenticated/retrospective verification label, six route rows, counts, five-area ANL-2 coverage, saved grade
  (unverified), and its highest-severity finding IDs. Outcome is `reported_violation` if any delivery is reported,
  otherwise `inconclusive`. Current DNS and UDP checks are find-only, so this profile cannot establish all six
  refusals from any currently legal report. The four direct TCP routes also have a separate fixed summary; it
  does not remove the DNS/UDP requirements or change the overall outcome. Uncertainty remains
  visible even alongside a violation. No A–F grade, certification, provider ranking or CI security gate is produced.
  The command exits 2 on input/usage error, 5 for invalid/incomplete source or any inconclusive required route,
  6 for reported delivery with otherwise complete source/route coverage. Exit 0 is deliberately unreachable under
  the current catalog; there is no fabricated successful fixture or silent exclusion of DNS/UDP. Every nonzero
  exit must be treated as not meeting the complete assessment requirements.
- **CAL-4 Interpretation.** Keep image/guest capability observations separate from proven boundary crossings.
  Report UID when recorded, without treating guest root alone as host escape. State that process/file openability
  plus independent marker delivery does not prove secret contents were exfiltrated. Writable startup files alone
  do not prove reset survival. Preserve all findings and unknowns, do not infer process ownership/trust roles from
  path names, and do not retrospectively invent image, namespace or policy context. Old grades, `run -min`, existing
  report formats and gate semantics remain unchanged.
- **CAL-5 Calibration.** Add deterministic replay tests on saved open-versus-refused reports (`test/reports`: the same
  local Docker box with every route out, and with every route refused by its own firewall), synthetic four-TCP-refused,
  delivery, unknown, invalid, omitted route, absent, wrong proof/scope, missing identity and unrelated incompleteness
  cases. Forged six-pass reports are rejected. DNS/UDP silence stays inconclusive, guest root never overrides a route refusal, and a delivery never gets
  hidden by other unknowns. Test CLI output/exit behavior and safe escaping. These are offline interpretation tests,
  not new live runs or proof that the probe's underlying controls work on an untested provider. Any later live
  calibration must still obey the provider's terms, bounded spend, owned disposable resources and verified cleanup.
  Replays of a real provider's saved reports, which check that this interpretation still reads a recorded provider
  report the same way, run where the operators keep those records, not in this repository.

Tests: CAL-1–5 map to `internal/analysis/assessment_test.go` and `cmd/sandprobe/assessment_test.go`.

- **CAL-6 Executed controls.** A separate, bounded Linux CI calibration job runs the actual Linux probe, host
  grader and run-owned local Docker canary against four existing synthetic fixtures: clean, holes,
  net-canary-down and broken-arch. Assert all four subtests actually execute and pass; missing/skipped controls
  fail the job. Expected legacy outcomes are clean A (with find-only/no-finding coverage distinct from refusals),
  holes F, unavailable canary incomplete with no egress refusal, and unexecutable probe no grade. This does not
  change grade rules or demonstrate a live provider result. Run no cloud/provider APIs or production resources.
  Bound the job and Go test deadlines; retain the test harness's exact-container-ID cleanup. Publish only a fixed
  synthetic-control summary with grades/coverage, not probe documents, secret values or provider evidence.
  Keep Go stderr separate from the JSON event stream. Failed controls may publish fixed reason codes,
  allowlisted control names and known check-ID hints; never raw output/error text. A nonzero Go command must
  not publish a successful summary even if its event stream appears complete. `TestFixtures/clean`'s
  `expectClean` and `TestFixtures/net-canary-down`'s `expectCanaryUnknown` own the finer coverage/no-refusal
  assertions; the summary parser verifies execution, grade and completeness.

Tests: CAL-6 maps to `test/calibration.sh`, `test/calibration_summary.py` and `test/calibration_summary_test.py`.

- **REF-1 Paired reference configuration.** Add opt-in AWS Nitro variants `reference-open` and
  `reference-network-isolated`. Use the same fixed public Amazon Linux multi-architecture image digest, command,
  UID/GID10001, fsGroup10001, capabilities drop ALL, no privilege escalation, RuntimeDefault seccomp, read-only
  root, no service-account-token automount and no service links. Only the existing network-isolated annotation
  differs between the pair. Keep both old variants unchanged. These are operator-hardened reference setups,
  never relabeled provider defaults or evidence that an existing provider grade improved.
- **REF-2 Scripted workload.** A fixed shell task writes/transforms/checksums nonsecret text in a run-owned
  ephemeral `/workspace`, then creates a completion marker and sleeps. This is a deterministic file-work task,
  not an LLM/coding-agent evaluation. Writable `/tmp` and `/workspace` emptyDir volumes are each capped64Mi;
  CPU1/memory1Gi limits remain. No external service, credential, persistent volume, host mount, privileged helper
  or additional Kubernetes resource. Readiness requires task completion; allow at most15minutes for scheduling,
  then bound reference readiness to two minutes, within the existing30minute run deadline.
- **REF-3 Check and record configuration.** Before upload/probing, verify the ready pod's API-reported UID and
  fixed security/runtime/image/workspace fields against the requested profile. Explicitly verify hostNetwork,
  hostPID, hostIPC and container privileged are false. Reject API-injected env/envFrom using presence only,
  without retrieving their values. Query only fixed nonsecret fields,
  never the whole Pod JSON, env values or credential objects. Reject a missing/mismatching field, extra container,
  init/ephemeral container, mount option, emptyDir medium, lifecycle hook, startup/liveness probe, volume device,
  capability or volume. Record the API-reported immutable imageID, fixed profile
  and requested security settings in existing escaped report notes. API-reported configuration is not kernel
  enforcement attestation; the probe's actual identity/capability results and all findings remain authoritative
  within SBX-10's limits. No skip, severity change, identity override or promised passing grade is introduced.
  Offline comparison compares only CLI-written reference context notes with the exact `REF-2: ` or `REF-3: `
  prefix, treating their contents as opaque data. Changed reference image/profile metadata remains a context
  change. Grader/lifecycle notes (including CHN-2) must not become configuration changes or mask regression exit6.
  Unrelated Pod annotations must not cause a missing network-isolated annotation to print a mismatching placeholder.
- **REF-4 Lifecycle and scope.** Preserve existing create/UID-check/upload/probe/delete and bounded cleanup.
  Reference verification errors take the same cleanup path. Plans disclose the reference setup and file task
  before approval. Preparing variants or CI checks authorizes no live EKS run.
- **REF-5 Tests.** Assert fixed manifests and pair equivalence except network annotation, old-variant behavior,
  command safety/readiness/resources, accepted API snapshot, missing/mutated fields and wrong UID rejection,
  safe notes and cleanup on verification errors. Unit tests use a fake kubectl only; unsupported runtime behavior
  remains unvalidated until an authorized live run. Map to `internal/host/nitro_reference_test.go` and
  `cmd/sandprobe/nitro_reference_test.go`. A gated CI check executes the exact task in the pinned public image
  as non-root with local Docker, no network and ephemeral scratch. It verifies completion, checksum and exact-ID
  cleanup; it validates task/tool availability, not Nitro enforcement. Map to `internal/host/nitro_reference_docker_test.go`.

## Any sandbox, 20 November 2026

Sandprobe works with any sandbox, starting with the top 20, without the canary becoming a hurdle: a hosted, anonymous
canary is the default. The canary's side of
HCN-1 to HCN-4 is built (`internal/canary`, `internal/canarycontrol`), and so are the host's client
(`host.HTTPSCanary`), PRV-15's `run exec`, and the hosted canary itself (HCN-7: deployed 21 Nov 2026 at
`pub.probe.ac0.dev`, verified end to end with `run exec` through `docker exec`), HCN-5's choice of canary for every run, including native adapters (22 Nov 2026), and `-no-canary`, and RCP's
runner with its first shipped recipe, Kubernetes (PRV-16), and PRV-15's `-provider-endpoints` for `run exec` and
shipped recipes. `-recipe <file>` and recipe resets aren't built yet.
Each piece needs AGENTS rule 2's two reviews before it lands. Where a rule below amends an existing
one, the amended text lands in place only after review.

- **HCN-1 Public control.** The canary may serve SBX-11's control operations (status, arm, query, disarm, and
  HCN-3's reserve) over HTTPS as well as through SSM and `docker exec`. The control listener shares port 443 and is
  chosen by SNI: the control name (`control.<our domain>` for the hosted canary) gets a WebPKI certificate and the
  JSON API under `/v1`; every other name gets today's pinned-key echo, unchanged. WebPKI only protects the run secret
  in transit; it doesn't prove the canary answered, since a CA-authorized proxy, an enterprise interception root or a
  redirected name can terminate TLS. Trust rests on a control key instead: an ECDSA key the canary's deployment makes
  on its own instance and never exports, kept across restarts. Its pin (SHA-256 of the public key) ships in each
  sandprobe release for the hosted canary, at most two at once for a rotation; a self-hosted canary's pin is given
  with `-canary-url`. Every request carries a fresh 32-byte host challenge. The control key signs one transcript: the
  label `sandprobe-control-v1`, the request's method and path, the request body's length and its exact bytes, then
  the answer body's exact bytes. The signature and the key travel in response headers, outside the signed answer, so
  nothing signed contains its own signature. Both sides parse JSON under JON-1 (strictjson: duplicate or
  case-ambiguous keys and unknown fields refused), and the host parses only answer bytes that verified. The host
  accepts an answer only when that signature verifies under a pinned key, so anything on the path can relay or drop an answer but never forge or replay one;
  a dropped or altered answer fails the request, which leaves the run unknown. The receipt key's pin is trusted only
  as a verified status answer carries it; health and EGR-2 keep checking it. The status answer also names the
  canary's receipt address and domain, signed like everything else, and the host sends the box's traffic and its own
  health checks only there, never to what DNS returns for the control name: a redirected name could otherwise put a
  relay in front of the box that forwards genuine control and health but drops the box's attempts, and turn a signed
  zero-receipt answer into a clean negative. A redirect, an unverified answer, or one
  over 16 KB fails the request; every request is bounded to 5 seconds. The control path takes only `application/json`
  and refuses a request a browser marks as cross-origin, so a web page can't spend anonymous slots through its
  visitors.
- **HCN-2 The run secret.** On the public path the host makes 32 random bytes per run, reserves and arms with their
  SHA-256, and presents the secret itself on every query and disarm; the canary compares digests in constant time. The secret
  never enters the box, a report or a log. Arm refuses a run ID or a nonce already armed (as today). Without the
  secret, query and disarm are refused, so a box that knows its run ID and nonces cannot reset or read its run. The
  arm's answer carries a run generation the canary draws at random; every query answer repeats it, and the host
  requires it unchanged, so a run re-armed by anything that learned the secret on the path is never read as clean.
  A failure to draw randomness, on either side, aborts the run.
- **HCN-3 Shared bounds.** On the public path: at most 256 runs armed at once; per control source address at most 4
  runs at once and 30 arms an hour; a lifetime of at most 1,800 s. A source is the caller's connection address (never
  a header), an IPv6 one counted as its /64; at most 50,000 sources are tracked, and a new one past that is told the
  canary is busy. Receipt-port caps rise to fit many boxes behind
  one provider's NAT. Every cap hit and kernel drop still marks the runs armed at the time overloaded, and an
  overloaded run gives no network negative (SBX-11): a shared canary under load makes results unknown, never a pass,
  and the report names the cause. Before creating any box, the host reserves a slot (`reserve`, with the secret's
  SHA-256 and the run's lifetime). A reservation counts against every bound above the moment it's made, so concurrent
  callers can't overbook the canary, and only an arm carrying the same SHA-256, before the reservation's lifetime
  ends, can use it; the per-hour count is of reservations. A refused reservation stops the run before any box is
  created. An arm that still fails (an expired reservation, a malformed run) stops the run before the probe runs: the
  box is deleted as usual, nothing is graded, and the report names the cause.
- **HCN-4 Retention.** The public canary holds receipts (with each box's source address) only for an armed run's
  lifetime, and per-source rate counters for at most an hour, in memory. It writes no access log and stores nothing.
  Reports are never uploaded (OUT-3).
- **HCN-5 Which canary, and consent.** In precedence, for every run but `run docker`: `-canary <state file>` (an
  operator canary from `deploy/canary.sh`, reached over SSM), used only when named: a `canary-*.state` file is never
  picked up on its own, since a forgotten one would send a run to a canary that may be gone; `-canary-url <https URL>`
  with its `-canary-pin` (a self-hosted public canary, `sandprobe canary serve`); otherwise the
  hosted canary at `control.pub.probe.ac0.dev`, under the
  control key each release pins (two during a rotation). A pin given without its URL is refused before any of this, never set aside for
  another canary. The command line always beats the environment: once any of `-canary`, `-canary-url`, `-canary-pin`
  or `-no-canary` is given as a flag, the `SANDPROBE_CANARY`, `SANDPROBE_CANARY_URL` and `SANDPROBE_CANARY_PIN` values
  are all set aside, so the flags name the whole choice and a stale value in the environment can never outrank them;
  with no canary flag, those values stand in for the flags. `run docker` always uses PRV-14's local canary: it refuses
  `-canary`, `-canary-url` and `-canary-pin` given as flags with a usage error before anything runs, and never reads
  their environment values. The native adapters (Sprites, AWS Nitro, Baseten, E2B, Vercel, Cloudflare, Daytona, Boat and
  exe.dev) choose the same way as `run exec` and recipes, under the same guarantees: after approval, and before the
  box is created (for `run exec`, before anything runs in it), a public canary must give its signed status under the
  pin and reserve the run's slot (HCN-1, HCN-3), and an operator canary must answer its status over SSM; either
  failing stops the run with nothing created. A public canary's slots are given back when the run ends, under their
  own budget, even after Ctrl-C or a cleanup that used all of its own. Where a provider's PRV row says "our canary", it means the canary the plan names.
  The plan names
  the canary and who runs it before approval (AGT-3). When the canary is a public one, the hosted canary or one
  `-canary-url` names, the plan also states HCN-4's retention of both addresses it sees, in one sentence shared by
  every plan: the box's public address, with the run's nonces, for the run's lifetime, at most 30 minutes; and the
  public address of the machine running Sandprobe, in a rate counter for at most an hour; both in memory only, with
  no access log and nothing stored. `plan`, `providers` and a run that isn't approved ask no canary anything. With `-no-canary`, EGR-1 to EGR-5 are
  unknown with the reason "run without a canary", never skipped: GRD-3's skips don't make a run incomplete, so
  skipping them could reach an A (KND-2 already lets the find-only ones end unknown). The run is incomplete (GRD-2).
  The probe is never asked for them and gets no canary address, nonce or domain; the host arms nothing and asks no
  canary anything; the grader refuses an outcome the box returns for one (GRD-5), and gives each the host's reason
  whatever the box sent. A check excluded for another reason (PRV-15's provider endpoints) keeps that skip. The plan
  says no test traffic leaves the box before approval. `-no-canary` is for `run exec`, a shipped recipe (`run
  kubernetes`) and their plans only, and is refused with any canary flag.
- **HCN-7 Deploying the hosted canary.** `deploy/canary.sh` with `PUBLIC=1` deploys it beside an operator canary,
  never in its place: its own domain (`pub.probe.ac0.dev` by default; `up` refuses a domain that already has records),
  namespace and state file (not `canary-*.state`, an operator canary's name, which a run uses only when `-canary`
  names it), a t4g.small, and an extra DNS-only `control.<domain>` record that `down` deletes with the
  rest. The non-public deployment is byte for byte unchanged. Its service makes the control key on first start in its
  own state directory and starts only once `canary.sh` has given it, over SSM, the Elastic IP it signs (HCN-1).
  `status` records the control pin on first sight and fails if it ever changes, then asks for the signed status from
  outside, as any host would. `sandprobe canary check` is that question: it asks twice, prints only what the second
  signed answer says after the client confirmed it names the first one's address and domain, reserves nothing, and its
  `-tls-insecure`, for a canary whose certificate comes from Let's Encrypt's staging service (`ACME_STAGING=1`), skips
  WebPKI for that check only, since a status carries no secret and trust rests on the pin.
- **HCN-6 Shared receivers.** A receiver binding (MEAS-1) on a hosted canary has scope `shared_public_endpoint`; its
  `ReceiverID` is its first pinned control key (HCN-1), which names the deployment across restarts (not built yet:
  until receiver sessions reserve their own slot and carry this scope, a public canary isn't a receiver); its cleanup is the disarm only, since the receiver is
  not the run's to delete. Every other MEAS-1 and MEAS-2 requirement is unchanged.
- **PRV-15 Any box by command.** `sandprobe run exec [-as <user>] -y -- <command>` probes an existing box through the
  person's own command, which must start a POSIX `sh` in the box on the agent's path with stdin attached. The host
  runs it without a shell, arguments as given, under the run's deadline. Its checks are non-mutating; its transport
  makes one bounded, transient scratch write (the probe and its input). Each invocation writes one script to stdin:
  a start marker with a fresh random token (output outside the markers is ignored); a scratch directory at an exact
  absolute path the host fixes before the first upload and passes as a literal, never a variable, to every
  invocation, the preflight included (`<dir>/sandprobe-<24 hex>`, where `<dir>` is `/tmp` unless the person names
  another absolute directory with `-scratch`; the preflight reports the box's own temporary directory so a run that
  can't write `/tmp` can say which to name), made with mode 700, and the run stops if it already exists; a random owner token the host made for this box,
  written into it right after that exclusive `mkdir`; an exit and signal trap that removes it only while it carries
  that token; the probe decoded from a base64 heredoc (no
  `base64` in the box stops the run); the probe's run framed between markers. The wrapper uses only `sh`, `mkdir`,
  `base64`, `chmod` and `rm`: upload plumbing run by the host's script, not by the probe, so SBX-5's rule for the
  probe holds. The digest the probe reports for its own executable must equal the shipped one (SBX-5). After each
  invocation, a separate one removes the path only if it carries that owner token, and confirms it gone; a path
  without the token isn't Sandprobe's and is never removed, only reported. If the host can't confirm its own path
  gone, the report names the path and a command that removes it only if it still carries the token (PRV-1).
  - **The user is bound before any check.** One invocation first asks only the box's machine type (`uname -m`, run
    by the wrapper through a command that must exit 0) to choose which shipped probe to upload: no probe runs, no
    check, no file is written. The next is identity only: the probe runs with `-whoami
    [<name>]`, resolves the requested name to a numeric uid inside the box, reports its own real, effective,
    saved-set and filesystem uids (the kernel's `Uid:` line) and its temporary directory, and runs no check. If
    `-as` was given and any of the four differs, nothing else runs. Every later invocation passes that uid
    (`-expect-uid`), and the probe refuses at startup, before the survey or any check, unless all four of its uids
    equal it. Without `-as` the preflight's uid is bound the same way, and the report says
    the user is unconfirmed as the agent's.
  - The box is an existing box (PRV-1): non-mutating checks only, GRD-3's existing-box skips, no reset, and the
    boundary is the person's attestation (PRV-2, UX-4). The launch mode is `exec` (SBX-4).
  - The provider isn't identified, so SEC-4, EGR-3, AMP-6 and AMP-7, the checks that contact a provider-owned
    endpoint, are excluded by default, as kind `opt_in` (SCR-2) (Sandprobe checks the person's own box and sends only to the
    canary). `-provider-endpoints <IDs>` selects named ones only (for example `SEC-4,AMP-7`), each one the person
    attests their provider's terms allow on their own account; the plan lists each with that attestation before
    approval (AGT-3), and the report records it beside the check. Nothing selects them all at once.
    - The value is a comma-separated list of those four IDs, each named once, exactly as the catalog spells it. An
      empty value, an empty item, `all`, `*`, a duplicate or any other ID is refused before the plan exists, and so is
      the flag anywhere but `run exec`, a shipped recipe (RCP-4) and their plans: `run docker` already runs these
      checks, and a native adapter's PRV row decides them (PRV-5). It has no environment default, so an attestation is
      typed for each run.
    - A selected check leaves the exclusions and runs as it does for a provider whose rules allow it, under every
      other gate: nothing is contacted before approval; SEC-4 asks for role listings only, never a credential document;
      AMP-7 is a TCP and TLS handshake to the API the agent's environment names, no request; EGR-3 goes only through
      the proxy the agent's environment names, a local one only with `-allow-local-proxy`; AMP-6 stays skipped on
      `run exec`, since an existing box gets no vsock connects (PRV-1), and on a recipe's throwaway box follows its own
      gate. The checks left out keep their `opt_in` skip (SCR-2).
    - The host records the attested IDs in the manifest (`Attested`, never in the probe's input), and each one's report
      row carries a fixed `attestation` sentence, never text from the command line; such a report declares
      `sandprobe/2` (AGT-6), and the reader accepts attestations under it only where this policy allows them. The grader (GRD-5) and ANL-1 refuse an attestation on a check that isn't a provider
      endpoint, is named twice, or still carries a skip kind, and ANL-1 also refuses one where this binary's own policy
      for the run's provider isn't `opt_in` (SCR-2): only `run exec` and shipped recipes take an attestation.
    - Every attested check keeps its report row, with its attestation, whether or not the run is valid, since the
      check may already have contacted its endpoint: an invalid run (GRD-5) grades nothing, so its row reads unknown,
      "not graded: the run is invalid", while the grade lists no unknowns. ANL-1 requires a row for every attested check
      in valid and invalid reports alike, and every row of an invalid report is a skip or an attested check exactly
      not graded: unknown, with that reason, and no evidence, severity, proof or scope. The
      page lists each attestation and its result in its appendix for every run.
- **RCP-1 Recipes.** A recipe is a POSIX shell file with a `# sandprobe-recipe: v1` header (provider, docs, terms with
  the quoted clause, exclusions, `addressed-by: id` or `name`) and the functions `sp_ready`, `sp_create`, `sp_shell`,
  `sp_delete` and `sp_gone`, and optionally `sp_checkpoint` and `sp_restore`, or `sp_recreate`, and `sp_whois` for a
  name-addressed provider. The host calls one function per `sh` invocation, under the run's deadline. `sp_shell`
  keeps PRV-15's contract. Each call is `sh -c` over the recipe's bytes as read once (at most 64 KiB, never read
  again from disk) followed by the function's name, with stdin from `/dev/null` except `sp_shell`'s, which carries
  PRV-15's script; its output is bounded. Its stderr goes to `/dev/null`, since kubectl and an exec plugin write
  there and it can carry a credential (AGENTS rule 3); the person sees only what the recipe writes to fd 3, a file
  the host opens and unlinks before the recipe starts, so only that descriptor reaches it, printable and bounded. A recipe runs every child command with fd 3 closed, so no tool can
  write a message as the recipe. A recipe
  takes its settings from the person's environment, under `SANDPROBE_` names its header lists (`env:`), never from
  flags. `sp_ready` checks them, which may mean read-only calls to the provider before approval (so `plan` and
  `providers` make them too), and prints one line naming where boxes will be made; the plan shows it before
  approval, and the host passes it back as `SANDPROBE_TARGET` to every later call, so a recipe refuses a call whose
  target no longer matches. The host sets `SANDPROBE_BOX`, `SANDPROBE_NAME` and `SANDPROBE_TARGET` itself, and the
  person's own values for them never reach a recipe.
- **RCP-2 Identity and deletion.** The box ID is `sp_create`'s whole stdout: exactly one line matching
  `^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`, or the run stops with the create's outcome reported. The host passes the ID
  and a fresh `sandprobe-<12 hex>` name in the environment (`SANDPROBE_BOX`, `SANDPROBE_NAME`), never in command
  text. Delete and gone use only that ID (PRV-1). `sp_gone` exits 0 only on the provider's positive "not found" or
  terminal deleted state, 1 while the box exists, 2 when it can't tell; anything but 0 is not gone (KND) and the run
  exits 7 naming the ID (OUT-4). A
  name-addressed recipe runs `sp_whois` before each call and the call is made only if it answers the recorded ID; the
  remaining race is reported (PRV-1). A create that returns no ID leaves its name recorded, reported, never deleted.
  Recorded means on disk (AGENTS rule 8): before `sp_create`, the host writes the recipe, its SHA-256, the target and
  the name to `~/.config/sandprobe/recipe-<recipe>-<name>.state` (mode 600), and nothing is created if it can't; the
  ID is added once returned, and if it can't be, nothing runs in the box and it's deleted by that ID; the file is
  removed only when `sp_gone` says 0, and is named in the error otherwise.
  The name and that path go to stderr before the create, even with `-o json`. The cleanup's budgets start when it
  does (the scratch removal, then five minutes for the delete), so a run that used all of its own still asks for the
  delete.
  Every shipped recipe must address an immutable ID, or a reviewed name exception, and its review checks it.
- **RCP-3 Reset.** PER-5 runs only through a recipe's TWN-3 reset: `sp_checkpoint` and `sp_restore` (restore in
  place) or `sp_recreate` (recreate). A recipe with neither skips PER-5 under its GRD-3 gate; PER-1 to PER-4 run
  either way.
- **RCP-4 Shipped and own recipes.** A recipe in `recipes/` is a provider adapter: it has a PRV row citing the
  provider's terms (PRV-5) and its exclusions, and gets the two reviews. Its exclusions default to PRV-15's four;
  its reviewed PRV row may select any of them, citing what allows it. A provider whose terms require written consent
  for testing gets no shipped recipe until that consent is recorded; `sandprobe providers` lists it with the reason.
  A shipped recipe's exclusions are lifted the same way: `-provider-endpoints` may name only checks its header
  excludes, each under the person's PRV-15 attestation.
  `sandprobe run -recipe <file>` runs a person's own recipe with the default exclusions, which only PRV-15's per-check
  `-provider-endpoints` attestation lifts; its plan shows the file's SHA-256 and says Sandprobe hasn't reviewed that
  provider's terms. A person's own recipe is trusted host code: it runs with the person's own credentials and
  permissions, and the plan says so. Built: the shipped recipes (`run kubernetes`); `-recipe <file>` isn't yet.
- **PRV-16 Kubernetes, by recipe.** `sandprobe run kubernetes [-as <user>] -y` makes one throwaway pod in the
  person's own cluster through `recipes/kubernetes.sh` and `kubectl`. Settings: `SANDPROBE_KUBE_CONTEXT` (required:
  the kubeconfig's current context is never used, since a kubeconfig often also holds production clusters),
  `SANDPROBE_KUBE_NAMESPACE` (default `default`, checked as a lowercase DNS label with its characters spelled out,
  since a range like `a-z` follows the locale), `SANDPROBE_KUBE_IMAGE` (default the debian image pinned by digest in
  test/probe.sh) and `SANDPROBE_KUBE_OVERRIDES` (a JSON merge patch over the generated pod, read by kubectl through
  `--patch-file` so its contents, an env value say, never sit on a command line: the agent's securityContext,
  service account, runtime class and so on). Every kubectl call names the context, and every call to the cluster the
  namespace. `sp_ready` checks that `create pods`, `get pods`, `delete pods` and `create pods/exec` are allowed there
  (`kubectl auth can-i`) and names the context, its API server, the namespace, and a SHA-256 of the context's cluster
  and context entries (CA, proxy, TLS server name, skip-verify, cluster and user names), shown as 12 hex digits and
  never the entries themselves; every later call refuses if any of that has changed, so a kubeconfig edit can't
  redirect it mid-run. An API server URL with a user, query or fragment part could carry a credential, so it is
  refused and never printed; of any other only the origin (scheme, host, port) is shown, since a proxy's path can
  carry one too, while the hash covers the whole URL. The create sets the fresh name, the namespace, an
  `app.kubernetes.io/managed-by=sandprobe` label and `activeDeadlineSeconds: 3600` over the overrides (so a pod whose
  cleanup never came stops on its own), dry-runs the result and creates nothing unless it is exactly
  `v1/Pod/<namespace>/<name>`, and is a create, never an apply, so it can't adopt a pod that exists; the ID is the
  UID it returned. The pod is name-addressed: `sp_whois` prints the UID now holding the name; `sp_delete` is the
  API's DELETE with that UID as its precondition and a one-second grace period, so it can delete no other pod and
  doesn't wait on the overrides' grace; `sp_gone` is 0 when the name is absent or held by another UID, 1 while
  ours holds it, 2 when kubectl fails or the target changed. `kubectl exec -i` reaches the box, and the report states
  the race left between `sp_whois` and each call (RCP-2). There is no reset, so PER-5 is skipped (RCP-3). Terms:
  Kubernetes is Apache-2.0 software and the cluster is the person's (no provider terms beyond the licence and the
  infrastructure's owner); whoever hosts it (EKS, GKE, AKS) has terms the recipe
  can't know, so PRV-15's four provider-endpoint checks stay excluded (RCP-4) unless the person attests one with
  `-provider-endpoints`: on EKS, say, `SEC-4,AMP-7` then lists the node's or pod's role and reaches the cluster's API. The maintainers' own live runs of it use a
  local kind cluster with its own kubeconfig file only.

Amendments these need, after review:

- "Not in v1": applied in place with the canary's side of HCN.
- OUT-3: "our canary" becomes "the canary the plan names (HCN-5)".
- PRV-5 and AGENTS rule 5: Summation's own runs keep the full rule (terms read and quoted in a PRV row before any
  probe). A person running Sandprobe on their own account reads their own provider's terms: the defaults keep every
  check off provider-owned endpoints, and only the person's per-check attestation (PRV-15) turns one on.
- GRD-3: applied in place with PRV-15's `run exec`.
- SCR-2: applied in place with HCN-5's `-no-canary`.
- PRV-2: for Summation's own runs, "the org or account the operator names" is one the project owner designates;
  anyone else's run creates boxes only in the account the person is logged into, under the person's attestation.
- SBX-11: applied in place with the canary's side of HCN.
- AGENTS rule 9: the maintainers' live-test holds govern Summation's own live runs, not people running Sandprobe on
  their own accounts.
- Tests: a row for each rule above, including the false-pass cases (re-arm, disarm or query without the secret, a
  duplicate nonce, a flood, a canary restart, an `-as` mismatch, a malformed or multi-line create ID, a gone check
  that fails), and these: redirected DNS plus an installed interception root never yields a clean network negative
  (HCN-1); a replayed or re-signed answer, or a changed generation, is refused (HCN-1, HCN-2); the effective user
  changed between the preflight, the survey and the full run means no network or provider-bound check runs
  (PRV-15); a killed invocation leaves no scratch path unreported (PRV-15).

## Not in v1

Sandprobe v1 is a one-shot check, run on demand: one run, one box, one JSON report and one HTML report, and the CLI
exits. A user who wants a re-check runs it again. Out of scope for v1, and nothing built leans toward it:

- No watch mode, no scheduled or periodic re-checks, and nothing left running after a run but the canary below: no
  daemon or agent in the box (the probe and its scratch directory are removed, SBX-1) and none on the host.
- No history service across runs: no run database or trends. The local robustness extension above explicitly permits
  user-invoked offline comparison of saved reports; it does not add scheduled collection. The TUI keeps its palette choice (UX-8).
- No paging, alerts or notifications.
- No hosted service or dashboard: reports are written locally and uploaded nowhere (OUT-3). The one hosted piece is
  the canary (HCN), which holds receipts, never reports.
- No OpenTelemetry exporter or metrics stream: OUT-1's mapping onto OpenTelemetry names is documentation for later.
- No paid-tier features.
- The Modal proof of concept (its own section) compares setups and runs a sidecar beside the box. It is built only
  with `-tags poc` and never ships.

The canary is the one thing that keeps running between runs, because a way out can't be proven without an endpoint
outside the box (SBX-11). It keeps receipts in memory only for runs the host has armed, bounded, and gone within an hour
at most, and drops everything else. Nothing is stored durably, nothing is kept per user beyond HCN-4's in-memory rate
counters, and no history across runs is shown anywhere.

## Rules

### SBX: how the probe behaves

- **SBX-1 What the probe may change.** Only these. (a) The probe binary the host copies in, and its private scratch
  directory (`mkdtemp`, 0700), both removed at the end, on every box, existing ones included. (b) On a throwaway box,
  PER-5's markers in storage roots. (c) Running `sudo -n -l` for AMP-1, which lists policy and runs no command, and
  which sudo may log to the system's auth log. (d) A listener the probe binds on loopback, on an ephemeral port, for
  TWN-1's client check, closed at the end. (e) One `CONNECT` to the canary through the box's own proxy for EGR-3,
  when that proxy is local (loopback or the box's own address) and the person approved it in the plan (SBX-3). A marker is a regular file named
  `.sandprobe-<run id>` holding only the run id. It is created with `openat(O_CREAT|O_EXCL|O_NOFOLLOW|O_WRONLY)` on a
  directory opened `O_DIRECTORY|O_NOFOLLOW`, and the probe records its device, inode and length. A marker is never
  removed by name: no check before an unlink can stop a same-user process swapping the name in between, and deleting
  someone else's file is no allowed effect. Markers are placed only on throwaway boxes and on volumes Sandprobe created
  for the run, and go when that box, and each such volume, is deleted by its immutable ID with the provider reporting
  the deletion done (PRV-1). Nothing else is ever marked. Never: a shell redirection or append as a write test; a marker in a directory something consumes
  (cron, systemd, profile.d, PATH, package or git config); opening a FIFO, socket or device; connecting to any local
  listener or unix socket the probe didn't create itself in this run, except an approved local proxy under (e); running any command through sudo; signals;
  ptrace. A run whose box or volume isn't confirmed deleted, or that crashes or loses its box mid-reset, lists every
  marker it may have
  left as an unresolved cleanup item: its path, and its device and inode when the probe confirmed them, else marked
  unconfirmed (the host plans each marker path before placing it). It never prints an unconditional removal command.
- **SBX-2 Never a secret's value.** Readability is proven on a pinned inode, so a path swapped mid-check can't make
  the probe open a FIFO or device: `openat(O_PATH|O_NOFOLLOW)`, which opens nothing for I/O; `fstat` on that
  descriptor must show a regular file; only then is that same inode reopened read-only through
  `/proc/self/fd/<n>` (`O_RDONLY|O_NONBLOCK|O_NOCTTY`, with `O_NOATIME` where the probe owns the file) and closed,
  reading nothing. An `EPERM` to an open carrying `O_NOATIME` can be the filesystem refusing the flag, as Docker
  Desktop's file sharing does, not the file refusing the agent: the open is asked once more without the flag, and only
  that answer counts, so a readable file is never recorded as refused (found 19 November 2026). Without `/proc`, the check is unknown. No byte, no hash, no length: the only thing
  derived from `fstat`'s size is, in memory, whether the file is empty, and no size is ever emitted. A symlink is resolved hop by hop with `readlink`, at most 8 hops, recording each
  hop; only a final target that `lstat` shows to be a regular file is opened. A chain that can't be resolved, loops, or
  ends anywhere but a regular file is unknown for that path, never absent or a pass. The environment gives names only. Metadata services give role or identity
  names from their listing paths, never a credential document. The probe's own environment holds values because the
  OS put them there; the probe never copies, measures, prints, writes or sends them.
- **SBX-3 Where the network goes.** Only to: the canary (SBX-11); the link-local metadata addresses SEC-4 names; vsock
  CID 2 on AMP-6's ports, on throwaway boxes only; EGR-6's hosts once approved, handshake only; the listener the
  probe itself binds on loopback for TWN-1 (SBX-1 (d)); the proxy the box's proxy variables name, for EGR-3 only,
  with one `CONNECT` to the canary (the plan authorizes it as a class; a local one only if the person opted in up
  front, `-allow-local-proxy` for agents, else EGR-3 is skipped); and `$KUBERNETES_SERVICE_HOST` for AMP-7, handshake
  only, never at a local address. Every fixed destination appears in the plan, every box-named one in the plan as a
  class and in the resolved plan as an exact endpoint before any contact (UX-4), and all of them in `contacted`. Every attempt to
  the canary carries the nonce the host issued for that one check (TLS SNI, DNS name, first payload bytes), so a receipt
  names exactly one check: direct and proxy attempts on 443 never share one. EGR-6 and AMP-6 can't carry one and never
  produce receipts, which is why they are find-only. Once the box exists, the host learns the agent's proxy from a
  survey run of the probe through the agent's path that reports the proxy variables as SBX-5 records them, the
  Kubernetes API the agent's environment names, and whether `/dev/vsock` exists. AMP-7's API, like EGR-3's proxy, is
  named in the manifest, and the probe contacts only that one, never at a local address. With no proxy,
  EGR-3 is skipped (GRD-3). One the agent names but Sandprobe can't parse leaves EGR-3 selected: the manifest says so,
  the probe contacts nothing, and EGR-3 ends unknown. The manifest names the planned proxy and whether a local one is
  approved. The probe
  contacts only that proxy, and one that resolves to a local address (loopback, unspecified, or the box's own) only
  with approval; each EGR-3 attempt names the canary as its destination and the proxy it went through as `via`.
  A provider's rules of engagement can narrow this list for its boxes, and the checks they exclude are skipped (PRV-5).
  No scans, and nothing beyond this list.
- **SBX-4 As the agent, by the agent's path.** The adapter starts the probe the way the platform starts the agent's
  commands (PRV), and records the exact launch command. The probe records who it ran as: uid, gid, groups, `CapEff`,
  `CapPrm`, `CapBnd`, `CapAmb`, `NoNewPrivs`, `Seccomp`, the inode of each `/proc/self/ns/*`, its cgroup, its parent
  chain (process names), the launch mode (`exec`, `workload`, `self`, `other`), and its scan of the system binary
  directories for setuid-root files, with whether the scan completed. `NoNewPrivs` must be reported, as 0 or 1. A probe run on a path the agent
  doesn't use would under-report: a policy layer can score well while the agent's normal path runs unenforced.
- **SBX-5 A host-shipped probe.** The probe is `sandprobe-probe`, a static Go binary built without cgo (no dynamic
  loader, so `LD_PRELOAD` and `/etc/ld.so.preload` can't reach it), for linux/amd64 and linux/arm64. The host copies it
  in through the provider and runs it by absolute path through the agent's path. The probe reports the digest of its
  own `/proc/self/exe`, and a mismatch invalidates the run; that catches an accidental swap, not a lying substitute,
  so reports call the probe host-shipped, never attested (SBX-10). The probe executes no tool from the box except
  `sudo -n -l` for AMP-1. It records the box's `curl` and `sudo` by `lstat` and `readlink` only (path, owner, mode, link target), never
  opening, reading or hashing them, since a PATH entry can point at a secret; it records the
  resolver configuration, `LD_PRELOAD` and `/etc/ld.so.preload`, any agent-writable PATH directory ahead of the
  system's, and the proxy variables sanitised: scheme, host, port, and whether credentials are present, never their
  values.
- **SBX-6 The probe's own client, for every route.** Every network attempt, direct or through the box's proxy, uses the
  probe's own Go client. A proxy URL's credentials are stripped and never used, so a proxy that needs them leaves
  EGR-3 unknown. A positive needs a canary receipt for this run. A negative needs TWN-1's network proof. Comparing the
  agent's own tools (its `curl`, its wrappers) is a separate diagnostic, out of scope for now; if added, it is opt-in,
  named in the plan, and never safety-critical.
- **SBX-7 Time limits.** 3 s per network attempt, 10 s per check, 90 s for the whole probe. A timed-out attempt is
  tried once more. Anything cut off is unknown. Adapters bound their own steps (create 5 min, reset 3 min, delete 3 min).
- **SBX-8 Observed, or unknown.** A two-sided check passes only on its negative proof (TWN); a find-only check never
  passes (KND-2). Any other error, unexpected output or cut-off attempt is unknown. Nothing defaults to pass.
- **SBX-9 One grader.** The probe emits observations, never a grade. The host grades them (GRD), so `run`, `self` and
  `report` grade alike, and the grader is tested apart from any box.
- **SBX-10 What the promise covers.** "No false passes" holds against faults, misconfiguration, wrappers and shims in
  the agent's environment, for the host-shipped probe run as the agent. It does not hold against a box that deceives
  the probe: one that substitutes or tampers with it before or during the run can report the expected digest and
  fabricate every observation, and the host can't tell. The only evidence from outside the box is the canary's
  receipts, which can prove a way out but never a refusal. Also outside the promise: interception in the kernel or
  hypervisor; escapes below the probe; resource exhaustion (AWS documents that one Nitro Sandbox can exhaust the
  parent's conntrack table and DNS resolver budget; we don't test it); and anything a box does only to other
  processes. In `self` and `other` modes the host didn't ship the probe at all. Every report states this boundary
  beside the grade.
- **SBX-11 The canary.** Ours, at `canary.<our domain>`: a TLS echo with a pinned key on 443, plain
  TCP listeners on 22, 80 and 8080, UDP 53, and the authoritative name server for `<nonce>.dns.<our domain>`. It
  records every attempt that carries a nonce: time, port, protocol, source address. It never needs to know the route:
  the nonce says which check sent it. Throughout the probe's network window the host connects to each canary port in
  use once a second, and the canary confirms each of those connects. A confirmation counts only when it proves the
  canary itself answered: on 443 a TLS handshake under the run's pinned key; on a plain port, the canary's signature,
  with that key, over the port and a fresh challenge from the host, checked against the public key the canary's
  status gave over the control channel, whose SHA-256 is the pin. An answer anything else could give, such as a bare
  health line, confirms nothing, so an impostor on the host's path can't stand in for an unreachable canary. The box's wall clock is never compared with the host's:
  the probe reports its run's length and each attempt's destination, start and end as offsets on its own monotonic
  clock, and the host records its own launch and return times, which bracket the probe physically. The health checks
  must cover that whole bracket. An attempt with no negative proof: one whose destination isn't the planned endpoint
  (which invalidates the run), one outside the probe's own run, any attempt in a run longer than the bracket (plus
  250 ms of slack), or any attempt on a port the health checks didn't cover. Before the
  probe runs, the host arms the run with the canary: the run ID, a lifetime, and each check nonce with the protocol
  and port that check uses (the document nonce isn't armed). The canary counts an attempt only when its nonce is armed
  and arrives on that nonce's protocol and port. For each armed nonce it keeps that count, the time and source of the
  first such attempt, and a separate count of the nonce arriving anywhere else. It drops everything else that looks
  like a nonce unrecorded, so nobody on the internet can fill its memory, and no attempt on another port can crowd out
  the one the grader matches. It holds at most 8 armed runs of at most 16 nonces each. It refuses an arm past either
  cap, or with a nonce that is malformed, `health`, or armed by another run, and a refused arm leaves the run not
  live. An armed run ends when the host disarms it after the query, or when its lifetime (at most 1 hour, by the
  canary's own clock) runs out; the canary frees an expired run within 30 s, even when idle. The canary serves at most 512 connections at once, and at most 64 from one source
  address; past either cap it closes the connection unread. It reports a run overloaded when, while the run was armed,
  a connection cap was hit or the kernel's counts of dropped connections (listen overflows and drops) or of dropped
  UDP datagrams rose: a flood can keep the box's attempt from ever reaching the canary while the host's health checks
  still get through. An overloaded run gives no network negative at all: every pass and every `not_found` it would
  have given is unknown, while a receipt is still a finding. After the window the host asks for the run's receipts. A
  network pass, or a find-only `not_found`, needs that query to have completed and to have been sent, by the host's
  clock, at least 2 s after the probe returned. The canary answers with the run's counts as they stand when it
  answers, so the canary's clock is never compared with the host's. With every field at its longest the answer is
  under 8,000 characters, well under the command channel's 24,000 (a test encodes that worst case), and the canary
  refuses to send one over 16,000. A failed or early query makes every such check unknown, while a receipt in hand is
  still a finding. A receipt shows that the check's nonce left the box and reached our canary on that protocol and
  port. It doesn't show that the box's own connection took the check's route: anything that saw the nonce leave (an
  egress proxy, a resolver, a logger) could have carried or replayed it. So a finding says the nonce reached our
  canary, and names the route the probe sent it on, never that the route connected. The report names the source
  address of the first matching attempt: for EGR-1 possibly the resolver that asked our name server, possibly
  whatever replayed the name. The canary answers from memory, over a control
  channel only the host reaches (never one on the box's network: for fixtures, a unix socket inside the canary's
  container; live, a unix socket on the canary's own instance, which the host reaches only through the cloud's command
  channel, never over the network; a reply cut short doesn't parse, and the query didn't complete), with its pin. A
  public canary also answers over HCN-1's path, which the box can reach: there each run is guarded by its secret and
  generation (HCN-2), and each answer counts only under the pinned control key's signature (HCN-1). The
  plan's pin comes from the canary's status answer, and the arm must answer with the same pin. The key is new on every
  start, so a reply under another pin comes from a restarted canary whose armed runs are gone, and the query didn't
  complete; nor did it when the canary no longer holds the run (expired, disarmed, or never armed). Its DNS answers
  are never larger than the query; reflection off spoofed sources stays possible, amplification doesn't. The operator canary is `canary.probe.ac0.dev`, the authoritative server for
  `dns.probe.ac0.dev`, on an EC2 instance that runs nothing else and accepts nothing but the canary's ports
  (`deploy/canary.sh`); fixtures run a local canary (Tests).

### KND: kinds of check and of evidence

- **KND-1 Two-sided checks** end `pass`, `finding`, `absent`, `scoped_out` or `unknown`. A pass needs the check's
  negative proof (TWN-1). `absent` needs a verified absence (TWN-2). `scoped_out` is allowed only where a discovery rule
  can show the check has nothing to apply to: SEC-2 and SEC-5 when no other process is visible (a PID namespace, or
  `hidepid`), and AMP-8's block devices when none is visible. It needs a reason and that rule's discovery count; a
  count above zero makes it unknown. It is listed, never counted as a pass.
- **KND-2 Find-only checks** end `finding`, `not_found` or `unknown` (AMP-1 also `absent`). They exist where no
  trustworthy negative proof does: a proxy's refusal of our canary, DNS and UDP that may leave later or elsewhere, an
  unreachable metadata address, a closed vsock port, a handshake-only host, a sudo policy the agent can't read, a
  marker that something other than the reset may have removed. `not_found` is never a pass, and every report lists
  these checks under "not proven". An indicator finding from a two-sided check (PER-1 to PER-4, AMP-4, AMP-5) still
  counts toward the grade at its severity.
- **KND-3 Evidence is a proof or an indicator.** A proof shows the capability: a file opened, a canary receipt, a
  privileged command run. An indicator shows exposure: a metadata service answering with a role attached, a handshake
  to an upload-capable host, a reachable Kubernetes API. Every finding says which.

### TWN: negative proofs

- **TWN-1 Every two-sided negative has a proof.** It runs through the same mechanism, in the same check, and the
  refusal must be the specific one expected. A sanity check that a client works (loopback) is a precondition, never
  the proof. A failed proof, or any other error, makes the check unknown.
- **TWN-2 Absence is verified.** `lstat` returns `ENOENT` for the exact path, from the probe, and its parent directory
  is searchable by the probe. Otherwise the check is unknown.
- **TWN-3 A reset is proven, not assumed.** It is what makes a surviving marker a PER-5 finding rather than a box that
  was never reset. The run goes: survey, plan and the main probe run on the original box; then the marks; then the
  reset; then a short recheck on the box after it. The survey takes a read-only inventory of the storage roots the
  agent can write (path, device and inode; nothing created), deduplicated by device and inode, and the host resolves
  the plan's marker rule against it (UX-4): a writable mount the adapter doesn't declare part of the box is listed and
  never marked. The main run corroborates
  the inventory. The mark touches only the approved paths, each only if its directory is still the one the survey
  saw; a root that is new or changed since is unknown, never marked.
  Root identity comes from the provider, never the box: mount source, filesystem type, device and mount ID are
  observations only, since another filesystem can share them and mount IDs change on every boot. Two reset models:
  - **Restore in place** (same provider ID, such as Sprites): the host issues the restore of a named checkpoint and the
    provider reports that operation done; the box keeps its provider ID; the boot ID or restore ID changed; and the
    adapter establishes a stable filesystem identity for every root from the provider. A boot ID change alone is a
    reboot, not a restore. A root without a stable provider identity can't show that a marker is gone: its absence
    leaves that root unknown, so PER-5 can't be `not_found`. A marker found after a proven restore is a finding
    whatever its root's identity: the recheck finds the placed marker's state (its inode, at its placed length,
    holding exactly the run id), so run data written after the checkpoint was present at the planned path after the
    restore. That is the claim, and no more: which filesystem held it stays unproven, since an inode number can repeat
    on another filesystem and a clone could have carried the file. A root whose
    provider identity is there and changed contradicts a restore in place, and stays unknown.
    On Sprites (seen 9 Nov): before the probe, the adapter takes a checkpoint, and the provider's checkpoint list must
    gain exactly one new version, which is the checkpoint; none or more than one leaves the reset unproven. The reset
    restores exactly that version through the provider's API. The host gives each restore attempt an ID of its own,
    which is the operation's ID, since Sprites gives none. Done is that call's own response stream ending cleanly on
    the `complete` event for exactly that version, plus the provider's state after it: the same sprite ID, by PRV-1's
    name check, and a changed restore ID, which is the provider's `Current` checkpoint time. The boot ID doesn't
    change, since a restore restarts the sprite's container, not its VM. The declared roots are the sprite's own
    filesystems: `/` (the overlay over the sprite's user data), `/tmp` and `/var/lib/docker` (each its own ext4).
    Anything else the survey finds (tmpfs mounts, `/.sprite/*`) is listed and never marked. Sprites exposes no
    identity per filesystem, so these roots have none: on Sprites, PER-5 finds a surviving marker or stays unknown,
    never `not_found`, until the provider binds an immutable ID to each root.
  - **Recreate** (a new box from the same image, such as AWS, Modal, Baseten and the fixtures): the provider reports
    the new box created, with a new provider ID, which stands in for the boot ID (containers share their host's); only
    persistent volumes Sandprobe created for this run, attached the provider's default way, are roots, each bound to
    its immutable volume ID and its provider-declared mount path and subpath, all three the same before and after. A
    volume can outlive its box, so after the recheck the host deletes each one by ID and records the provider's
    confirmation. A volume Sandprobe didn't create, or can't delete with that confirmation, is never marked; with no
    such volume, PER-5 is skipped.
  The host acts on the mark's report only if it names exactly the planned markers, in order; the recheck's input is
  built from the plan, with only each mark's outcome taken from the report. The recheck pins each marker the way SBX-2 pins a file (`O_PATH|O_NOFOLLOW` under the root opened
  `O_DIRECTORY|O_NOFOLLOW`, a regular file on its descriptor), and reads it only when its inode, and its length, are
  the placed marker's: then exactly the run id and nothing after. Any other file at that name is unknown, unread.
  Absence is `ENOENT` on the name under the opened root. Any gap makes the affected root unknown, and PER-5's
  `not_found` needs every planned root marked, rechecked and definitively without its marker after a proven reset.

| Mechanism | Refusal that counts | Negative proof |
|-|-|-|
| file read (SEC-2, SEC-3, SEC-5) | `EACCES`, `EPERM` on `open` of a resolved regular target (SBX-2) | the probe's own 0600 file opens through the same call; as non-root, its own 0000 file is refused |
| write permission (PER-1 to PER-4, AMP-4, AMP-8 kernel settings) | `faccessat(AT_EACCESS, W_OK)` gives `EACCES` or `EROFS` for the path and every ancestor directory up to `/`, through symlinks; an ancestor counts as safe only if not writable, or sticky with neither it nor the path owned by the agent | the same call allows the probe's scratch directory, and refuses its own 0500 directory as non-root |
| read permission (AMP-8 block devices) | `faccessat(AT_EACCESS, R_OK)` gives `EACCES` or `EPERM` on each block device, never opened | the same call allows the probe's own scratch file, and refuses its own 0000 file as non-root |
| `/proc/<pid>/environ`, `/proc/<pid>/mem` | `EACCES`, `EPERM` | the same file of a child the probe starts opens |
| TCP or TLS out (EGR-2, EGR-5 TCP) | exactly one of `ENETUNREACH`, `EHOSTUNREACH`, `ECONNREFUSED` (each subject to the evidence rule beside it), or `ETIMEDOUT` on both tries; `EACCES`/`EPERM` are always unknown; any other error, or any failure after the TCP handshake, is unknown | all four: kernel evidence the attempt happened. For a non-blocking `connect` that returns `EINPROGRESS`, `TCP_INFO` must show `SYN_SENT`, or count the SYN in `tcpi_segs_out`, before the final error arrives through `SO_ERROR` (and SYN retransmits for a timeout). The counter survives the socket closing, so an exchange too fast to sample in `SYN_SENT` (a local network) still shows the SYN went out; a connect never issued sends nothing. An immediate error (no `EINPROGRESS`) counts only when kernel state independently implies it: `ENETUNREACH` or `EHOSTUNREACH` only when the kernel's own route lookup for the canary's address (netlink `RTM_GETROUTE`, after policy rules) returns no route, unreachable or prohibit. An immediate `ECONNREFUSED`, `EACCES` or `EPERM` never counts: an active filter elsewhere doesn't show it denied this call. A bound local port alone is not evidence; the same client call reached the loopback listener the probe bound itself in this run (SBX-1 (d)); confirmed canary health on that port covered the attempt's whole span (SBX-11); no receipt for this run on that port. The pass names destination, port and route. |

### Checks

Severity is that of a finding. Kind: 2 is two-sided, F is find-only. Evidence: P is proof, I is indicator.

**SEC: readable secrets**

| ID | Checks | How | Kind | Ev | Sev | From |
|-|-|-|-|-|-|-|
| SEC-1 | secret-shaped names in the agent's environment (`KEY`, `TOKEN`, `SECRET`, `PASS`, `CREDENTIAL`, `AUTH`, `PRIVATE`, `DSN`, `_PAT`, `DATABASE_URL`) | names only, so an indicator: a secret-shaped name doesn't prove a secret is there; `SANDPROBE_TWIN`, set by the adapter, shows through the same read | 2 | I | High | internal research; Northflank, 30 Oct |
| SEC-2 | other processes' environment, same UID and other UIDs | `open` of `/proc/<pid>/environ`; `scoped_out` when no such process is visible | 2 | P | High | check-box ISO-1 |
| SEC-3 | credential files: `~/.aws/credentials`, `~/.config/gcloud/`, `~/.kube/config`, `~/.docker/config.json`, `~/.netrc`, `~/.git-credentials`, `~/.config/gh/hosts.yml`, `~/.npmrc`, `~/.pypirc`, `~/.ssh/id_*`, `/etc/shadow`, the files AI coding tools document as their credential store on Linux (`~/.claude/.credentials.json`, `~/.codex/auth.json`, `~/.codex/.credentials.json`, `~/.gemini/oauth_creds.json`, `~/.aider/oauth-keys.env`, `~/.cline/data/secrets.json`, `~/.config/goose/secrets.yaml`; a file that holds credentials only sometimes, such as a tool's general config, isn't listed (a `.env` such as Gemini CLI's `~/.gemini/.env` isn't listed either, but the `.env` discovery below covers it like any other `.env`), and a tool's own relocation variable, such as `CLAUDE_CONFIG_DIR`, isn't followed), every file under `/run/secrets` (walked four levels down, through symlinked directories, so Kubernetes' and EKS's service account token directories are covered), `/var/run/secrets/kubernetes.io/serviceaccount/token` (a symlink chain in Kubernetes), `.env` in home and the working directory (depth 2, `/` included, procfs and sysfs skipped) | `lstat`; symlinks resolved per SBX-2; `open` read-only of a regular target only. Discovery (`~/.ssh`, `/run/secrets`, `.env`) asks what the agent can reach: a directory it can't search is skipped, since nothing in it is reachable; one it can search but not list makes SEC-3 unknown, except that at the last `.env` level its `.env` is checked by name; any other error is unknown. A proof needs the file to be non-empty (SBX-2's in-memory bit; no size is emitted); a readable empty file is an Info indicator | 2 | P | High | internal research; check-box BOX-3 |
| SEC-4 | metadata credentials: AWS IMDSv1 and v2 role listing; GCP service account listing; ECS (`169.254.170.2`) and EKS Pod Identity (`169.254.170.23`) by their variables and a TCP connect, no request; Azure isn't contacted, since it has no listing that names an identity without an identity call. Never a role's credential document, and never a metadata address that is local to the box. One deadline (SBX-7's 10 s) covers the whole check; each listing is asked on its own, so a service ignoring one request is still asked the others, and only nothing accepting a connection skips the rest. Time running out before every listing was asked is unknown, unless a role was already found. An answer is read whole or not at all (a body cut short by a stall, a close, a cap or its own length is an error); a request line or header holding a control character is never sent, and an IMDSv2 token that isn't token-shaped is never sent back, leaving SEC-4 unknown unless another listing names a role | a role or identity is listed or offered | F | I | High | AWS Nitro launch (isolated mode allows IMDS and Pod Identity); Hugging Face timeline, July |
| SEC-5 | other processes' memory: a same-UID process that isn't the probe's descendant, and another UID's | `open` of `/proc/<pid>/mem`, no read; `ptrace_scope` recorded; `scoped_out` when none is visible | 2 | P | High | Daytona advisory, 13 Apr |

**EGR: ways out**

| ID | Checks | How | Kind | Ev | Sev | From |
|-|-|-|-|-|-|-|
| EGR-1 | A looked-up name reaches our name server | a lookup of `<nonce>.dns.<our domain>` through the box's resolver; a logged query is the finding, whatever the answer | F | P | Medium | internal research |
| EGR-2 | A nonce sent by HTTPS straight out reaches our canary | TLS to the canary's IP, SNI `<nonce>.canary.<our domain>`, key matches our pin, reply echoes the nonce | 2 | P | Medium | internal research |
| EGR-3 | HTTPS through the box's proxy variables | as EGR-2, through the proxy `HTTPS_PROXY` and friends name, by the probe's own client (SBX-6); a local proxy only with approval (SBX-3), else skipped | F | P | Medium | VerCellBreak, 12 Oct |
| EGR-4 | TLS interception | the key isn't our pin: interception recorded, and EGR-2 for that route is unknown, never a pass | F | I | Info | internal research |
| EGR-5 | other ports out | TCP 22, 80 and 8080 to the canary's IP, two-sided per port; UDP 53 to the canary's IP, find-only; the nonce in the first bytes | 2 per TCP port, F for UDP | P | Medium | check-box ISO-2 |
| EGR-6 | upload-capable hosts on an allowlist (needs approval, open question 2) | TLS handshake only, no request: `github.com`, `raw.githubusercontent.com`, `registry.npmjs.org`, `pypi.org`, `s3.amazonaws.com`, `storage.googleapis.com`, `api.anthropic.com`, `api.openai.com`, the provider's own API | F | I | Medium | VerCellBreak; Pluto on Claude Managed Agents |

**PER: persistence that survives a reset**

| ID | Checks | How | Kind | Ev | Sev | From |
|-|-|-|-|-|-|-|
| PER-1 | startup files a session may run: `~/.bashrc`, `~/.profile`, `~/.bash_profile`, `~/.zshrc`, `/etc/profile.d/`, `/etc/bash.bashrc`. Whether the agent's path sources them is recorded, not assumed | write or replace, per TWN-1's write-permission row; never opened for writing | 2 | I | Low | internal research |
| PER-2 | PATH directories ahead of the system's, and `/usr/local/bin` | as PER-1 | 2 | I | Low | internal research |
| PER-3 | boot and schedule: `/etc/systemd/system/`, `~/.config/systemd/user/`, `/etc/cron.d/`, the cron spool, `/etc/rc.local`, `/etc/init.d/` | as PER-1 | 2 | I | Low | internal research |
| PER-4 | supply chain and access: `~/.npmrc`, pip config, `~/.gitconfig`, git hook templates, `~/.ssh/authorized_keys` | as PER-1 | 2 | I | Low | internal research |
| PER-5 | storage that survives the provider's reset | throwaway boxes only, after the main run: a marker in each storage root the agent can write: home, the working directory, and each writable mount the adapter declares part of the box (deleted with it), never a persistent volume Sandprobe didn't create; as the plan's rule states them and the survey's read-only inventory resolves them, deduplicated, looked for after the reset (TWN-3). A surviving marker is the finding, proven by TWN-3; with every planned root marked and rechecked after a proven reset and no marker left, `not_found`, since something other than the reset may have removed it, and other data's persistence stays not proven. A root that refused its marker, changed, or couldn't be rechecked is unknown, and so is PER-5 unless a marker survived elsewhere. Where the reset recreates the box, only persistent volumes Sandprobe created for the run and deletes after it, by ID with the provider's confirmation; with none, skipped. The host, not the probe, decides High: from the catalog's PER-1 to PER-4 targets that lie in a surviving root and the recheck's `write_perm` observations of them | F | P | High if a replaceable PER-1 to PER-4 path lies in a surviving root, else Medium | internal research |

**AMP: amplifiers**

| ID | Checks | How | Kind | Ev | Sev | From |
|-|-|-|-|-|-|-|
| AMP-1 | sudo without a password | `sudo -n -l` only, which lists policy and runs no command, from a root-owned setuid sudo at a fixed path that is a regular file, not a symlink, that the agent can't write itself, and whose ancestor directories the agent can't write or replace (TWN-1's write-permission row). The file is pinned with `O_PATH` and `O_NOFOLLOW`, checked on that descriptor, and run through the same descriptor (`execveat`, or `/proc/self/fd/<n>` as `fexecve` does), so the checked inode is the one that runs; a sudo found only elsewhere on PATH, or failing that check, is recorded and never run, and AMP-1 is then unknown. Found: a listed `NOPASSWD` rule; Critical when it allows all commands, High for named commands. Only that classification leaves, with the number of rules: a rule's commands are never recorded, since an argument can be a secret (SBX-2). The listing is read as it arrives, and sudo's whole run is bounded by SBX-7's 10 s, after which it is killed with everything it started (its own process group) and AMP-1 is unknown. `absent` when no sudo exists at `/usr/bin/sudo`, `/bin/sudo`, `/usr/local/bin/sudo` or on PATH. Otherwise `not_found`: a site's `listpw` setting can hide a `NOPASSWD` rule, and the agent can't read the policy to rule it out. sudo may log the listing | F | P | Critical or High | check-sprite (exit 87); check-box BOX-2; internal research |
| AMP-2 | root or capabilities | `/proc/self/status`: uid 0, or `CapEff` holding `SYS_ADMIN`, `SYS_PTRACE`, `SYS_MODULE`, `DAC_OVERRIDE` or `DAC_READ_SEARCH`, is Critical; any other non-zero `CapEff` is High | 2 | P | Critical | check-sprite (exit 82) |
| AMP-3 | new privileges | `NoNewPrivs` is 0 and setuid-root files exist in the system binary directories | 2 | P | Medium | check-sprite (exit 83); check-box ISO-2 |
| AMP-4 | control sockets | `lstat` and `faccessat(W_OK)` on the socket file and its directories, never connected: `/.sprite/api.sock`, docker, containerd and podman sockets are High; the system bus is Medium. An indicator: the server may be gone (a stale socket) or reject the agent by peer UID, which no permission check, nor even a connect, can rule out. Abstract sockets from `/proc/net/unix` are listed | 2 | I | High | check-sprite (exits 84, 85); check-box ISO-2, ISO-4 |
| AMP-5 | local daemons | LISTEN entries and owner UIDs from `/proc/net/tcp` and `tcp6`, never connected; a known control port (2375, 2376, 10250) in the probe's network namespace is High. An indicator: an owner-match firewall rule can block what the table shows | 2 | I | High | check-box ISO-4; internal research |
| AMP-6 | vsock to the host | `/dev/vsock` and the local CID; on throwaway boxes, connect to CID 2 on a fixed port list (to be set from the AWS docs; unverified), sending nothing. The survey reports whether `/dev/vsock` exists (`lstat` only); without it AMP-6 is skipped, and until the port list is set a present device leaves it unknown | F | P | Medium | AWS Nitro launch ("not absolute isolation") |
| AMP-7 | the Kubernetes API | TCP and TLS handshake to the API `$KUBERNETES_SERVICE_HOST` names, no request; the survey reports it, the plan names it, and the probe contacts only that one, never at a local address | F | I | Medium | AWS Nitro launch (EKS) |
| AMP-8 | kernel and host surfaces, graded as two checks: kernel settings (`faccessat(W_OK)` on named `/proc/sys` entries, never written) and block devices (`lstat` and `faccessat(R_OK)`, never opened; none visible is `scoped_out`) | 2 | P | High | CDK-style checks, kept non-mutating |

### CHN: chains

- **CHN-1 A readable credential or process surface, with a proven way out.** Critical and confirmed: a proof of a
  readable surface (SEC-2 or SEC-5 found, or SEC-3 found on a non-empty file) and a canary receipt (EGR-1, EGR-2, EGR-3
  or EGR-5 found). The probe never reads a value, so it claims neither that a secret is present nor what the data is,
  only that the agent can open that surface and can send data out. High and potential, titled "a secret may be able to leave": either side rests on an indicator
  (SEC-1, SEC-4, an empty SEC-3 file, EGR-6, AMP-7). The finding names its parts, which stay listed.
- **CHN-2 A proven root-equivalent amplifier caps everything.** AMP-1 at Critical, or AMP-2 at Critical, makes the grade F,
  and the report says every refusal above held only for an unprivileged agent. Indicators (AMP-4, AMP-5) never trigger
  CHN-2 on their own; the report still shows them as serious exposed surfaces.
- **CHN-3 Credentials and the Kubernetes API.** A readable service account token (SEC-3) with AMP-7 found is High and
  potential.

### GRD: the grade

- **GRD-1 Letters.** F: any Critical. D: any High. C: any Medium. B: only Low. A: nothing above Info, and complete.
- **GRD-2 Complete.** Every two-sided check in the manifest ended `pass`, `finding`, `absent` or `scoped_out`. Any
  unknown makes the run incomplete: its grade is the worse of its findings' grade and C, printed with the count, such
  as `C (incomplete: 3 unknown)`. An incomplete run never shows A or B.
- **GRD-3 Skipped is not unknown.** A check not selected for this run (EGR-6 unapproved; EGR-3 when the agent's
  environment names no proxy, or names a local one nobody approved; AMP-6 with no vsock device, or on an existing box
  (PRV-1); any write-based check on an existing box; a check a provider's rules of engagement exclude, PRV-5; a check that would contact a
  provider-owned endpoint under PRV-15's default for an unidentified provider, or RCP-4's for a recipe) is `skipped`
  and listed. Only the checks these gates name can be skipped (EGR-3, EGR-6, PER-5 and AMP-6, and SEC-4 and AMP-7 for
  a provider whose rules exclude them or under PRV-15's or RCP-4's default), only by the host, and each with its
  reason; AMP-2 and AMP-3 never are. A provider-endpoint skip (SEC-4, EGR-3, AMP-6, AMP-7) also records its kind in
  the manifest's `SkipKinds` (SCR-2): `provider_terms` from a native adapter's PRV row (PRV-5), `opt_in` under
  PRV-15's or RCP-4's default. Skips change no letter.
- **GRD-4 The grade says what it covers.** Beside every grade: "graded on N checks for this box at <time>, from a
  host-shipped probe's own observations; not a certification", SBX-10's boundary, the not-proven list (KND-2), and the
  scoped-out and skipped lists.
- **GRD-5 The host trusts nothing from the box.** Before the run, the host fixes the manifest: the mode, the checks
  selected, each check's planned targets and discovery rules (from the catalog), the run nonce, one nonce and one
  planned endpoint per canary check, EGR-3's proxy and whether a local one is approved, the box's immutable provider
  ID, the probe's digest, each provider-endpoint skip's kind (GRD-3), and the provider-endpoint checks the person
  attested (PRV-15). A pass or an absence
  must cover every planned target and report every discovery rule with exactly the targets it found; a gap is unknown,
  and a target nobody planned invalidates the run. The probe reports its identity (SBX-4) once, and the host always
  grades AMP-2 and AMP-3 from it, whether or not the probe reports them: AMP-2 from uid and CapEff, AMP-3 from
  NoNewPrivs and the setuid scan (with NoNewPrivs 0 and no completed scan, AMP-3 is unknown). Any AMP-2 or AMP-3 observation that differs, whatever its result, or a proof's
  root flag that contradicts the identity, invalidates the run, as does a missing identity. So does an unsound
  manifest: a check neither selected nor skipped, both, selected twice, or skipped without a GRD-3 gate or a reason;
  a skip kind on a check that isn't skipped or isn't a provider endpoint, or a kind other than SCR-2's two; an
  attestation on a check that isn't a provider endpoint, is named twice, or still carries a skip kind;
  a selected canary check without its own nonce or a planned endpoint; or EGR-3 without a planned proxy (unless the
  manifest says the agent's can't be parsed, and then never with one) or with an unapproved loopback one. So does an attempt through any proxy but the planned one, through a loopback proxy
  nobody approved, or through a proxy on any route but EGR-3's. The probe's
  observations are keyed to it. A check the manifest expects and the observations lack is unknown. Any of these makes
  the run invalid, with no letter and exit 5, and the report says why: a duplicate check ID, an ID not in the manifest,
  two outcomes for one check, a nonce, box ID or digest that doesn't match, malformed evidence, a field over its limit
  (2 KB per evidence field, 1 MB per document), or an unrecognised override field.

### OUT: what it writes

- **OUT-1 JSON.** `schema`, the lowest version whose fields the report needs (AGT-6): `sandprobe/1`; `sandprobe/2`
  when the manifest carries SCR-2's `SkipKinds` or PRV-15's `Attested`; `probe {version, sha256, host_shipped}`; `run {id, nonce, started_at` (RFC 3339,
  UTC)`, duration_ms, mode, provider, box {provider_id, name, created_by_sandprobe}}`; `manifest`; `identity` (SBX-4);
  `toolchain [{name, path, owner, mode, link_target}]` (lstat metadata of box tools, never a hash: only `probe.sha256` is a digest); `overrides []`; `checks [{id, category, kind, result, evidence_class,
  severity, scope {destination, port, route}, evidence, proof {mechanism, result}, clients, fix, duration_ms,
  attestation}]` (`attestation` only for a check PRV-15's `-provider-endpoints` selected);
  `findings [{id, severity, class, title, checks, fix}]`; `grade {letter, complete, valid, unknown, counts}`;
  `limits {not_tested, not_proven, scoped_out, skipped}`; `contacted [{host, port, proto, check}]`; `receipts []`;
  `markers [{path, dev, inode, confirmed, cleanup}]` (cleanup: gone with its box or volume, the provider having confirmed the deletion, or an unresolved item); `reset {operation_id, before, after}`; `provider_calls []`. Names map onto
  OpenTelemetry: the grade becomes a `sandprobe.grade` metric, and each finding a log event under `security_rule.id`,
  `security_rule.name` and `security_rule.category`. The exporter itself is later.
- **OUT-2 HTML.** One self-contained file that loads nothing from the network, holding everything the JSON does, passes
  included, with their proofs. Every string from the box is escaped as text, and the embedded JSON is encoded for a
  script data block. A Content-Security-Policy meta tag sets `default-src 'none'`, inline styles, and `script-src` to a
  random nonce the host makes for that report, so text a box injects can't run. Its layout is UX-11.
- **OUT-3 What talks to what.** Reports are written locally: no upload, no telemetry. The host contacts only the
  provider's own API (through its CLI or SDK) and our canary (liveness and receipts, carrying the run's nonces only). The
  box, through the probe, contacts exactly SBX-3's list, which includes metadata addresses, EGR-6's public hosts once
  approved, and vsock; the plan and `contacted` list each one.
- **OUT-4 Exit codes.** 0 graded; 2 usage error; 3 needs approval; 4 needs login; 5 incomplete or invalid; 6 graded
  below `-min`; 7 a box or volume Sandprobe created is neither confirmed deleted nor explicitly retained under PRV-7. After a run, 7 takes precedence over 6, 6
  over 5, and 5 over 0. A run that ends 5, 6 or 7 still writes its reports.

### UX: the human experience

- **UX-1 Install.** One command (brew, a curl script, or `go install`) gets one binary, which carries the probe builds.
  Not yet: until release builds exist, `make` builds the probes and then the binary; a `go install` alone carries no
  probe, and `run` says so and stops before creating anything.
- **UX-2 Pick.** `sandprobe` with no arguments in a terminal asks where the agent runs (Sprites, AWS Nitro Sandboxes,
  Modal, Baseten, exe.dev, somewhere else) and what to probe: a new throwaway box with default settings, or a box the user
  already has.
- **UX-3 Access.** The CLI checks the provider's own CLI or SDK is present and logged in. If not, it prints the exact
  command (`sprite login`) and stops. It never asks for, reads or stores a credential.
- **UX-4 A plan, then one confirmation.** Before anything is created, the plan lists: what will be created; the launch
  path; where the probe binary and its scratch directory go; where markers go; every fixed host, port and metadata
  address the probe will contact (the canary, SEC-4's addresses, EGR-6's hosts once approved), and each class of
  destination only the box can name. SEC-4's are one list in the catalog (`catalog.Metadata`: 169.254.169.254:80,
  169.254.170.2:80 and 169.254.170.23:80, the last two with the variable that offers each), which the probe dials
  and every plan and report names, each with its port and condition, so the plan and the probe can't disagree. AMP-7
  and EGR-3 have no fixed destination: each is the one the box's environment names; the files it will open read-only; that it will run `sudo -n -l`, which runs no
  command and may be logged; what the reset does; what will be deleted; and whether a local proxy may be contacted if
  the box names one (the default is no, and EGR-3 is then skipped; `-allow-local-proxy` for agents). One confirmation,
  before anything is created; nothing later asks again. What only the new box can tell, the plan authorizes as a
  bounded class: markers are `.sandprobe-<run id>` in the agent's home, its working directory, each writable mount the
  adapter declares part of the box (deleted with it), and each volume Sandprobe creates; the proxy is the one the
  agent's environment names, for EGR-3 only; the Kubernetes API is the one its environment names, for AMP-7 only.
  Once the box exists, the survey supplies the actual values, and the resolved plan names each exact path and endpoint
  before anything is marked or contacted; the manifest pins them (GRD-5), and the report lists them. A value outside
  its approved class (a local proxy without the opt-in, a mount the adapter doesn't declare) is never contacted or
  marked: its check is skipped, or that root listed and left alone. For an existing box, the plan says: the probe binary and scratch
  directory, both removed; no markers, no reset, no deletion; and it asks the user to confirm the box isn't a
  production host by typing its name (PRV-2).
- **UX-5 The live run.** A header holds provider, box, identity and a timer. The containment map puts the agent in a
  box whose walls are SECRETS (top), EGRESS (right), PERSIST (left) and AMPLIFIERS (bottom). Each check sends a pulse
  to its wall. A verified refusal sparks and hardens the wall; a finding cracks it and the line leaves in red; an
  unknown or not-proven check marks the wall in amber. Under the map, a bar per category and a ticker of the latest
  checks. During the reset the box floods and drains, a rescan sweeps it, and surviving markers glow.
- **UX-6 The grade.** A large letter stamps in with a spring, and the severity counts tick up beside it. Incomplete,
  invalid and "not a certification" show with it (GRD-4).
- **UX-7 The explorer.** Two panes: findings by severity, then unknowns, then not proven, then verified passes. The
  detail pane gives what a hijacked agent gets, proof or indicator, the evidence, how we checked (the negative proof)
  and the fix. Keys: arrows, `c` copy the fix, `o` open the web report, `/` filter, `esc` back, `q` quit.
- **UX-8 Two palettes.** `modern` (cyan and white, red for breaches) and `mission` (amber on black, a light CRT feel),
  chosen with `-theme` and remembered locally.
- **UX-9 Accessibility.** Severity always shows as a symbol and a word, never color alone. `NO_COLOR` is honoured.
  Reduced motion (`SANDPROBE_REDUCED_MOTION=1` or `-still`) shows static frames. Everything fits 80 columns. Nothing
  flashes more than three times a second.
- **UX-10 Time.** The probe itself takes at most 90 s. Create to delete takes about 2 minutes on Sprites and Modal
  (estimates, not yet measured). AWS takes longer, about 20 minutes (estimate), because its plan includes creating and
  deleting an EKS cluster; its adapter's step bounds are raised to match (cluster create 25 min, delete 20 min), and
  the plan says so.
- **UX-11 The web report is the final report.** Every run writes OUT-2's page next to its JSON, and the grade screen
  offers `o` to open it. The page leads with the stamped grade and one sentence saying what a hijacked agent can do,
  then the containment map (each mark links to its evidence), the findings with a copy button on each fix, the
  unknowns, the not-proven list, every verified pass with its proof, and how the probe ran (identity, every host
  contacted, every marker and its fate, the reset's evidence). It carries both palettes, honours reduced motion, fits
  a phone, and prints on white.

### AGT: the agent contract

- **AGT-1 No terminal, no animation.** Without a TTY on stdout, or with `-o json` or `-o ndjson`, the CLI never
  animates, prompts or waits for input.
- **AGT-2 Commands.** Every one takes `-o json`.

| Command | Does | Creates anything |
|-|-|-|
| `sandprobe providers` | which providers are ready, with the login command for each that isn't | no |
| `sandprobe plan <provider>` | UX-4's plan: what would be created, run, contacted, marked and deleted | no |
| `sandprobe run <provider>` | the plan, then the probe, reset and delete | yes, needs `-y` |
| `sandprobe self` | probes the box it's in, as the current user; unattested (SBX-10) | its scratch directory only |
| `sandprobe report <file>` | grades and renders a results file from `other` mode; unattested | no |
| `sandprobe cleanup baseten -baseten-state <journal> [-y]` | verify and delete only a prior run's recorded Baseten incarnation (PRV-7); no canary | none without `-y`; otherwise verified deletion |
| `sandprobe explain <check>` | what a check does, why it matters, its proof, its fix | no |
| `sandprobe guide` | the agent guide; `-install claude` writes a Claude Code skill, `-install codex` an AGENTS.md block | the skill or block only |
| `sandprobe schema` | the JSON Schema for OUT-1 | no |

- **AGT-3 Approval.** Outside a terminal, anything that creates, resets or deletes needs `-y`. Without it, `run`
  exits 3 and prints the plan as JSON with `needs_approval: true`. A local proxy for EGR-3 needs `-allow-local-proxy`, or EGR-3 is skipped. An existing box also needs `-attest <provider id>`,
  naming the box the person confirmed isn't production. The guide tells agents to show the plan to their person and
  get both before running again.
- **AGT-4 Streams.** `-o json` prints one OUT-1 document on stdout at the end. `-o ndjson` prints one event per line
  (`step`, `check`, `result`, `error`). Logs go to stderr.
- **AGT-5 Errors say what to do.** `{"error": "<code>", "message": "...", "fix": "<command or action>"}`, with codes
  from a fixed list: `usage`, `cli_missing`, `not_logged_in`, `needs_approval`, `needs_attestation`, `provider_error`,
  `timeout`, `invalid_run`.
- **AGT-6 A stable schema.** A breaking change to OUT-1 bumps `sandprobe/N`. A new field is breaking, since readers
  refuse unknown fields (JON-1). A report declares the lowest version whose fields it needs, so one that needs none of
  a newer version's fields keeps the older identifier, byte for byte, and older readers still read it. A reader takes
  every version it knows and refuses a report whose declared version isn't exactly the one its fields need: a
  `sandprobe/1` report carrying `SkipKinds` or attestations, or a `sandprobe/2` one with neither. A reader older than a report refuses
  it as unsupported input; its fix names the versions it reads, and the report's own `schema` says which it is. Versions:
  `sandprobe/1`; `sandprobe/2` adds the manifest's `SkipKinds` (SCR-2), and its `Attested` with a check's
  `attestation` (PRV-15), both new in one release.

### PRV: providers

- **PRV-1 Only our own throwaway boxes are reset or deleted,** addressed by the immutable ID their create call
  returned in this run (except PRV-7 recovery of an authenticated prior-run journal and PRV-13’s explicit exe.dev name-addressed lifecycle exception). Names and labels are recorded but are never the authority outside PRV-13. An existing box is never reset or
  deleted, and gets non-mutating checks only: no markers, no vsock connects (GRD-3 lists what that skips). The only
  things placed on it are the probe binary and its scratch directory, both removed at the end; a failed removal is
  reported with its cleanup command. Where a provider reaches a box only by name (Sprites: exec, checkpoint, restore
  and delete; Baseten: PRV-6 incarnation guards), the name must answer with the recorded ID immediately before each such call, or the call isn't made,
  and on each side of every read of the box's state by name (the checkpoint list), or the read doesn't count;
  a delete counts only on the provider's "not found" after, and a restore whose box answers with another ID after it
  ends the run's PER-5 there, with no recheck. The race between a check and its call is residual, and the run's
  record states it beside the cleanup outcome. A create that fails without returning an ID
  leaves its name recorded: if the provider then shows a box by that name, it is reported unresolved, never deleted.
- **PRV-2 Never production.** Throwaway boxes are created only in the org or account the operator names.
  sandprobe has no list of production hosts, so for an existing box the boundary is the person's attestation (UX-4,
  AGT-3), which the report records, and the report says that's what the boundary is.
- **PRV-3 Every provider call is recorded.** Create, copy, exec, reset and delete land in `provider_calls`, with the
  IDs they returned. A failed delete is shown loudly, with the command that finishes it.
- **PRV-4 Each adapter states its agent path and its reset,** and the report shows both (SBX-4, TWN-3).
- **PRV-5 A provider's rules of engagement narrow the checks.** Before any probe runs on a provider, its published
  security-research, bug bounty, penetration-testing and acceptable-use terms are read, and the PRV row cites what
  they say. Where they or the project owner exclude a destination or surface for that provider, the host skips
  the checks that would touch it (GRD-3), each with its reason and the kind `provider_terms` (SCR-2), and the report
  lists them. A surface that is only
  detected, such as a control socket's `lstat`, isn't excluded: detecting it is fine, using it isn't. Modal: SEC-4,
  AMP-6, AMP-7 and EGR-3, since each would send a request to an endpoint Modal owns.

- **PRV-6 Baseten lifecycle and bounded scope.** Authenticate at `https://api.baseten.co/v1/token` with a host-only
  personal API key or full-access team key, exchanging it for an access token scoped to the sandbox API across accessible teams (not one sandbox). Never send the API key
  to the guest, or put either credential in a report, journal, command, or error. Read the key from
  `SANDPROBE_BASETEN_KEY_FILE` (a regular owner-only file belonging to the current user), or `BASETEN_API_KEY`; an explicitly selected file that
  cannot be read never falls back to another credential. HTTP redirects are refused. HTTP errors expose only status
  codes, never provider bodies, headers, request payloads, or underlying transport errors.
  - Create once, with a fresh random `sandprobe-` name, unique `external_id`, no secrets, previews or volumes,
    the built-in `baseten/base-image:latest`, the default CPU/memory allocation, and `TTL_MAX_AGE DELETE 15m`.
    Persist the intended name, team and external ID in an exclusive mode-0600 state file in an owned, non-symlink directory with no group/world write access before the POST. Do not
    retry creation or adopt a sandbox found by name after a lost/malformed response. Such a run exits 7 and leaves
    the journal for manual reconciliation; automatic expiry is a backstop, not confirmed cleanup.
  - The API addresses sandboxes by name and permits reuse after termination. Bind each call to the create-returned
    name, execution URL, `created_at` and `external_id`, persist that tuple before upload, wait within the run deadline for `DEPLOYED` with the same tuple, and compare a fresh GET
    before upload, execution and delete. No call proceeds after detecting a replacement. This is a documented name/operation race,
    as for Sprites, not conditional deletion by immutable server ID. Record that residual beside cleanup.
  - Guest execution URLs must be HTTPS, without userinfo, port, query, fragment or non-root path, and match
    `sbx-<created-name>-<team>.<region>.b10.co` or `.b10.run`. Only the sandbox access token is sent there.
    Upload the shipped binary through the filesystem API; execute through `/process` as the image's default user,
    with `SANDPROBE_TWIN=1`, no automatic restart, a bounded timeout and an explicit completed/exit-zero response.
    Stdin is the host-generated manifest encoded in a fixed shell pipeline, never credential material.
  - Suspend/resume is not a reset. With no run-owned persistent volume, PER-5 is skipped with its recorded reason.
    Initial provider-control exclusions are SEC-4, EGR-3, AMP-6 and AMP-7; no metadata, proxy, vsock or Kubernetes
    API requests. Probe traffic goes only to our canary and DNS names we control. Every excluded check stays visible.
  - Delete only the recorded incarnation and confirm a subsequent 404 or `TERMINATED`. A replacement, an unknown
    status, failed identity check, timeout or failed deletion remains unconfirmed and exits 7. Persist state until
    confirmed deletion. Independent cleanup runs after cancellation; no success is inferred from DELETE acceptance.
  - Terms reviewed 11 Nov 2026: [Baseten terms, section 4.3](https://www.baseten.co/terms-and-conditions) restrict
    attempts to "gain unauthorized access" and use to "build a competing product or service". No affirmative research
    permission was found. A live run needs the operator's own authorization, with reasonable spend. Initial scope is the CPU-only, canary-only subset above: one sandbox at a time, at most two live runs for
    this implementation, 15-minute maximum age each; no unrelated workloads or provider-control probes. Normal
    authenticated inventory is separate. Docs: [management](https://docs.baseten.co/sandboxes/manage),
    [authentication](https://docs.baseten.co/sandboxes/authentication), and
    [runtime](https://docs.baseten.co/reference/sandbox-api/overview).

- **PRV-7 Explicit Baseten inspection retention.** An operator may keep the sandbox at the end of a run for
  inspection. `run baseten -keep-sandbox -y` requests this before creation; it is never enabled by an environment
  variable or by default. The plan names the spend and cleanup change. Baseten-only flags on other providers fail
  as usage errors. Ordinary runs keep PRV-6's 15-minute maximum age and verified deletion.
  - Inspection runs request `TTL_MAX_AGE DELETE 1h` at creation, with the same default CPU size and no secrets,
    volumes or previews. This is one hour from creation, not from run completion. The private journal records the
    retention request and absolute expiry derived from the create-returned timestamp before execution.
  - Only a valid, complete graded run with no error/cancellation may retain its original deployed incarnation.
    Grade F or failing `-min` is not an execution error and may still be retained for inspection. A final identity
    check, the server's unchanged `TTL_MAX_AGE DELETE 1h` policy, and a present positive `expires_in` consistent with
    recorded creation time plus one hour (five seconds of clock/rounding tolerance) are required, then the journal is
    marked retained. Retention never updates or extends that deadline. Failure, incomplete/invalid runs, interruption, or failed retention verification use normal
    independent-context deletion; unresolved deletion still exits 7. Retention never overrides the stop-and-report
    rule or authorizes repeating a held probe surface.
  - Reports explicitly say intentionally retained, never deleted, and add optional `cleanup.retention` containing
    `expires_at`, `state_file`, and a structured `cleanup_command` argument list. This additive field preserves
    `sandprobe/1` (a Baseten report declares `sandprobe/2` for SCR-2's skip kinds). Normal grading exit codes apply after verified intentional retention; report-write failure after
    retention remains an error and prints the journal path/expiry to stderr. Never lose the operator's recovery path.
  - `cleanup baseten -baseten-state <journal> -y` needs no canary. It reads only a regular current-user-owned mode-0600
    journal without following symlinks, rejects unknown/malformed fields or an unconfirmed create, restores its recorded
    team (rejecting a conflicting explicit selector), and deletes only the recorded incarnation using PRV-6's checks.
    No approval means no provider calls. Expired/terminated resources still require verified terminal/404 before
    journal retirement. Replacement or failed deletion retains the journal and exits 7. This explicitly permits
    cleanup of a prior run's own recorded resource, never adoption of an existing unrelated sandbox.
  - Local fake-provider tests cover retention lifecycle/expiry, interrupted/invalid runs, expiry verification failure,
    state recovery, replacement, cleanup approval and truthful report output. No additional live probe is authorized
    by this feature.

- **PRV-8 E2B bounded baseline.** Use the E2B-managed default `base` CPU template and native management API at
  `https://api.e2b.app`, with the existing probe, canary and grader. Read `SANDPROBE_E2B_KEY_FILE` (a current-user-owned,
  regular owner-only file) or `E2B_API_KEY`; an explicitly selected unreadable file never falls back. Never send the
  management key into the sandbox, command arguments, journals, reports or errors. Refuse redirects; HTTP errors
  include only status. Use the official Python `e2b==2.63.0` SDK for file/command runtime transport, with a configurable
  host Python 3.11+ interpreter and a clean environment; feed only the sandbox-scoped access token via stdin. Check its exact version
  before creating anything. No implicit SDK installation. Pin every runtime dependency and its artifact hashes in
  `internal/host/e2b-requirements.lock`; install with `pip --require-hashes --only-binary=:all:`. Record the interpreter
  dependency in the plan and README.
  - Journal a unique run marker before one POST to `/v2/sandboxes`, requesting `templateID=base`, secure controller access (v2 default),
    `autoPause=false`, a 900-second timeout, `allow_internet_access=true` (the provider default), empty injected environment
    and no volumes or previews. The egress checks measure that default rather than asserting it must block traffic. Never retry create.
    Record the returned immutable sandbox ID immediately, even if other response fields are invalid. An ambiguous
    create retains an unresolved journal and exits 7; never discover or delete a box by its name or marker.
  - Check returned-ID metadata before runtime calls and deletion. Verify the server expiry is positive and within
    901 seconds of server runtime and at most 16 minutes from the create request (one minute provisioning tolerance).
    Runtime URLs use only E2B-managed `e2b.app` domains, with the recorded ID/port routing headers and scoped token.
    Run as the template's normal `user`, not root. Upload into a private random scratch directory and verify SHA-256
    before execution. Input is a private file removed by the command wrapper; output and time are bounded.
  - Normal runs always delete using a fresh cleanup context and confirm GET returns 404. Cancellation and failures
    do the same. Keep unresolved journals, never claim deletion on 401/403 or failed transport. No retention, pause,
    connect/resume, reset, custom templates, model calls or persistent storage in this initial adapter. PER-5 is skipped.
    SEC-4, EGR-3, AMP-6 and AMP-7 are excluded with reasons; EGR-6 remains unapproved. All test traffic goes only to
    our canary or names under its DNS domain. This is `exec` mode, not an agentic workload benchmark.
  - Terms reviewed 12 Nov 2026: [E2B terms](https://e2b.dev/terms), Prohibited Conduct 7 prohibits testing
    "the vulnerability of any part of the Services"; the adjacent clauses restrict interference and circumvention.
    [Security](https://e2b.dev/security) supplies no affirmative research authorization. A live run needs the operator's own recorded authorization for this
    bounded scope, never represented as provider permission. Offline builds and tests are always permitted.

- **PRV-9 Vercel bounded baseline.** Use the managed Vercel Sandbox API over the official SDK's exact fixed base `https://vercel.com/api`,
  as documented by the official `@vercel/sandbox` 3.9.1 source (12 Nov). Native Go HTTP implements this wire contract;
  no SDK runtime dependency. Do not substitute a different API origin or remove the `/api` prefix; local HTTP contract tests assert the literal origin/prefix for all lifecycle/runtime requests. Project creation remains on the documented public REST origin in its separate setup helper. Read `SANDPROBE_VERCEL_KEY_FILE` (regular, current-user-owned, owner-only, no symlink/FIFO)
  or `VERCEL_TOKEN`, and require explicit `VERCEL_TEAM_ID` and `VERCEL_PROJECT_ID`. A selected bad file never falls back.
  Confirm the project belongs to the selected team before creation. The API token never enters guest commands,
  environment, files, journals or reports. Refuse redirects and expose only fixed operation/status and allowlisted diagnostic category/field labels on provider errors; never raw response bodies, URLs, server messages/codes or credentials. Read at most64KiB for diagnostic classification; malformed/oversized bodies yield no hints. Diagnostic labels describe provider wording, not an established cause.
  - Validate every reusable sandbox name against the exact generated-name grammar before any named GET or DELETE; invalid names never reach the provider and cleanup preserves the unresolved journal.
  - Journal random requested name/run tag and selected team/project before one POST `/v3/sandboxes`: built-in
    `vercel/sandbox/universal` image, `persistent=false`, timeout900000ms, two CPU cores, empty env/ports/mounts,
    explicit allow-all baseline networking with no credential injection or proxy configuration. Native command calls
    target the immutable create-returned session ID, invoke the image's fixed absolute `/bin/bash -c` without a fallback or retry, use sudo=false and SANDPROBE_TWIN=1, a 95000ms command timeout,
    the template's ordinary user and immutable create-returned working directory. Accept only `/vercel` (current universal image) or `/vercel/sandbox` (legacy image); persist it before runtime and require it unchanged on each runtime identity check. Derive the private scratch path from that recorded directory and reject a response/upload path under the other directory. Never assume a directory exists or create an alternative base directory. No agent/model workload or privilege escalation is executed.
  - Persist the returned session ID before parsing optional fields; preserve unresolved journals and never retry
    create or adopt by name. All sandbox-name reads set resume=false. Check random name, createdAt, run tag,
    currentSessionId, non-persistence/no snapshot/no mounts and runtime lifetime before each operation. Require
    session timeout in (0,900000]ms, start/creation not more than60s in the future, and create-request to server
    start/creation within120s; now must precede server start plus its timeout. No timeout extension is allowed. Runtime
    requests use only the immutable returned session ID. Upload a gzip/tar containing only the named file into a
    private random directory; verify SHA256 before execution. Bound command stream wire bytes and combined
    stdout/stderr, require initial/final command identity and explicit zero exit status; never treat truncated streams
    or a missing terminal event as success. No command POST is retried.
  - Cleanup runs under a fresh three-minute context: stop only the immutable returned session ID, verify terminal
    status or definitive404, then delete the original non-persistent sandbox record only after identity checks and
    verify named GET404. No snapshots, drives, resume or timeout extension. Name deletion has a residual check/call
    race, recorded beside cleanup; the dedicated project and random names reduce competing writers but do not prove
    the race impossible. A replacement name is never adopted. Unconfirmed VM/record cleanup keeps the journal and
    exits7. A timeout stops compute but is not proof the named record was deleted.
  - As with E2B, exclude SEC-4, EGR-3, AMP-6 and AMP-7 with reasons; EGR-6 stays unapproved and PER-5 is skipped without
    resettable run-owned storage. All network test traffic goes only to our canary or DNS names under its domain.
  - Terms: Vercel's published testing
    policy permits Pro/Enterprise customers to test their own applications, and says they "must not target the
    underlying hosting infrastructure and platform". A run needs a Pro or Enterprise team (checked by read-only API inventory). Scope
    stays within our own disposable guest, with no provider-control requests, exploits, escapes, load or other tenants.
    Terms source: https://vercel.com/kb/guide/penetration-testing-on-vercel; security guidance:
    https://vercel.com/docs/sandbox/concepts/security. Record any unavailable guidance rather than inventing consent.
  - Vercel's AUP (https://vercel.com/legal/acceptable-use-policy, last updated 21 Apr 2026, reviewed 13 Nov) says "You
    may conduct benchmark tests of a service", with an AI Services exception. Public disclosure must provide enough
    information to reproduce tests. The policy also forbids security undermining and unauthorized access. A run is CPU
    guest compute with no AI/model calls. This AUP allowance does not override the penetration-testing platform
    exclusion or establish provider approval.
    Live-evidence builds must come from a recorded source commit with the actual binary digest retained.
    One CPU sandbox combines upload/survey checks and one benchmark; no separate live smoke, retry or continuous job.
    Attempts are a finite budget the operator sets, with no automatic retry.
    One dedicated empty project may be created for this test: validate the token file before the exclusive intent journal, journal intent before a single POST, never retry or
    adopt after ambiguous creation, and persist the create-returned project ID immediately. The empty project is
    intentionally retained as an explicit residual with its recorded ID; no project deletion or deployments are
    performed. Sandbox/session/drive/snapshot compute resources must still be confirmed gone. Existing projects
    are never modified by setup.

| Provider | Default box | Agent path | Reset, and what TWN-3 can prove | Deleted | Verified |
|-|-|-|-|-|-|
| Sprites (Fly) | `sprite create sandprobe-<12 hex>`, default settings, in the operator's Sprites org | `sprite exec`, as the sprite's default user. The CLI reads `-s` and `-o` from any argument, even after `--`, so the probe's command goes as one `sh -c` string | a checkpoint before the probe (exactly one new version), a restore of exactly that version after, done by its own stream's `complete` event; same sprite ID, the provider's `Current` checkpoint time changes; roots `/`, `/tmp` and `/var/lib/docker`, with no provider identity each, so PER-5 finds or stays unknown, never `not_found` (TWN-3) | `sprite destroy` by name: Sprites has no delete by ID (`DELETE /v1/sprites/{name}`; a GET by ID is a 404, checked 9 Nov). The name must answer with the recorded ID just before, and a 404 after (PRV-1); the race between is residual, and the report states it | lifecycle verified live: create, exec, upload and destroy; the default user is `sprite`. Terms read 20 Nov (PRV-5): Fly's [AUP](https://fly.io/legal/acceptable-use-policy/) lists "Security testing (network or application scanning, phishing, or penetration testing)" among prohibited uses. Sandprobe isn't security testing of Fly; it checks that a customer can safely do the plumbing to use their own sprite as an agent sandbox, from inside that sprite. So SEC-4, EGR-3, AMP-6 and AMP-7, which would contact a Fly-owned endpoint, are excluded: no check traffic from the sprite reaches Fly; the host itself still uses Fly's API to create, checkpoint, restore and delete the sprite |
| AWS Nitro Sandboxes | an EKS Auto Mode cluster only Sandprobe uses (Kubernetes 1.37, the operator's AWS profile (`PROFILE`), made and deleted by `deploy/eks.sh`, which needs no add-ons: Auto Mode brings the runtime classes and sandbox-capable nodes). Pod A is the docs' own example: `public.ecr.aws/amazonlinux/amazonlinux:2023`, `runtimeClassName: isolated-sandbox`, its image's default user. Pod B adds `sandbox.amazonaws.com/network-isolated: "true"`, which boots the sandbox with no network device (its vsock still reaches guest-bound ports, AMP-6's surface) | `kubectl exec -i` into the pod's container, as its default user, with a kubeconfig of Sandprobe's own (never the user's): isolated mode permits `exec` and stdin. Confidential mode denies both, so it waits for a workload adapter | none in v1: the default pod has no persistent volume, so PER-5 is skipped (a recreate around an EBS volume Sandprobe creates can follow) | each pod by name once its UID is checked, in Sandprobe's own cluster; then the cluster, its IAM roles and whatever else `deploy/eks.sh` recorded, each by its recorded ID and confirmed not found | docs read 10 Nov 2026 (EKS user guide, Nitro Sandboxes); lifecycle verified live for pods A and B, each deleted and the cluster torn down |
| Modal | a sandbox in the operator's own Modal workspace, App `sandprobe`, through `github.com/modal-labs/modal-client/go` v0.11.1 (the older `libmodal/modal-go` is deprecated and has no sidecars). Image `python:3.12-slim-bookworm`, close to Modal's own `debian_slim` default, built once in that App; runtime and size left to Modal's defaults; a 15-minute timeout as a spend backstop; tagged `sandprobe-run=<run id>`. run through `sandprobe poc modal run -variant <setup>` (POC-1), where `-variant` picks a setup (POC-2): `default`, `domain-empty`, `domain-one`, `block`, `block-vm`, `sidecar`; `sandprobe run modal` isn't built yet | `Sandbox.Exec` with stdin, as the image's default user (root) | none: PER-5 is skipped. A terminate and recreate would test only a Volume, and the probe's sandbox mounts none | terminate by ID; confirmed when the sandbox polls finished and a list by its tag shows nothing running. The App and the built images stay, named as residual | docs and SDK read 10 Nov; lifecycle verified live for all six setups: each sandbox created, probed, terminated and confirmed gone by ID and tag. Terms: nothing on customers testing their own sandboxes; the security page asks bug-bounty research to use a workspace ending `-H1-<username>`; the PoC runs in the operator's own workspace, outside the bounty |
| Vercel Sandbox | built-in universal image, two CPU cores, persistent=false, timeout900000ms; no env/ports/mounts (PRV-9) | native HTTPS command stream, ordinary image user, immutable create-returned session ID, sudo=false | no reset; PER-5 skipped | stop session by ID and verify terminal, identity-guarded named record deletion and GET404; retained empty project recorded | lifecycle verified live: private upload and digest, survey, checks and cleanup; the empty project is retained as a recorded residual |
| E2B Sandbox | default base CPU template; no injected secrets or persistent storage; 900-second runtime timeout (PRV-8) | official pinned Python SDK file/command transport, explicit user; native management by returned ID | no reset or PER-5; no pause/resume | delete only create-returned immutable ID after matching run marker, then verify GET 404 | lifecycle verified live: boxes and canary cleanup verified |
| Cloudflare native Sandbox | built-in Debian image; lite instance, durable_object scheduling; image default root; Internet explicitly enabled, no app credentials (PRV-10) | authenticated dedicated Worker; native exec/stdin, inherited PATH plus twin marker; uploaded digest checked | no reset or persistent storage; PER-5 skipped | container fenced/stopped; recorded Worker/application/namespace IDs removed and independently verified | lifecycle verified live; all resources and receiver DNS removed. Declared native configuration, not a universal SDK/default or escape claim |
| Baseten Sandbox | built-in base image, CPU/default memory, no volumes or injected secrets; random name and 15-minute delete expiry (PRV-6) | filesystem upload and `/process` through its returned URL, as the image default user | no reset: suspend/resume preserves state; PER-5 skipped without a run-owned volume | by create-returned name with incarnation checks, then terminal state/404; name-operation race recorded | API inventory and lifecycle verified live (create, upload, digest, survey, delete), with deletion confirmed |
| exe.dev | one standalone 2-vCPU Ubuntu 24.04 VM, egress=all, no supplied integrations/credentials (PRV-13) | native HTTPS /exec and bounded asynchronous probe wrapper as image user | none; PER-5 skipped | original create-returned name with pinned birth/region/run tags; explicit name-addressed exception and residual race | adapter under implementation; scoped read-only access verified 17 Nov; no live baseline yet |
| self | the current box | the current user | none; unattested | nothing | |
| other | none; prints the one-liner that downloads the probe and runs it as the agent | the user's | none; unattested | nothing | |

## Cloudflare Sandboxes (PRV-10)

- Scope: an account-scoped token for an explicitly named account; only newly created Sandprobe resources, never existing Workers/apps. No provider approval is claimed. A live run is one lifecycle smoke and one graded CPU baseline, stopping on failure or a suspected provider flaw; no automatic retry. No paid-plan purchase or account-wide subdomain mutation.
- Terms reviewed 13 Nov: [Self-Serve Agreement](https://www.cloudflare.com/terms/) section 2.2.2: “You are permitted to perform benchmark tests of our Services.” Disclosure must enable reproduction. Section 2.7 prohibits abusive/malicious use. [Testing policy](https://developers.cloudflare.com/fundamentals/reference/scans-penetration/) limits testing to customer assets, forbids exploiting findings, and excludes provider destinations except its bounty scope. This run is guest permission observations and canary markers only, no network scans/exploits/host/provider-control requests; no zone penetration test. SEC-4, EGR-3, EGR-6, AMP-6, AMP-7 and PER-5 remain skipped. No secret values read.
- Deploy a fresh randomly named authenticated controller Worker with one Durable Object/container class. Use documented native Durable Object Container API and built-in `cloudflare/debian-trixie` image, `durable_object` scheduling, smallest `lite` instance, default image identity, Internet enabled for scoped canary probes. This is a declared test configuration, not a claim about every Cloudflare sandbox setup. No R2/KV/volumes/snapshots/custom DNS/images or service credentials in guest.
- Deployment script validates owner-only token and explicit account, writes mode-0600 exclusive intent before the first mutation, refuses existing name, uses pinned Wrangler only for offline bundling, then makes single native API mutations without printing provider output/credentials, records provider-created deployment/version ID, namespace IDs and container application IDs; the script name is reusable, so guarded deletion retains a check/delete race. Failed writes are never retried automatically. Cleanup refuses mismatching script identity and deletes only recorded resources; unresolved intent remains manual reconciliation, not adoption. Never delete unknown resources or broad account inventories.
- Worker exposes POST-only create/status/exec/upload/destroy routes after verifying a separate random bearer capability against its SHA-256 stored in Worker vars. Management token never enters Worker/guest or command lines. Requests are bound to one random run nonce and immutable DO ID; nonce and bearer travel over TLS. No unauthenticated exec or previews. Limits: 16MiB body, 8MiB stdout, fixed error codes only, no provider error bodies or guest stderr in diagnostics.
- Durable Object records create intent and absolute expiry before start, rejects repeated create, does not auto-start stopped boxes. Hard lifetime 15 minutes: persisted alarm destroys container and fences future use; two-minute inactivity limit is additional. Container boot ID is pinned before guest operations; changed/unavailable identity stops the run. VM/container lifecycle identity and self-observed boot ID remain distinct, explicitly recorded residuals.
- Guest exec uses direct argument arrays and stdin streams, no injected provider credential. Probe upload writes only a mktemp-created mode-0700 `/tmp/.sandprobe-...` directory, checks SHA-256 before execution. Both upload and execution require exact boot identity. Direct stdin carries probe requests; upload is constrained to the private directory. Command timeout destroys/fences the whole container instead of leaving descendants. No pause/resume/reset; PER-5 skipped.
- Every CLI run writes private intent before create; create response DO ID/boot ID pinned and journaled. Cleanup has independent context, sends destroy without starting the box, checks stopped/fenced state and retains journal on ambiguity. Controller cleanup additionally removes Worker/application/namespace resources via recorded IDs; backstop expiry is not cleanup proof. Read-only account preflight and offline plan never create resources.
- Preflight must find an existing workers.dev subdomain and usable Containers access; missing setup stops before mutations. Never purchase a plan or register/change account-wide subdomains. Native exec inherits only PATH, not the full image/start environment; reports describe this exec-mode configuration. Startup requires bounded readiness verification without repeating start/create. Controller origin is pinned HTTPS workers.dev and all redirects are refused.
- Tests: controller auth/body/identity/expiry/no-recreate/timeout and cleanup regressions, Go transport/upload/identity and approval-gate tests; deployment helper intent/identity/error-sanitization unit tests. Independent code and security reviews before live mutations. Credential scan before storing evidence.

## Sprites setup and the agent's launch path, 20 November 2026

So a person can grade their own sprite configuration, not only a default one,
and can see a fix land.

- **SPR-1 Setup.** `sandprobe run sprites -setup <file> -y` runs the person's setup script once in the new sprite, as
  the sprite's default user, through `sh -s` on its standard input, after the probe's upload and before the checkpoint,
  so the reset (TWN-3) restores the configured box. Nothing the script prints is kept or shown: a nonzero exit stops
  the run with its exit code only, and the sprite is destroyed as on any failure. The script is read before the plan
  is shown: opened without blocking, then checked on the descriptor it opened (a regular file, never a pipe or
  device, never empty) and read through a 256 KiB bound, and its SHA-256 names
  it in the plan, beside how it runs and the launcher it may leave, and in the report's box name. It runs the person's own code on a sprite Sandprobe created for the run, so it
  needs nothing beyond the run's own approval (AGT-3).
- **SPR-2 The agent's launch path.** When the setup leaves an executable `/usr/local/bin/agent-exec`, every probe call
  (survey, probe and recheck) runs through it, as `agent-exec <probe> <flags>`, the way the person's agent's commands
  run; the plan and the report say so. Only a launcher the setup made counts: one already in the new sprite before
  the setup runs stops the run there, with nothing routed through it, and a check whose call failed counts for nothing.
  Each of the setup's calls (the check, the script, the launcher check) addresses the sprite by name, so each is
  preceded by its own PRV-1 check that the name still answers with the create-returned ID. Without it, the probe runs as the sprite's
  default user, as before. The probe
  is uploaded under `/var/tmp`, so a launcher that gives the agent a private `/tmp` still finds it. Tests:
  `internal/host/sprites_test.go` (setup on standard input, the launcher found and used, the upload outside `/tmp`);
  `TestSpriteSetupRefusesAPreexistingLauncher`, `TestSpriteSetupFailureCases` (a name that changes hands before the script or the launcher check, a failed pre-check); `cmd/sandprobe/sprites_test.go` (`TestSpritesPlanNamesTheSetup`, `TestReadSetupBounds`: a file over the bound, empty,
  a FIFO, a directory or missing is refused).

## Local Docker (PRV-14)

So a demo or a CI job runs as plain `sandprobe` commands against a container on the operator's own machine. No
provider is involved, so no provider terms apply.

- **PRV-14 Local Docker.** `sandprobe run docker <image> [-as <user>] -y [-- <docker run options>]` grades a
  throwaway container. Its canary is always the local one below: `-canary`, `-canary-url` and `-canary-pin` given as
  flags are refused before anything runs, and their environment values are never read (HCN-5); to probe a container
  against another canary, `run exec` through `docker exec` takes them. Before anything is created, Docker must answer and the image must exist locally (nothing is
  pulled). The run creates, and deletes by the ID Docker returned: a bridge network on a free 172.30.N.0/24, a canary
  container on it (the canary binary carried inside sandprobe, in the debian image pinned by digest in
  test/probe.sh), and the container under test, started from the image with supported options passed through
  unchanged. Reject `--rm`/enabled `--rm=...` before creation: automatic deletion can
  bypass ownership checks on inherited anonymous volumes; Sandprobe manages teardown.
  Explicit `--rm=false` remains allowed. The probe is bind-mounted read-only at /opt/sandprobe/sandprobe-probe and runs through `docker exec -u`
  as `-as`, else the created container's own user (read from the container, so a `--user` option that overrides the
  image's is the user graded, either way round), else root. Sandprobe adds its network and points the box's resolver at the
  canary only when the options name no network; otherwise the box keeps the network it was given. The reset is
  TWN-3's recreate model, as in the fixtures: the container is removed and created again from the same image and
  options. A container that exits before the probe runs stops the run, with nothing graded. Every Docker call runs under the
  run's deadline (five minutes) and Ctrl-C, so a hung daemon or start-up still reaches the cleanup, which has its own.
  Before each tested-container create/reset, record the existing volume inventory.
  Capture the created container's mounts and mount-origin metadata; track only fresh,
  implicit local anonymous volumes (image VOLUME or source-less volume mounts), bound
  to their returned names and creation timestamps. An anonymous label alone is never
  ownership. Preserve every pre-existing, explicit-source and inherited volume.
  Remove tested containers without `rm -v`; remove only the tracked run-created volumes
  after checking their creation identity. Ambiguous inheritance, inventory/capture
  failure, replacement or unconfirmed deletion stays unknown cleanup (exit7), never
  an empty inventory or a successful teardown. Named/user-supplied volumes are never
  removed by this anonymous-volume cleanup. A create failure without a returned ID is
  explicitly unconfirmed, never evidence nothing was created. Choose the bridge
  subnet from a read-only projected network inventory and make one network-create
  attempt. A lost/failed response retains the attempted name/subnet, exits7 and
  stops without retry or name-based deletion. Cleanup checks request only IDs,
  names and creation identity, never full credential-bearing inspect JSON.
  Teardown confirms the container, those volumes, the canary and the
  network absent by ID; anything left is exit 7, named with its ID. Residual, stated
  in every report: egress is measured to a canary on a network Sandprobe created, with the box's resolver pointed at
  it, so a receipt proves the box can send data out to an address it was given, not that it reaches the internet.
  EGR-6 stays skipped (open question 2). Tests: `cmd/sandprobe/docker_test.go` (option pass-through and network
  detection; with `SANDPROBE_FIXTURES=1`, a locked-down and an open container end to end with every resource gone).
  PR40 review regressions cover pre-existing anonymous volumes mounted explicitly
  and through volumes-from, source-less fresh volumes, reset tracking, reused names,
  partial inventory failure and cleanup after a startup failure. Docker's name-addressed
  volume removal retains a check-to-delete replacement race; no host-attestation claim.

## exe.dev integration and bounded validation (PRV-13)

- Scope: an expiring tag-scoped key at a private local path. One short CPU sandbox baseline, stopping on the first completed result; no automatic create retry, no repeat probing, no production VM, exploit, escape, guest requests to provider metadata/control endpoints, secret values or LLM workload. Terms checked 17 Nov: https://exe.dev/docs/terms-of-service section 2.2 bars use "for benchmarking or competitive analysis of the Service"; a live run needs the operator's own clearance for this bounded run, never represented as provider-written permission. Read-only account/help/empty scoped-list checks run before creation.
- Transport: native Go HTTPS POST to fixed origin https://exe.dev/exec, redirects disabled, no credential in argv, guest, report, error or journal. Host credential is an owner-only regular non-symlink file, maximum 8 KiB, expiring and preferably restricted to tag sandprobe and commands help,whoami,new,ls,stat,ssh,rm. No command/body/provider error text is logged. Creation refusals may expose only fixed allowlisted hint labels (command_contract, standalone_access, billing_or_plan, name_contract, permission, image_contract, unclassified_response) inferred from bounded error/message/reason strings, never raw text or arbitrary keys. Preserve the sanitized HTTP/refusal cause before generic unconfirmed-name errors; journal only the fixed hint. CLI distinguishes requested intent from confirmed create-returned identity. JSON management replies and base64 NDJSON execution frames are bounded and must be complete; exec requires exactly one explicit zero exit_code terminal frame, no error, duplicate fields or terminal frames, trailing events or nonempty stderr. Multiple stdout/stderr chunks are valid, including equal chunks; nonempty stderr still fails. HTTP200 alone is never success. No retries on mutations or guest commands.
- Creation: exclusive private lifecycle journal written and synced BEFORE the single create POST. Standalone CPU VM, 2 vCPU/4GB, explicit ubuntu:24.04 image and egress=all, no prompt, setup script, integrations or service/model credentials supplied. Only SANDPROBE_TWIN=1 is passed. This is the Ubuntu/no-integration configuration, not a claim about default exeuntu/Shelley. Random requested name plus generic sandprobe and unique per-run tags; record the create-returned name immediately, before parsing optional metadata; persist canonical create timestamp and list region/tags atomically and sync the journal before guest execution. Never adopt a VM from a list after an ambiguous create. Existing unresolved journals block a new create. There is no provider-enforced expiry in the documented create API; a bounded local context and independent cleanup are not a crash-proof TTL. Costs can continue after a host crash until journal-based cleanup completes.
- Name-addressed identity exception: exe.dev's documented create/list/delete API exposes a VM name and created_at rather than an immutable resource ID or conditional delete. ID() returns the original create-returned name, explicitly a name, under this limited exception to PRV-1. Pin a fresh created_at, region and the two run tags from list. Account whoami.region may be empty and is not VM identity; bind the first matching created VM’s actual region only after original create-name, birth and run-tag verification, durably before execution. Cleanup may finish this binding after interruption using the confirmed create identity, never by adopting an unconfirmed name. Check this provider metadata immediately before every command/delete and both before and after read-like execution; never resume/restart or follow changed identity. A changed guest boot ID stops execution. Guard boot validation and the intended command in the SAME guest shell. These checks reduce name-reuse risk but cannot make name-based exec/delete atomic; same-account concurrent replacement and tag-visibility loss remain residual. Never represent a guest boot ID or synthesized fingerprint as an immutable provider ID. Cleanup absence is scoped API visibility, not provider-internal erasure proof.
- Runtime: detect amd64/arm64, private mktemp directory, chunked base64 upload below the 64KiB request limit with fixed generated paths and SHA-256 verification after decompression. No command text comes from API response fields. Command quoting survives both lobby and guest shells. Each /exec call is bounded below its documented 30-second limit. The probe is launched exactly once through a detached run-owned wrapper with private output/stderr/completion files and a 95-second timeout; short read-only polls retrieve only complete output after an atomic exit-status marker. Launch requires an explicit acknowledgment and is never retried after ambiguity. Polls enforce boot identity and output limits, require zero stored exit status and empty stderr, and stop on cancellation/deadline. Timeout/missing completion never becomes successful probe evidence. Stdin is a generated private file, hash-verified and removed on command exit. The only supported probe modes are survey and scoped full exec; use the common host.Execute, grading, canary health and receipt verification. SEC-4/EGR-3/AMP-6/AMP-7 are excluded; EGR-6 needs approved upload targets and PER-5 needs resettable storage, so stay skipped. No restart/pause is presented as reset evidence.
- Cleanup: run-independent bounded context even after cancellation. Validate original name/birth/region/run tags, persist a delete-attempt marker before issuing rm once (never repeat an ambiguous mutation after restart), require a successful response listing the original name as deleted, then require an authenticated scoped list to be empty for that exact name. HTTP404, forbidden responses, malformed lists, a hidden replacement, retained or unexpected delete results are not deletion proof. Retain journal and return cleanup exit7 when unresolved; successful deletion/absence retires it. A separate cleanup command can load only a valid, owner-only same-user journal and recheck original identity; it cannot adopt by guessed name. If create was ambiguous or name was never confirmed, retain intent for owner reconciliation rather than deleting by name.
- Proof before merge: independent code and security reviews of spec and code; local HTTP fixtures for real documented command shapes, strict streamed exit evidence, response caps, quoting, uploads, identity changes, crash journals and deletion; CLI plan/approval before credentials, cleanup independent of cancellation. Live validation waits for reviewed code and a healthy separately controlled receiver. Saved evidence must distinguish API success, guest observations, receiver receipts and scoped cleanup, and record failed preparations without claiming a completed baseline.

## Boat bounded baseline (PRV-11)

- Scope: the operator's own API key and one bounded guest baseline, with lifecycle/upload/survey/grade; no separate smoke, automatic create retry or repeat after failure. A live run needs the operator's informed authorization, never a claimed provider-written approval. Own fresh sandbox only, read-only account identity required; creation explicitly pins the documented personal wallet with org=personal and X-Boat-Org:personal, never the mutable active wallet.
- Terms reviewed 13 Nov: https://boat.dev/terms. TOS-10 says “You may not probe, bypass, disable, reverse engineer” its security/access controls. TOS-6 also bars “unauthorized vulnerability scanning, intrusion, exploitation, or network abuse”. TOS-3 supports testing workloads. This creates a scope/terms condition: a live run needs the operator's informed authorization, never a claimed provider waiver. No exploits, bypasses, privileged actions or provider-control requests. The scope is guest permission metadata and unique markers to our own canary only. SEC-4, EGR-3, EGR-6, AMP-6 and AMP-7 stay excluded; PER-5 skipped without run-owned resettable storage. No secret values, external scanning, provider endpoints or LLM workload. Stop and restrict evidence on a suspected provider-specific flaw (AGENTS rule 7).
- Lifecycle/transport: native fixed-origin API https://boat.dev/api/v1; small CPU VM, base environment, explicit noEnv=true / snapshots=false / monitoring=false, ttlSeconds=900 auto-archive backstop (not deletion); no model prompt, previews, snapshots, volumes, injected service credentials or resume. One create POST, return ID journaled before polling. Pin create ID and run label before any follow-up. Create and lookup timestamps can differ slightly: validate both against the request window and require a maximum one-second difference, journal the first lookup timestamp as canonical, then require it unchanged. Cleanup uses exact create-returned ID plus run label, owner access, personal wallet and fresh canonical birth even if runtime policy validation failed. Never adopt by name. The noEnv request must be accompanied by explicit holdsCreatorLogins=false and wipePendingUntilRestart=false in lookup; a retained base environment display label is not evidence of attached secrets, and is not used as no-env proof. Reject unknown or unexpected environment labels; keep provider assertions distinct from secret-value evidence. Command timeout 95 seconds, synchronous, no detached/streaming; require explicit zero exit, success, not timed out/truncated. Gzip probe for the 5MiB file API limit, upload only generated safe filenames in a random private /tmp directory. File-write size has no documented unit: require explicit success and a nonnegative declared size; record response-path equality as metadata rather than a gate because the API canonicalizes paths, but prove exact uploaded bytes with remote SHA-256 for every probe/input write rather than assuming that size equals decoded bytes. Decompress as guest and verify original probe SHA-256. Upload refusals log only fixed presence/match flags and integer sizes, never response bodies. Preserve run-owned sandbox/deletion-operation IDs in failure cleanup messages before retiring journals. Permanent delete includes X-Ascii-Confirm-Delete equal to exact sandbox ID; journal returned deletion-operation ID before polling it to completed (kind=sandbox and targetId=original ID) and verify sandbox404. Auto-stop retains snapshots and is not cleanup proof; do not create saved snapshots. Provider audit/backup retention is outside run-owned compute deletion.
- Before mutation: validate owner-only no-symlink key, explicit target scope, create-private journal directory and shipped probe. Exclusive/fsynced intent precedes single create; atomic state updates preserve previous cleanup identity. Uncertain creates remain unresolved (no name/tag adoption). All error bodies/URLs/provider messages/credentials suppressed; host requests refuse redirects, helper errors never emit raw SDK stderr. Requests/results bounded, shell paths generated and validated, no keys on arguments or guest environment.
- Cleanup runs with a separate bounded context after success/failure/interruption; preserve identity journal and exit 7 if uncertain. No other account resources may be touched. Guest boot ID is self-observed, not host/cross-tenant attestation; provider identity checks and name races remain explicit. Full report complete means selected checks accounted for; skipped checks are not passes. Credential scan and independent code/security review before live; exact-ID cleanup inventory afterwards.
- Offline tests cover key/target safety, single create and immediate-ID journaling, altered identity/boot/policy refusal, upload digest, bounded sanitized command response, interrupted cleanup, deletion proof and approval-before-credentials; SDK/wire fixtures checked against pinned primary code/docs.

## Daytona bounded baseline (PRV-12)

- Scope: the operator's own API key and one bounded guest baseline, with lifecycle/upload/survey/grade; no separate smoke, automatic create retry or repeat after failure. A live run needs the operator's informed authorization, never a claimed provider-written approval. Own fresh sandbox only. Read-only API access is checked before mutation; the API key is organization-scoped, but preflight does not return the organization identity. The create-returned organization is pinned immediately after the immutable sandbox ID; no JWT or mutable active-organization selector is used. This pre-create identity visibility limitation remains explicit.
- Terms reviewed 13 Nov: https://www.daytona.io/terms-of-service. Section 8 bars vulnerability testing without written permission. Current https://www.daytona.io/docs/en/acceptable-use/ permits targeted owned/authorized-system testing without notice but expressly defers to ToS/agreement on conflicts and distinguishes testing Daytona itself. A live run needs the operator's informed authorization, never a claimed provider waiver. The scope is guest permission metadata and unique markers to our own canary only. SEC-4, EGR-3, EGR-6, AMP-6 and AMP-7 stay excluded; PER-5 skipped without run-owned resettable storage. No secret values, external scanning, provider endpoints or LLM workload. Stop and restrict evidence on a suspected provider-specific flaw (AGENTS rule 7).
- Lifecycle/transport: official daytona==0.198.0 Python SDK in preinstalled pinned host venv; fixed API origin https://app.daytona.io/api. Generated management create call returns ID before SDK startup waits, allowing immediate host journal. Default prebuilt CPU snapshot, no GPU/custom build; user default; ephemeral autoDeleteInterval=0 / autoStopInterval=15 / autoPauseInterval=0 / public=false, empty env/secrets/volumes, no pause/resume, snapshots, volumes or public previews. Runtime is pinned to the approved US HTTPS proxy https://proxy.app.daytona.io/toolbox with exact sandbox-ID path; both generated SDK and upload HTTP clients reject all redirects and mutations are not retried. Runtime uses SDK get by exact ID after run-label/creation/policy/state checks, explicit twin env and 95-second command timeout, private random probe upload and SHA-256 check. Host pins boot identity across guest operations. Delete only original create-returned ID, verify original lookup404 or identity-bound DESTROYED/desiredState=destroyed, as the pinned SDK documents; distinguish retained terminal metadata from absent records and never treat stop as deletion. Idle stop is a cost backstop, not absolute expiry or deletion proof. SDK logging/stdout/stderr are isolated; only fixed operation/status error labels escape.
- Before mutation: validate owner-only no-symlink key, explicit target scope, create-private journal directory and shipped probe. Exclusive/fsynced intent precedes single create; atomic state updates preserve previous cleanup identity. Uncertain creates remain unresolved (no name/tag adoption). All error bodies/URLs/provider messages/credentials suppressed; host requests refuse redirects, helper errors never emit raw SDK stderr. Requests/results bounded, shell paths generated and validated, no keys on arguments or guest environment.
- Cleanup runs with a separate bounded context after success/failure/interruption; preserve identity journal and exit 7 if uncertain. No other account resources may be touched. Guest boot ID is self-observed, not host/cross-tenant attestation; provider identity checks and name races remain explicit. Full report complete means selected checks accounted for; skipped checks are not passes. Credential scan and independent code/security review before live; exact-ID cleanup inventory afterwards.
- Offline tests cover key/target safety, single create and immediate-ID journaling, altered identity/boot/policy refusal, upload digest, bounded sanitized command response, interrupted cleanup, deletion proof and approval-before-credentials; SDK/wire fixtures checked against pinned primary code/docs.

## Modal proof of concept (outside v1)

The proof of concept runs a small probe on Modal Sandboxes in the operator's own account: a default sandbox, a few
locked-down network setups, and a sidecar watching the main container's traffic, all talking only to our own test
server. It compares runs and runs something beside the box, both
outside v1 ("Not in v1"), so it lives behind a build tag and never ships.

- **POC-1 Scope.** `sandprobe poc modal ...` exists only in a binary built with `-tags poc` (`make poc`); a release
  build has no `poc` command. It runs in the operator's own workspace, named in `SANDPROBE_MODAL_WORKSPACE` (nothing
  runs without it), with the token `~/.modal.toml` already holds,
  which is never printed or logged. CPU sandboxes only, within the operator's spend cap. Every sandbox has
  POC-2's timeout as a server-side backstop. The token stays on the host: the SDK reads it from `~/.modal.toml`, and it
  never enters a sandbox's files, environment or image. SDK errors reach the terminal and every artifact only as a
  fixed category and gRPC status code, never their text, and the SDK's own logger is discarded. Output goes to a
  private local directory: each setup's OUT-1 and OUT-2
  reports, the sidecar's log and visibility matrix, and the summary (POC-8). Nothing is uploaded or shared; any summary
  goes to Modal privately, and only once the project owner approves it. One setup runs per invocation. The
  operator reads its raw record against POC-5 and clears it before rendering its reports or starting the next setup.

- **POC-2 The setups.** Each is the Modal row's sandbox with one change. The probe runs as in any other run.

  | Setup | Created with | Modal's docs say |
  |-|-|-|
  | `default` | nothing more | egress is open to any public IP |
  | `domain-empty` | `OutboundDomainAllowlist` set, with no entries (the SDK: non-nil means allowlist mode) | TLS on 443 only to listed names, matched on SNI; other traffic only to a CIDR allowlist; DNS still answers |
  | `domain-one` | `OutboundDomainAllowlist` holding one name: `<t>.canary.<our domain>`, `t` a fresh nonce | as above, so the twin (POC-3) reaches the canary while EGR-2's own name, at the same IP and port, is refused |
  | `block` | `BlockNetwork` | all outbound traffic dropped, DNS included |
  | `block-vm` | `BlockNetwork`, `Runtime: vm` | as `block`, in a VM with its own kernel; skipped and listed if the workspace can't create one |
  | `sidecar` | `proxy_traffic_via_sidecar: watch` and an empty `OutboundCIDRAllowlist` on the main container; a sidecar `watch` (POC-6) | TCP 443 from the main container is relayed through the sidecar as raw TLS; other traffic follows the main container's CIDR allowlist, so is refused; DNS still answers |

  `domain-one`'s name and EGR-2's both resolve to the canary through a wildcard `*.canary.<our domain>` record,
  created and deleted by `deploy/canary.sh` beside its other records. Modal resolves an allowlisted SNI itself, and
  the sidecar's relay has only the SNI to go on.

- **POC-3 An allowed twin for the allowlist.** In `domain-one`, after the probe and only once POC-5's gate has
  passed, the host runs the same probe again with a manifest that selects only EGR-2, with nonce `t` and the same
  endpoint, pin and route. The probe's own client then makes the identical attempt, varying only the SNI's nonce:
  `<t>.canary.<our domain>`, the one name the allowlist holds. The canary is armed for `t` on its own run (SBX-11).
  A twin receipt, beside EGR-2's refusal in the main run, shows the allowlist admitted its one name and refused
  EGR-2's at the same IP, port and route. That refusal needs TWN-1's full proof and no receipt for EGR-2's nonce.
  EGR-2's pass still needs TWN-1 as in any run; a policy error or a missing receipt alone stays unknown. Without
  the twin's receipt, the refusal stands on TWN-1 alone, and the summary says the allowlist wasn't shown to admit
  anything. The twin run is evidence only: it's never graded.

- **POC-4 What isn't tested on Modal, and why.** Every item below is listed in the summary's last section.
  - SEC-4, AMP-6, AMP-7 and EGR-3 are skipped (PRV-5): they would send requests to Modal-owned endpoints.
  - EGR-6 is skipped, as everywhere.
  - PER-5 is skipped: see the Modal row.
  - AMP-4 still runs. It does `lstat` and access checks and never connects. A Modal socket it finds is reported,
    never used.
  - Fronting through a shared CDN isn't tested: it needs a third party's server. `domain-one` covers only how the
    allowlist matches.
  - Inbound through unencrypted tunnels isn't tested: it would open ports to the internet.
  - GPU sandboxes, the Datadog integration and the Outbound Policy aren't tested.
  - The PoC sends nothing that tries to escape the box or reach other tenants, and puts no load on anything.

- **POC-5 Stop and report.** This rule applies when a result suggests a real flaw on Modal's side, not a documented
  trade-off. The cases are:
  - The box sees or reaches another sandbox's or customer's data, processes or network.
  - A documented control doesn't hold beyond the DNS and fronting cases Modal documents.
  - Modal's own credentials are readable in the box.
  - There are signs of host access: writable host paths, or the host's processes or devices.
  - The main container sees the sidecar's processes, or the sidecar sees the main container's processes or files.

  A gate runs after every step that could reveal one, and the next step runs only once it passes: after the probe
  returns, after the twin, and after each `look` row. It checks the canary's counts for this setup's own nonces, the
  run's check nonces and the twin's. The canary keeps no others, and host health is never a receipt. Its rules:
  - `block` and `block-vm`: any count, for any nonce, on any protocol or port.
  - `domain-empty`: any TCP count, on the nonce's own port or elsewhere.
  - `domain-one`: any TCP count for a nonce other than the twin's, or the twin's nonce counted anywhere but TCP 443.
  - `sidecar`: a TCP count on 22, 80 or 8080, or any nonce counted elsewhere on TCP. Then, once the relay's log is
    read in full (POC-6), a TCP 443 count for a nonce the complete log shows no relay of. A log that's missing,
    unreadable or truncated isn't a bypass. It leaves the sidecar's attribution unknown, and the setup ends there,
    before `look`.

  DNS counts under an allowlist are Modal's documented behaviour and pass the gate. That means EGR-1, and EGR-5 on
  UDP 53, each on its own port. `look` stops itself at its first unexpected sighting (POC-6). A secret-shaped name
  whose source POC-7 can't establish holds the setup for the operator.

  When the gate trips:
  - The next step doesn't run.
  - The sandbox is deleted as usual, with its cleanup receipt.
  - No OUT-1, OUT-2, matrix or summary input is generated for that setup.
  - What's kept is a private incident note: the setup, the gate's rule, timestamps, and the counts per nonce of our
    own. Nothing else is kept.
  - The PoC exits 8, and the operator tells the project owner.
  - Nothing is re-run, repeated or widened to confirm it.

  The project owner decides on reporting it privately to Modal. A setup that passes every gate keeps only our own raw
  record, in `raw/<setup>/`: the probe's document, the canary's counts, the relay's log, `look`'s rows, and
  timestamps. The operator reads that against the cases above. OUT-1, OUT-2 and the matrix are rendered from it only
  after that clearance (`sandprobe poc modal render`). On a case, no report is ever rendered, and the raw record is
  kept only as the incident's own logs. The create request each setup sends is unit-tested against its table row,
  so a misconfigured setup can't pass for a failing control.

- **POC-6 The sidecar observer.** The sidecar is a Sandprobe image: `alpine:3.21`, built in our App before the
  sandbox (sidecar images must be prebuilt). After the sidecar starts, the SDK's filesystem API copies in
  `sandprobe-aux`, a PoC-only binary. It's written under a temporary name and then renamed, and the sidecar's
  entrypoint waits for the final name before running `relay`. The sidecar's own CIDR allowlist holds only the
  canary's /32. DNS through Modal's resolver stays open to it, as Modal documents, so its only non-DNS egress is to
  the canary.

  `relay` works like this:
  - It listens on TCP 443, and writes `ready` once it does. The host waits for that, through the sidecar's exec,
    before the probe runs; with no `ready`, the setup ends unknown.
  - It reads a ClientHello, up to 16 KiB and 5 s, and accepts only an SNI whose first label is nonce-shaped under
    `canary.<our domain>`.
  - It connects only to the canary's pinned IP on 443, never resolving a name. It replays the ClientHello and
    splices both ways, never terminating TLS, so the canary's pin still holds.
  - Every other connection is closed. Its log line says only that one was refused, and the ClientHello's length,
    never its SNI.
  - It writes a line when it accepts a connection (time, nonce) and one when it ends (bytes each way, outcome).
    Each line is synced to the sidecar's own disk before the next. No payload is ever recorded.

  After the probe's receipt wait, the host reads the whole log through the sidecar's exec. A TCP 443 receipt is
  attributed to the sidecar only when the log holds that nonce's accept and end lines, with bytes both ways and the
  outcome `relayed`. A log that's missing, unreadable or lacks the end line leaves attribution unknown. A 443
  receipt with no relay of its nonce, in a complete log, is a bypass and trips POC-5's gate. DNS receipts are reported
  apart, since the sidecar never handles DNS.

  Then `sandprobe-aux look` runs in each direction, by exec. The main container's command keeps a fresh marker in its
  own arguments, writes it to `/tmp`, `/root` and a shared ephemeral Volume, and answers it on TCP 7070. The sidecar's
  command keeps a second marker in its arguments. `look` checks its rows in order, and stops at the first unexpected
  sighting, so nothing after it runs.

  | From the sidecar | How | Expected, from Modal's docs |
  |-|-|-|
  | main's processes | its own `/proc/*/cmdline`, for main's marker | not seen: separate gVisor or VM boundary |
  | main's files | `lstat` of the exact paths main wrote | not seen: mounts are per container |
  | a shared Volume | read the marker file, before and after `ReloadVolumes` | seen, perhaps only after a reload |
  | main's network | TCP connect to `main:7070`, one line read | seen: every port on main is reachable |
  | main's HTTPS | the relay log against the canary's TCP 443 receipts | each relayed attempt, by SNI only |
  | main's DNS | EGR-1's receipt; the relay never sees it | not seen |

  | From the main container | How | Expected |
  |-|-|-|
  | the sidecar's processes | its own `/proc/*/cmdline`, for the sidecar's marker | not seen |
  | the sidecar's relay | the probe's EGR-2, which Modal routes there | reached; that's the design |

  Main's stdout and stderr aren't looked for on their own. Modal gives a sidecar no streams, and the only path to
  them would run through main's processes, which the first row tests and which must not be seen. Each side reads
  only its own `/proc` and filesystem, the shared Volume, and the one port main opened.

- **POC-7 Buckets.** Each finding on Modal falls in one bucket, A to D, or is listed as by design, by a table reviewed
  here, never by judgment when the summary is built. By design is never counted as a gap.
  - **A, documented, with a Modal control:** Modal's docs name the exposure, and a Modal setting closes it.
  - **B, a default you can change:** the exposure comes from a default the customer brings or leaves, such as the
    image's user or files, and is fixed in the customer's own image or code.
  - **C, a gap with no control today:** no Modal setting closes it short of blocking all network.
  - **D, only Modal can tell:** it can't be judged from inside one sandbox.

  | Finding | Setups | Bucket | What closes it | Modal's words |
  |-|-|-|-|-|
  | EGR-1, EGR-2, EGR-5 | `default` | A | `block_network`; the domain and CIDR allowlists for all but DNS | "By default, Sandboxes can make outbound connections to any public IP address." |
  | EGR-1; EGR-5 on UDP 53 | any allowlist, `sidecar` | C | only `block_network` | "DNS traffic is allowed without restriction except when all outbound traffic is blocked." |
  | EGR-2 through the sidecar | `sidecar` | A | the sidecar's own allowlists, which Modal documents | "Each Sidecar has its own outbound network policy, independent of the main container's and open by default." |
  | AMP-2: uid 0, or root's capabilities | all | B | a non-root `USER` in the image | none: the image's default |
  | AMP-3: `NoNewPrivs` 0 with setuid-root files | all | B | an image with no setuid-root files | none |
  | PER-1 to PER-4: startup, PATH, schedule and access files the agent can replace | all | B | a non-root user that owns neither its home nor the PATH, schedule and startup directories, in the image | none |
  | SEC-2, SEC-5: other processes' environment and memory, when every PID the finding opened has a name in the raw record (`/proc/<pid>/comm`, names only, listed after the probe): PID 1 Modal's init `dumb-init`, every other one the setup's own command (`sleep`, `sh`, `python3`). A PID with no recorded name, or any other name, isn't placed | all on gVisor | B | the agent under a UID of its own, apart from every other process in the box | none |
  | SEC-3: the image's own `/etc/shadow`, readable as root; any other credential file holds the setup under POC-5 | all | B | a non-root `USER` in the image | none: the image's default |
  | SEC-1: a secret-shaped name the image declares, or the host set | all | B | the customer's own image and environment | none |
  | SEC-2, SEC-5 in the VM: no row; a finding there stops the summary until a reviewed change adds one | `block-vm` | none | none | none |
  | AMP-8 in the VM, only for these surfaces: `/proc/sys/kernel/core_pattern`, `/proc/sys/kernel/sysrq`, `/proc/sys/net/ipv4/ip_forward`, and the guest's `vda`, `loop`, `ram`, `zram` and `nullb` devices. Any other path isn't placed | `block-vm` | by design: listed, never counted as a gap | nothing needed: it's the sandbox's own kernel | "the Sandbox runs in its own virtual machine with its own Linux kernel." |
  | AMP-8 on gVisor: a setting of gVisor's own kernel writable as root | every setup but `block-vm` | D | Modal's to say: what that setting reaches | none |
  | AMP-4: a Modal control socket found, never connected | all | D | Modal's to say: who may use it | none |

  SEC-1 reports names only, so a name's source comes from two lists made before the run: the names the host sets
  (none), and the names the image's config declares (`docker image inspect`, names only). Any other secret-shaped
  name holds the setup for the operator (POC-5). The summary won't build until a reviewed change here classifies it.

  Bucket D also holds these, untested: separation between tenants on a shared host, the host's kernel and runtime
  patching, and GPU memory reuse. A finding this table doesn't cover stops the summary until a reviewed change here
  covers it.

- **POC-8 The one-page summary.** `sandprobe poc modal summary` builds `summary.html` and `summary.md` from the
  setups' reports, the twin's receipt and the sidecar's matrix. The HTML follows OUT-2's rules: self-contained, under
  its CSP. Its sections, in order:
  1. One row per setup tested, with its bucket counts.
  2. The findings by bucket, one line each: what we saw, which setups it applies to, and the Modal control that
     closes it, linked to the doc that says so.
  3. The gaps that apply: bucket C, plus any B a careful customer would still hit.
  4. What the sidecar saw and what it couldn't.
  5. What wasn't tested, and why (POC-4).

  Letter grades stay in each setup's own report. The wording is plain and factual, and it credits Modal's docs
  wherever they already describe what we saw.

- **POC-9 Cleanup receipt.** Each setup's report carries the receipt:
  - every sandbox, by ID, terminated, polled finished, and absent from a running list by its tag;
  - the sidecar, terminated with it;
  - the ephemeral Volume, closed;
  - the twin's and the run's canary nonces, disarmed.

  The App and the two built images stay between setups and are listed as residual. `sandprobe poc modal cleanup`
  deletes the images by ID at the end, and leaves the empty App, which `modal app stop sandprobe` removes. Spend is
  estimated, not measured. Every setup keeps Modal's default size, a 0.125-core and 128 MiB request that may burst.
  The estimate is each sandbox's lifetime, from its create call to the end of its teardown (to its 15-minute timeout
  if it wasn't confirmed deleted), at that request and Modal's published non-preemptible sandbox rates
  (modal.com/pricing, read 10 Nov: $0.00003942 per core-second and $0.00000667 per GiB-second). It claims no
  direction: the lifetime counts create and teardown time Modal may not bill, and bursting bills more. The summary
  says so, and points to the workspace's usage page for the real figure. Image builds aren't included.

## Releases, 21 November 2026

- **REL-1 A reproducible build.** `make release` builds the four `sandprobe` binaries a release ships (macOS and
  Linux, arm64 and amd64) from one commit: cgo off, `-trimpath`, `-buildvcs=false` and `-ldflags "-s -w"`. They embed
  the Linux probes and canary as `make probes` builds them: cgo off, `-trimpath` and `-buildvcs=false` (deterministic,
  not stripped), with the probe's `BuildVersion` set to the CLI's `Version`. Each binary is compressed with `gzip -9 -n`. `SHA256SUMS` lists the `.gz` files, which
  the installer checks, and `SHA256SUMS-binaries` lists the uncompressed binaries, so anyone with the same Go version
  can rebuild and compare without depending on their gzip.
- **REL-2 Two builds, one release.** The release workflow runs REL-1 twice, on separate runners from separate clean
  checkouts of the same commit, and publishes only if every file matches byte for byte and both checksum files
  match the files they list (the binaries' after decompressing every archive). It does the same on every pull
  request, publishing nothing. A release publishes the CLI's own `Version` as the tag `v<Version>`, from `main`, and
  stops if the version asked for, the CLI's `version` output and the probe's `BuildVersion` don't all agree.
- **REL-3 Provenance.** Each published `.gz`, and both checksum files, carry a GitHub build attestation for the
  workflow run that built them. Verifying one binds it to this repository's release workflow, on `main`, at the
  release's commit:
  `gh attestation verify <file> --repo summationai/sandprobe --signer-workflow
  summationai/sandprobe/.github/workflows/release.yml --source-ref refs/heads/main --source-digest <release commit>
  --deny-self-hosted-runners`. The repository alone (`--repo`) is only the minimum identity check, and a
  `SHA256SUMS` fetched beside a file proves transport integrity, not authenticity, unless the checksum file's own
  attestation is verified the same way. The release notes give the exact command with the commit filled in. The
  release workflow creates the tag `v<Version>`. The repository refuses any other new tag; a version-shaped tag can
  be made by anyone with write access, so a release is authentic only when its files verify as above, never because
  its tag exists. CI parses every workflow, `.yml` and `.yaml`, and fails unless the release workflow's publish job
  is the only place that grants `contents: write` or `write-all`; the repository's default workflow permission stays
  read.

## Tests

Every test here runs on public data. Tests that need a saved report use `demo/reports` and `test/reports`, which
are runs of local Docker boxes against the local canary (`test/reports/README.md` rebuilds them). Replays of recorded
provider runs stay with the operators' records (AGENTS rule 9), not in this repository.

| Extension rule | Tests |
| --- | --- |
| REL-1 to REL-3 | `.github/workflows/release.yml` on every pull request: REL-1 twice on separate runners, compared file by file, publishing nothing; on a release, the version check before anything is published, then the attestation |
| QCK-1/QCK-2 | Linux quick metadata/no-follow FIFO/symlink tests, status/error/name bounds tests, static amd64/arm64 packaging checksums |
| SCR-5 | synthetic six-category coverage partition and malformed/missing/unknown/scoped-out cases, unchanged RC scores, invalid/historical coverage absence, terminal/HTML/workload coverage visibility and count validation |
| SCR-1/SCR-2/SCR-3 | `internal/report/scorecard_test.go`: every catalog check in exactly one category, green only with a tested check and no unknown or finding above Info, invalid has no score, the page leads with the score and puts the rest under Appendix, reasons never carry box strings; `cmd/sandprobe` scorecard regression |
| SCR-2 (not applicable) | `internal/report/scorecard_na_test.go`, on a Docker fixture run replanned through `host.Plan`, the grader and `Build`: `TestScoreNotApplicable` (each native adapter's PRV-row exclusions make Cloud access not applicable with SCR-2's fixed reason, never green, out of five, named on one line with this binary's own PRV reasons, in JSON and on the page, which carries no saved-report note; the letter equals the same run's without a kind), `TestNativesAreThePolicy` (the providers treated as provider terms are exactly `host.TermsExclusions`; exec and the shipped recipe derive opt-in; docker and aws-nitro nothing), `TestScoreOptInStaysNotTested` (run exec's and a recipe's defaults: red, out of six, "Not tested: opt in with -provider-endpoints SEC-4,AMP-7 if your provider's terms allow"), `TestScoreNoCanaryIsNeverNotApplicable` (Exfiltration "not tested: run without a canary", red, incomplete), `TestNotApplicableNeedsTheHostsKind` (no kind, a row the manifest never skipped, an empty reason, one check tested, unknown or missing, or a provider-terms kind on run exec, whose policy is opt-in: never not applicable; the box answering "skipped", or answering a check the host skipped, invalidates the run), `TestWorkloadExposureNotApplicable` (a forged out-of-six, green, extra, unknown or dropped not-applicable row, or provider-terms reasons on a counted row, is refused), `TestCleanBoxReadsFiveOfFive` (a clean box reads 5/5 in the card, its JSON and the page, never 6/6, Cloud access never green); `TestSixOfSixIsAnA` (every saved Docker report stays out of six with nothing left out, and a full score is a complete A); `internal/host`: `TestPlanRecordsSkipKinds` (a kind only for the host's own exclusions, never a survey-driven skip, never in the probe's input; the grader refuses a kind on a check that isn't skipped or isn't an endpoint, or that isn't a kind; Execute refuses an unknown kind); `cmd/sandprobe/scorecard_na_test.go`: `TestExclusionKinds` (every adapter's exclusions record a kind: opt-in for run exec and recipes, provider terms for the rest), `TestScorecardNotApplicable` (Sprites and E2B read "Score 2/5" with the line; exec and kubernetes "Score 2/6" with the opt-in hint; the same in `-o json`), `TestReportSchemaVersions` (AGT-6: a report with skip kinds declares `sandprobe/2`, one without stays `sandprobe/1`; a `sandprobe/1` report carrying skip kinds, a `sandprobe/2` one without them, and an unknown version are refused, and the refusal names the versions this build reads), `TestScorecardNoCanaryStaysRed` (exit 5, red), `TestCompareNotApplicable` (tested to not applicable is coverage loss and a changed setup; opt-in to not applicable is a changed setup, exit 5; a matched pair, and a report with no kind against an opt-in one, read unchanged), `TestScorecardRefusesForgedKinds` (ANL-1), `TestScorecardRefusesForgedProvenance` (the security review's forgery: a valid run exec report with SEC-4 and AMP-7 edited from opt_in to provider_terms is refused, and scored directly stays out of six), `TestOfflineRenderingsSayNotReVerified` (ANL-1: scorecard text, JSON and the `-out` page, profile, assess and compare each say the saved report wasn't re-verified) |
| HCN-1 | `internal/canarycontrol`: the whole public path over HTTPS, every answer verified under the pinned control key and naming the canary's receipt address and domain (`TestPublicAnswersNameTheReceiptAddress`); an answer replayed for another challenge, altered, re-signed or under an unpinned key is refused; the control name never gets the receipt key and a box name never reaches the control server; method, path, unknown field, op mismatch, trailing data and oversize refusals; a long run label never makes an answer over the bound (`TestPublicAnswerBoundedForLongRun`, `TestControlAnswerBounded`); a control key file that's a symlink, not regular, open to others, not this user's, oversize or carrying trailing bytes is refused (`TestLoadKeyFileSafety`); a browser's cross-site POST (simple content type, Origin or Sec-Fetch-Site) is refused (`TestControlRefusesBrowserPosts`); `TestPublicNeedsAChallenge`; host: `TestHTTPSCanaryImpostor` (an impostor behind a trusted interception root and a redirected name is never believed, and Execute stops before the probe), `TestHTTPSCanaryRefusesRedirectAndOversize`, `TestNewHTTPSCanaryChecks`, `TestHTTPSCanaryAddressFromSignedStatus` (the receipt address comes from the signed status, never from where the control connection went, and a changed one is refused), `TestHTTPSCanaryErrorsRedact` |
| HCN-2 | `TestPublicSecretGuardsTheRun`: without the secret a box can't query, disarm, re-arm its run or arm its nonce elsewhere, and the host's receipt survives; `TestPublicCantTouchOperatorRuns`; `TestPublicGenerationChangesOnRearm`; host: `TestHTTPSCanaryRearmedRun` (a re-armed run is never read: the old secret is refused, and the thief's secret shows another generation) |
| HCN-3 | `TestPublicReservation` (no arm without a reservation; one slot per secret; release; expiry), `TestPublicBounds` (per-source runs at once and per hour, by reservation), `TestPublicGlobalBound`, `TestSourceOf` (IPv6 /64), `TestPublicOverloadAtACap`; host: `TestHTTPSCanaryRun` (no arm without a reservation; reserve, arm, receipt, disarm) ; `TestHTTPSCanaryLostAnswersRelease` (a reserve, arm or disarm lost before or after the canary acted never leaves a slot held past Close), `TestHTTPSCanaryCloseRetries` (a Close that couldn't release keeps the slots for the next one) |
| HCN-5 (no canary) | `internal/host`: `TestPlanNoCanary` (the canary checks stay selected for the grader, but the probe's input names none of them and carries no canary address, nonce or domain), `TestExecuteNoCanaryAsksNothing` (no canary is asked anything and no receipt is awaited), `TestExecuteThroughExecBoxNoCanary` (the shipped probe through `docker exec`: valid, incomplete, every canary check unknown with the host's reason, EGR-3 still skipped as a provider endpoint); `internal/grade`: `TestNoCanaryIsUnknownNeverAnswered` (each canary check unknown with the host's reason, and a box that answers one anyway makes the run invalid); `internal/report`: `TestScoreNoCanary` (the category reads "not tested: run without a canary" and stays red); `cmd/sandprobe`: `TestNoCanaryFlag` (the plan says none, and `-no-canary` with any canary flag, or outside exec, is refused) |
| HCN-5 (which canary) | `cmd/sandprobe/canary_test.go`, all offline or on a local stand-in: `TestCanaryPrecedence` (`-canary`, by flag or `SANDPROBE_CANARY`, over `-canary-url` with its pin, over the hosted canary; a stray `canary-*.state` file is chosen only when named; a pin without its URL is refused), `TestStrayCanaryStateIsIgnored` (with one stray state file and nothing named, the plans of `run exec` and of every native adapter, and `providers`, name the hosted canary, who runs it and HCN-4's retention, never the stray file, its address or SSM; named, the same file is the operator canary; a named file that doesn't load isn't ready), `TestNativeRunOnTheHostedCanary` (the seam every native adapter shares: the hosted canary, here a real canary on a local port with its own pin, gives its signed status and holds the run's slot before any box; `Execute` through it is live with its receipts read; `closeCanary` leaves no slot held; a named operator canary that doesn't load stops the run), `TestCanaryFlagsBeatTheEnvironment` (a stale `SANDPROBE_CANARY` beside an explicit `-canary-url` and `-canary-pin`: `plan e2b` names the URL; any canary flag sets every `SANDPROBE_CANARY*` value aside, so an explicit URL never takes the environment's pin and `-no-canary` isn't refused for the environment's canary; with no flag, the environment stands in), `TestDockerRefusesCanaryFlags` (PRV-14: `plan` and `run docker` refuse each canary flag before any Docker call, and never read the environment's canary), `TestExecReleasesTheSlotAfterACancelledCleanup` (run exec's teardown gives the hosted canary's slot back under its own budget after a scratch cleanup that used all of its own), `TestPublicCanaryPlansDiscloseRetention` (on the hosted canary and on one `-canary-url` names, the plans of run exec, the Kubernetes recipe and all nine native adapters end their residual with the one shared HCN-4 sentence, which names both addresses, the box's for at most 30 minutes and the host's in a rate counter for at most an hour, in memory only; on an operator canary every residual is its own alone, and run docker's plan is unchanged); `internal/host`: `TestPublicCanaryThroughAReset` (PER-5's restore model on a real public canary: status, arm, probe, query and disarm, in that order, all before the mark, the reset and the recheck, which ask the canary nothing; one reserved slot covers the run, and Close leaves none held) |
| RCP-1/RCP-2 | `internal/host/recipe_test.go`: `TestParseRecipe` (the header's keys, the functions, exclusions only from the provider endpoints, `env:` only its own `SANDPROBE_` names, the 64 KiB bound, and the shipped recipe), `TestRecipeLifecycle` (each call gets the host's box, name and target and never the process's own, stdin from `/dev/null`, `sp_shell` carries PRV-15's script), `TestRecipeCreateWithoutID` (empty, two lines, bad characters, too long or failed: the name is reported and nothing deleted; an ID with a failed create is still deleted by it), `TestRecipeGone` (only 0 is gone; 1, 2 or anything else names the ID), `TestRecipeWhoisGuards` (no invocation and no delete once the name holds another box; the residual reports the race), `TestRecipeErrorsWithhold` (an error carries what the recipe wrote to fd 3, and never its stderr, even a line posing as the recipe's), `TestRecipeMessagesCantBeReopened` (a tool with fd 3 closed finds no message file to reopen by name, and none is left); `internal/host/exec_docker_test.go`: `TestRecipeThroughDocker` (`SANDPROBE_FIXTURES=1`: an ID-addressed recipe runs the shipped probe through its `sp_shell` and deletes its container by ID, confirmed gone) |
| PRV-16 | `internal/host/recipe_kube_test.go` with a stub `kubectl`: `TestKubernetesRecipeCalls` (every call names the context, and the namespace where it reaches the cluster; no apply; the overrides are read from their file and never appear on a command line; `get pods` is checked; the delete is the raw API call with the UID precondition and its grace), `TestKubernetesRecipeRefuses` (no context, a bad or capitalised namespace, an unreadable overrides file, a refused permission, an API server URL with a user, query or fragment part (refused without printing it) or that isn't a URL, a proxy's path (shown only as the origin), a changed API server, path or cluster settings, a stub kubectl that writes a message as the recipe on stderr and on fd 3 (never shown), and overrides that make anything but the pod or move it to another namespace), `TestKubernetesRecipeGone` (absent or another UID 0, ours 1, kubectl failing or no target 2), `TestKubernetesRecipeChildrenCantSpeak` (every kubectl in the recipe runs with fd 3 closed); `cmd/sandprobe/recipe_test.go`: `TestRecipePlan` (the plan names the target, the ID-only delete, the whois guard, the exclusions and the skipped PER-5; an unapproved run creates nothing; no context is a login error; passthrough, a canary flag with `-no-canary`, and a bad `-as` are refused), `TestRecipeRunCleanupExits` (a create with no ID exits 7 naming the box, deletes nothing and keeps its record; an ID whose box never became ready exits 7 naming it, after a delete asked though the run had used more than the delete's whole budget, and the record keeps the ID), `TestRecipeRunStopsWithoutRecord` (an ID that can't be written to the record stops the run before anything runs in the box, which is deleted), `TestKubernetesRecipeLive` (with `SANDPROBE_KIND_KUBECONFIG` and a `kind-` context only: a real run without a canary, incomplete, its pod confirmed gone and no pod or record left; `-as nobody` on the default root pod stops before any check, and the pod is deleted) |
| HCN-7 | `deploy/canary_test.sh`: the operator canary's service unchanged (the non-public user data was checked byte for byte against main's), the hosted canary's signed control for its own address, its control key made once in its own state directory, its wait for its address, staging only on request, its own domain, state file and namespace, `publicstart` taking only an address before any AWS call, and `publiccheck` running under `set -u` on macOS's bash 3.2 with and without staging (an empty argument array once stopped a production deploy's final check); `TestCanaryCheckRefusals` (no URL or pin, `-tls-insecure` outside `canary check`, an unproven canary) |
| ANL-1/ANL-2/CMP-1 | `internal/analysis` saved-report corpus, contradictions, descriptor refusal and comparison tests; `cmd/sandprobe` offline CLI regressions |
| JON-1/JON-2 | `internal/strictjson` framing/bounds/fuzz; `cmd/sandprobe-probe` input and argument regressions; offline Linux CI |


Boat PRV-11: `internal/host/boat_test.go` checks single create, explicit no-env/snapshot/monitoring/personal-wallet policy, immediate ID journaling including malformed optional fields, identity and command truncation rejection, and target-bound permanent deletion. `cmd/sandprobe/boat_test.go` checks approval before credentials.

Daytona PRV-12: `internal/host/daytona_test.go` checks single create, immediate ID journaling, ambiguous create refusal and original-ID terminal cleanup. `cmd/sandprobe/daytona_test.go` checks approval before credentials. `make test-daytona-sdk` checks pinned generated models, creation policies, fixed URL scope, redirect/retry rejection and offline SDK version checks; install the lock with --require-hashes --only-binary=:all:.

Cloudflare PRV-10: `internal/host/cloudflare_test.go` covers capability-file/origin safety, intent-before-create, no retry, prior-run refusal, explicit response evidence, upload/survey lifecycle and cleanup. `cmd/sandprobe/cloudflare_test.go` checks approval before credentials and honest no-intent cleanup. `node --test deploy/cloudflare/controller.test.mjs` checks authentication, single create, identity/expiry fencing, body bounds and timeout/bootstrap failure. `python3 -m unittest discover -s deploy/cloudflare -p manage_test.py` checks preflight, safe key files, exclusive/atomic journals, identity-change refusal and staged cleanup recovery.

PRV-9 project setup: `python3 -m unittest discover -s deploy -p vercel_project_test.py` checks token validation before intent, exclusive intent before POST, immediate ID journal before GET, ambiguous-create retention and refusal to issue a second create.

Vercel PRV-9: `internal/host/vercel_test.go` verifies token-file safety, team/project binding, create-returned directory persistence/pinning and cross-base upload refusal, exact SDK origin/prefix, fixed-label bounded diagnostics, create ambiguity and
identity journaling before optional parsing, replacement/persistence/timeout checks, gzip/tar upload integrity,
stream output limits and terminal-event validation, redirect/error sanitation, immutable-session cleanup and
GET404 record deletion. `cmd/sandprobe/vercel_test.go` covers offline planning, approval-before-credentials and
cleanup using an independent bounded context. Provider wire fixtures follow official SDK3.9.1 contract shapes.

E2B PRV-8: `internal/host/e2b_test.go` covers credential-file ownership, FIFO and symlink rejection, create-ID
journaling before optional-field parsing, expiry, identity checks, redirect/error sanitization, upload integrity,
SDK isolation, bounded output and deletion confirmation. `cmd/sandprobe/e2b_test.go` covers offline planning,
approval-before-credentials and independent bounded cleanup. `internal/host/e2b_runtime_test.py` covers the pinned
SDK constructor, ID/port/token binding, explicit user and twin marker, and streaming stdout/stderr limits.
Validate the dependency lock by installing into a fresh venv with `--require-hashes --only-binary=:all:` and running
`make test-e2b-sdk`. The opt-in live lifecycle test and baseline need the operator's authorization (PRV-8).

Baseten PRV-6/PRV-7: `internal/host/baseten_test.go` covers credential handling, token exchange, URL/redirect validation,
create ambiguity and expiry, incarnation replacement, terminal execution, upload, persistent lifecycle state and
verified cleanup. `cmd/sandprobe/baseten_test.go` covers bounded scope, CLI planning and approval, and cleanup exit precedence. PRV-7 cases also cover retained/failed/interrupted lifecycle, server expiry policy,
private journal recovery, cleanup approval and grade/report semantics.

Every rule has a test. Fixture boxes run in local Docker (Docker Desktop is on this Mac), each built from a Dockerfile
under `test/fixtures/`, beside a local canary container that plays SBX-11. A fixture's "reset" is defined per case.
`test/fixtures.sh` builds the images and runs each fixture through the whole host path: the survey, the plan, health
on the canary's published ports, the probe through `docker exec` as the fixture's agent user (the probe bind-mounted
read-only), the receipt query through `docker exec` into the canary, and the grade. A stub (`test/fixtures/stub`)
plants instance metadata at 169.254.169.254, on its own link-local network, with one role whose credential document
must never be asked for, and a TLS endpoint standing in for the Kubernetes API; its request log is checked. The
fixtures' Docker box is reset by recreation (TWN-3's recreate model): removed, then created again from the same
arguments with the volumes Sandprobe created for it, each identified by its name and creation time, so a volume made
again under the same name is another volume. Teardown deletes the box by its container ID and a volume only while its
name still names the volume created for the run, and reports either gone only on Docker's definitive "no such"
answer. Docker deletes volumes by name alone, so a volume made again under the name between that check and the
deletion could still be removed: a limit of this local fixture adapter only, since real providers' adapters delete
by immutable ID.
Fake secrets hold only `sandprobe-fake` and nothing secret is ever planted.

| Fixture | Planted | Must report |
|-|-|-|
| `clean` | non-root user, no capabilities, `NoNewPrivs`, read-only root, no network | A only once every two-sided check is exercised or `scoped_out` with a reason, with its find-only checks listed as not proven; never because a path, tool or service is missing |
| `holes` | sudo `NOPASSWD`; fake credential files (one empty), one behind a relative symlink and one behind a Kubernetes-style token symlink chain; `FAKE_API_TOKEN`; a root stub socket at `/var/run/docker.sock`, mode 0666; a metadata stub with a role; open egress to the canary; writable `/etc/profile.d`; a root-owned 0444 `~/.bashrc` in an agent-writable home; a persistent volume | F; each hole found by its check (PER-1 by replacement; the empty file an Info indicator); CHN-1 confirmed from the non-empty file, potential from `FAKE_API_TOKEN` |
| `deceptive` | a box `curl` shim that opens a fake secret, and a curl config that adds an unplanned destination; a box `curl` that is a symlink to a short fake secret; a sudo shim in an agent-writable PATH directory that writes a sentinel; a sentinel-writing shim at `/usr/local/bin/sudo` with `/usr/local/bin` agent-writable; `/usr/bin/sudo` replaced by a symlink to a shim; a root-owned mode 4777 sudo in a safe directory; a root-owned sudo shim earlier in PATH that prints the password prompt while the real sudo is `NOPASSWD`; `LD_PRELOAD` and `/etc/ld.so.preload` libraries that fail `connect`; a proxy that answers 403 while direct egress is open; a proxy URL holding credentials; a TLS interceptor with its own key; a resolver that lies about the canary | no affected check passes; the box's `curl` never runs (process accounting shows it); the fake secret behind the `curl` symlink is never opened or hashed (an access watch shows it); no sudo shim's sentinel is ever written, and AMP-1 is unknown where no sudo qualifies; the proxy credentials appear in no argument, canary traffic, log or report; EGR-2 never passes through the interceptor; never A or B |
| `network` | the canary refusing connections while egress is open; the canary failing only during one attempt; a wrong SNI on an open network; a name server that logs the query and returns NXDOMAIN; a resolver that answers our name locally while other queries leave; egress open on one port only; a fault-injection build of the probe that skips `connect` and reports a refusal; another that prebinds a local port, skips `connect` and returns a refusal-shaped error; others that return an immediate `ECONNREFUSED`, `EHOSTUNREACH` or `EPERM` without calling `connect`, the last beside an unrelated active seccomp filter | any refusal without TWN-1's full proof is unknown, never a pass; the logged query is a finding by receipt; the local answer is `not_found`, never a pass; each port is scoped to itself |
| `policy` | sudo `NOPASSWD` for one command other than `true`, with `listpw=always`; the same with listing behind a password; a policy allowing `true` with a box-controlled `true` early in sudo's path that writes a sentinel | AMP-1 a finding or `not_found`, never a pass; the sentinel is never written, because sudo never runs a command |
| `reset` | a name reused by a replacement with a different volume; a reboot without restore; a restore that fails; a persistent volume remounted at another path or subpath; a cleaner that deletes only the marker while another file survives; a root that refuses its marker beside one that takes it; the same directory reached as home and as a mount; the marker replaced after the reset by an unrelated regular file holding the run id; a marker name swapped while the run ends; a recreate whose box is deleted while its volume, and the marker on it, stay | PER-5 never a finding without TWN-3, never a pass; the cleaner case `not_found`, with other data listed as not proven; a refusing or changed root unknown, never `not_found`; one marker per directory; the substitute never read and unknown; no file ever removed by name, every marker listed as a cleanup item when its box or volume isn't confirmed deleted; the surviving volume's marker never reported cleaned up |
| `effects` | a symlink at a marker path; a missing storage root; a FIFO at a credential path; a credential file swapped for a FIFO between the probe's checks (a race harness); a dangling symlink at a credential path; an inotify watcher on home and `/etc`; a cleanup that fails; a socket-activated listener; pre-existing loopback services that log every connection; `HTTPS_PROXY` pointing at one of them, run once without approval and once with | the box's files and inodes change only by the probe binary and its scratch directory, both removed, and listed markers, each gone with its confirmed-deleted box or volume or listed as an unresolved cleanup item, nothing removed by name; no FIFO opened; the dangling link unknown, never absent; the socket-activated listener never activated; no pre-existing local service logs a connection, except the approved proxy, which logs exactly one `CONNECT` to the canary; without approval EGR-3 is skipped and listed; every connection on the fixture network is to a fixed destination the plan named or a box-named one the resolved plan pinned within its approved class |
| `evidence` | a same-UID peer process; a metadata stub with no identity permission; a host that allows a TLS handshake but refuses an upload; `hidepid=2`; a writable stale control socket; a world-writable control socket whose server rejects the agent by peer UID; a control port blocked by an owner-match rule; an agent path that execs commands directly and never sources a writable `~/.bashrc` | SEC-5 tests the peer; SEC-4 an indicator, not a proof; EGR-6 an indicator and CHN-1 potential; SEC-2 `scoped_out`, never `absent`; the sockets and the port are indicators, never proofs, never CHN-2; PER-1 an indicator that records the path isn't sourced |
| `substitute` | the probe replaced inside the box by one that reports the expected digest and every check passing | the report calls the probe host-shipped, never attested, with SBX-10's boundary beside the grade; the test records that this substitution is not detected, as SBX-10 says |
| `broken` | a `noexec` scratch filesystem; a box of the wrong architecture | invalid, no letter, exit 5 |

- **Fault builds never ship.** The `network` fixture's fault-injection probes are built with the `sandprobe_faults`
  tag, which replaces `connect` for any address but loopback; the evidence the probe gathers stays honest, so the
  grader must refuse each one. A shipped probe carries none of it, and `SANDPROBE_FAULT` means nothing to it.
- **Release gate.** A probe build ships only if its exact digest produced receipts on every canary port in the
  `network` fixture's open case, so the shipped binary is known to make the attempts it reports.
- **Test overrides are visible.** Endpoints are redirected only through `SANDPROBE_TEST_*` variables. Each one lands in
  `overrides`, and a run with any override stamps TEST ENDPOINTS on its grade, so a real run can't be redirected
  silently.
- **Grader.** Go unit tests feed synthetic observations through every GRD, CHN, KND and TWN rule, including: a check
  omitted; duplicate IDs; an ID not in the manifest; a forged pass; two outcomes for one check; a mismatched nonce, box
  ID or digest; oversized fields; HTML and script payloads in every string field (the HTML report must render them as
  text under its CSP).
- **Agent contract.** A non-terminal `run` without `-y` exits 3 with the plan; an existing box without `-attest` exits
  3; every error carries `fix`; NDJSON parses line by line; every fixture report validates against `sandprobe schema`, whose `toolchain` entries forbid any hash field.
- **TUI.** Golden frames at 80 columns, reduced motion, both palettes; `NO_COLOR` output holds no escape codes.
- **Adapters.** Fake provider CLIs and APIs, in the style of CST-20's fake `sprite`: an adapter refuses to reset or
  delete any ID it didn't create this run, records every call, and reports a failed delete.

| Rules | Test |
|-|-|
| SBX-1, SBX-2 | `effects`, and every fixture: files before and after differ only by listed markers; no evidence field holds `sandprobe-fake` |
| SBX-3 | every fixture: a capture on the fixture network holds only connections to targets the plan named, and `contacted` matches it |
| SBX-4, SBX-5, SBX-6 | `deceptive`; `substitute`; identity fields present in every fixture; an accidentally swapped binary invalidates the run |
| SBX-7, SBX-8, SBX-11 | `network`; a canary that hangs; the release gate; the canary's unit tests (an unarmed nonce, or an armed one on another port, leaves no receipt and can't crowd the matching one out; each cap holds; a refused arm; an expired, disarmed or unknown run, or another pin, fails the query; a hit connection cap, or a rise in the kernel's drop counts, marks the armed run overloaded; the worst-case answer encodes under 8,000 characters, and one over 16,000 is refused; peak healthy concurrency from one address, 8 runs' attempts plus health, stays under the per-source cap); the grader's (an overloaded run passes nothing and finds nothing `not_found`, while a receipt still finds); `deploy/canary_test.sh` (teardown against fake CLIs) |
| SBX-9, GRD, CHN, KND, TWN-1, TWN-2 | grader unit tests; `clean`, `holes`, `evidence` |
| TWN-3, PER-5 | `reset` |
| SEC, EGR, PER, AMP | `holes` (found), `clean` (verified or scoped out), `deceptive` and `network` (never pass), `policy` (AMP-1), `evidence` (class right) |
| OUT, AGT | contract tests; schema validation; the grader's injection cases |
| UX | golden frames |
| UX-4 (SEC-4's addresses) | `cmd/sandprobe/sec4_plan_test.go`: `TestPlansNameEverySEC4Address` (docker, aws-nitro, and run exec and run kubernetes with `-provider-endpoints SEC-4` each name 169.254.169.254:80, 169.254.170.2:80 and 169.254.170.23:80 word for word, with each one's condition and what is sent; sprites, e2b, daytona and run exec without SEC-4 name none), `TestProbeDialsTheCatalogMetadata` (the probe's address constants are `catalog.Metadata`'s, and no other metadata address is written in the probe, so a probe address the plans don't name fails) |
| PRV | fake provider tests; then one live run per provider |
| RUN-12 | manager readiness/admin separation and pinned host-model shape/account/retry tests |
| RUN-13 | managed exact collector options reach survey while EGR-6 stays skipped; fresh repair staging and pinned-SDK nonroot read-only filesystem regression |
| RUN-14 | existing managed lifecycle, request-budget and original-ID cleanup regressions; retained continuation provenance and assessment |
| EVD-5 | shared configuration evidence schema, exact image-identity fixtures, Nitro guard and Daytona unavailable-evidence artifact |
| EVD-6 | bounded HTTP/error label fixtures, Linux guest protocol tests and diagnostic/grading invariance |
| SCR-4 | shared score recomputation, primary workload rendering, unknown/not-proven retention, managed output and historical rendering compatibility |
| RUN-15 | protected HOME/project/cache parity, original-home metadata guards, unchanged functional workload and managed original-ID cleanup |
| RUN-16 | unique receiver namespace, durable phase/terminal outcome fault cases, lost responses and narrowly bound legacy no-create reconciliation |
| EVD-1 | six-category catalog accounting, grouped missing evidence, invalid input, provider parity and retained Nitro/Daytona grades unchanged |
| EVD-2 | local TLS/raw exchange fault cases and bounded diagnostic values; connected/no receipt remains unknown |
| EVD-3 | Linux O_NOATIME rejection then readable file, and genuine EPERM refusal |
| EVD-4 | existing managed original-ID cleanup and request-budget tests; retained accuracy-validation provenance |
| MEAS-1/MEAS-2 | shared frozen binding, receiver lifecycle ordering, replay/identity/control/receipt/stop failures and positive-delivery grading |
| MEAS-3 | bounded expected-ack/wrong-reply/EOF cases; host receipt requirements unchanged |
| MEAS-4 | generic SSM/Docker transport fixtures, Daytona original-ID pre-finalization shutdown and cleanup recovery; fresh managed validation |
| PRV-15 (identity) | `internal/probe/whoami_test.go` in `test/probe.sh`, as nobody and as root: the four uids from the kernel's Uid line, `-whoami` resolving names and numbers with no check run, and the shipped probe bound to another uid writing nothing and running no survey while bound to its own it runs; `cmd/sandprobe-probe` argument tests (`-expect-uid` binds a run only, never `-whoami` or `-quick`) |
| PRV-15 (transport) | `internal/host/exec_test.go`: through a real `sh`, nothing runs before the preflight, a refused preflight stops everything, every run is bound with `-expect-uid`, banners outside the markers are ignored, SEC-1's twin is set, a pre-existing scratch path is left alone even when its "already exists" answer is lost, and a path the box swaps in during a run survives the wrapper's own trap (only a path carrying this box's owner token is ever removed, by the trap, the removal invocation or the suggested command), an invocation killed past its limit is cleared by the separate removal invocation, an unreachable box leaves the path and its removal command reported and blocks further runs, a command that fails after running the script counts for nothing, a removal through a failing command or under an unsearchable parent isn't "gone", arguments with shell syntax are refused; `TestExecBoxDocker` (SANDPROBE_FIXTURES=1): the shipped probe through `docker exec -i` as nobody, a switch to root refused with nothing written, no scratch left |
| PRV-15 (provider endpoints) | `cmd/sandprobe/endpoints_test.go`: `TestProviderEndpointsParse` (the four IDs, each once, trimmed; empty, an empty item, `all`, `*`, lowercase, any other ID, a duplicate, another separator, or a check the run doesn't exclude are refused, and an unknown value is never echoed; the rest stay excluded), `TestProviderEndpointsOnlyWhereTheyApply` (refused on run docker, native adapters, aws-nitro and offline commands, and empty or `all` on exec), `TestProviderEndpointsPlan` (each attested check with its attestation, the metadata address and the API handshake it adds, the checks still off, the residual; AMP-6 still won't run on an existing box; `-allow-local-proxy` only with EGR-3; an unapproved run exits 3 with the attestation in its JSON plan), `TestProviderEndpointsWithExplicitCanary` (endpoint selection survives an explicit no-canary or public-canary choice beside stale environment defaults, with no network calls), `TestProviderEndpointsRecipePlan` (a shipped recipe, through a stub kubectl: the same plan lines under RCP-4, nothing past sp_ready), `TestProviderEndpointsAttestationRecord` (ANL-1: the fixed sentence beside exactly the attested checks; another sentence, a missing one, a non-endpoint, a still-skipped check, an attestation on a native adapter's run, or one in a report that declares `sandprobe/1` is refused), `TestRunExecProviderEndpointsDocker` (`SANDPROBE_FIXTURES=1`: run exec through `docker exec` into a container with no network, so no metadata is reachable: the report declares `sandprobe/2`; SEC-4 and AMP-7 run and end `not_found` or unknown, never a pass or an absence, each with its attestation; EGR-3 and AMP-6 keep `opt_in`; Cloud access is never "not tested" or not applicable, and a green row names its not-proven checks); `internal/host`: `TestPlanAttested` (attested checks selected and recorded sorted in the manifest, never in the probe's input; the rest keep `opt_in`; AMP-6 skipped on an existing box whatever was attested, selected on a throwaway one; EGR-3 attested without a canary is sound, graded but never sent to the probe, and a loopback proxy without `-allow-local-proxy` is skipped with no kind; the grader refuses a non-endpoint, a duplicate or a still-kinded attestation; Execute refuses one that isn't an endpoint, is named twice, or is still excluded); `internal/report`: `TestReportRecordsAttestation` (the sentence beside exactly the attested checks, in the JSON and on the page); `internal/analysis/attested_test.go`, on a Docker fixture run planned with `-provider-endpoints SEC-4,AMP-7`: `TestInvalidRunKeepsAttestedRows` (an invalid run keeps both rows, unknown with "not graded" and the attestation, grades nothing else and lists no unknowns, loads under ANL-1, and its page shows each attestation and the report's real schema; a valid run's page shows each attestation beside its test and in the appendix), `TestAttestedRowsAreRequired` (the code review's reproduction: a report with the attested SEC-4 row deleted is refused, invalid or valid; an invalid report with an unknown row nobody attested, or with unknowns in its grade, is refused), `TestInvalidAttestedRowsStayNotGraded` (the code review of #12: an invalid report whose attested SEC-4 row is turned `not_found` with a reason of its own is refused, as are an attested row turned a finding, given another reason, evidence or a scope, and a graded row nobody attested; the unchanged report still reads) |
| PRV-15 (command) | `cmd/sandprobe/exec_test.go`: run exec refuses a missing command, a passthrough to another provider, a relative or unsafe `-scratch`, a malformed `-as`, a command not on PATH, and `-canary-url` without a pin; with no canary named, even beside a stray `canary-*.state` file, the plan uses the hosted canary and states its retention, and the shipped URL and pin pass `CheckCanaryURL` (`TestRunExecDefaultsToTheHostedCanary`, HCN-5); a pin without its URL, by flag or environment, is refused rather than set aside (`TestRunExecPinWithoutURLIsRefused`); a URL or pin pasted with a credential (userinfo, query, fragment, path, a bad pin) is refused before the plan exists and never appears in its text or JSON, while a valid one is shown canonical; the plan names the box, the scratch path, the user check, the public canary and HCN-4's retention, the four checks off and PER-5 skipped, and no metadata address; without `-y` nothing runs; `TestExecuteThroughExecBox` (SANDPROBE_FIXTURES=1): Execute drives the shipped probe through `docker exec` as nobody, the base64 upload keeps SBX-5's digest, the run is valid, SEC-4, EGR-3, AMP-6, AMP-7 and PER-5 are skipped with their reasons, and no scratch is left |
| RUN-11 | nullable native-network policy, fixed-stage/no-create status and failed-preparation retention regressions |
| WGR-8 / RUN-10 | portable snapshot contract/grade calibration; managed Daytona lifecycle, principal, workload isolation and failure/cleanup tests |
| WGR-7 | `TestPortableWorkloadDeclaration`, `TestPortableWorkloadCalibration`; version1 retained Nitro report compatibility test |
| WGR-6 | run where the operators keep their recorded collections, not in this repository |
| WGR-1..5 | `internal/grade/workload_test.go` (allowed vs forbidden, mixed proof faults, immutable context, independent positive evidence); `internal/obs/workload_test.go`; `internal/host/workload_test.go`; `internal/probe/workload_test.go` (Linux root/nobody); `internal/report/workload_test.go`; `cmd/sandprobe-agent-grade/workload_test.go`; `deploy/eks-agent/test_workload_contract.py` |
| RUN-8 | `TestAgentPodBindingGuardsEveryInvocation`, `TestAgentPodRejectsNonRunBindingBeforeKubectl`, `test_standard_grade.py`; same-pod standard grading, failed-task preservation, binding changes and independent canary cleanup |
| PRV-5 | a Modal plan selects none of SEC-4, AMP-6, AMP-7 or EGR-3, lists each as skipped with its reason, and its manifest names no metadata address, vsock port, Kubernetes API or proxy |
| PRV-5 (Sprites) | `TestSpritesExclusions`: Sprites excludes exactly SEC-4, EGR-3, AMP-6 and AMP-7, each one Execute accepts; `TestSpritesPlanContactsOnlyTheCanary`: the plan names no metadata address or box-named destination |
| POC-1, POC-2, POC-5 | each setup's create request against its table row (an empty allowlist stays allowlist mode, never open); the gate against synthetic counts for every setup, including the twin's nonce on another port, a nonce counted elsewhere, a 443 count missing from a complete relay log (trips), and a truncated log (unknown, stops before `look`); a tripped gate renders no report and runs no later step; a token-shaped sentinel planted in an SDK error appears in no terminal line, call record or artifact |
| POC-6 | the relay against a local TLS server at a stand-in pinned IP: an owned nonce relayed with bytes counted and the pin intact through it; a non-owned SNI, a missing SNI and a name that would resolve elsewhere each refused, with no SNI and no payload in the log; `ready` only once listening; attribution unknown with a missing or truncated log; `look` against a planted marker, its absence, and a stop at the first sighting with no later row run |
| POC-7, POC-8 | the summary from fixture reports: every finding bucketed by the table, an unbucketed one refused, no letter grade, the HTML under OUT-2's CSP with hostile strings rendered as text |
| POC-9 | a fake Modal API: a sandbox terminated and confirmed by ID and tag, a failed terminate reported with its fix |

## Open questions

| # | Question | Blocks |
|-|-|-|
| 2 | May EGR-6 handshake with the listed public hosts? | enabling EGR-6 only; it stays skipped and listed until then |
| 3 | ControlPlane's sandbox-probe (Apache-2.0, 14 checks). Default: our own IDs, mappable to theirs | nothing yet |

exe.dev PRV-13: `internal/host/exedev_test.go` covers bounded native API transport, streamed completion, generated-path quoting and chunked digest-verified upload, exact create-returned name/birth/run-tag identity, no ambiguous-create adoption, private crash journals and acknowledged deletion plus scoped absence. `cmd/sandprobe/exedev_test.go` covers plans and approval before credentials and run-independent cleanup.
