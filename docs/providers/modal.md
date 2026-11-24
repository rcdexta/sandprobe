# Modal: a proof of concept

**Status for 0.3.0, being validated:** Beta: a proof of concept, not in the release build. Last validated: pending.
[All providers](README.md)

The Modal proof of concept probes Modal Sandboxes in your own workspace: a default sandbox, a few locked-down network
setups, and a sidecar that watches the main container's traffic (SPEC.md, "Modal proof of concept"). It lives behind
a build tag. A release has no `poc` command, and there is no `sandprobe run modal`.

Its known gaps:

- You build it from source.
- It needs a canary you deploy yourself (see the last section).
- It runs one setup per invocation, and you read each setup's raw record before you render its reports.

## Prerequisites

- A clone of this repository and Go 1.25, to build `bin/sandprobe-poc` with `make poc`.
- A Modal workspace of your own, with Modal's token already in `~/.modal.toml`.
- A canary from `deploy/canary.sh`. That needs an AWS CLI profile (`PROFILE`), a Cloudflare DNS zone you control
  (`ZONE` and `DOMAIN`), the `cf` CLI and `jq`. The `domain-one` and `sidecar` setups also need its wildcard record:
  `deploy/canary.sh wildcard`.

## Credentials

| Name | What it is |
|-|-|
| `~/.modal.toml` | Modal's own token file. The SDK reads it on your machine. It never enters a sandbox, and Sandprobe never prints it. |
| `SANDPROBE_MODAL_WORKSPACE` | The one workspace the proof of concept may use. Nothing runs without it. |

## Run it

```sh
make poc
bin/sandprobe-poc poc modal run -variant default -canary <canary state file> -out <dir> -y
bin/sandprobe-poc poc modal render -variant default -out <dir>
bin/sandprobe-poc poc modal summary -out <dir>
bin/sandprobe-poc poc modal cleanup -out <dir> -y
```

`-variant` picks the setup: `default`, `domain-empty`, `domain-one`, `block`, `block-vm` or `sidecar`. Each sandbox
has a 15-minute timeout as a spend backstop and is terminated by its ID. The built images stay until `cleanup`, and
the App stays, named in the report.

## Probe your own Modal sandbox with run exec

You don't need the proof of concept to probe a sandbox of your own: `run exec` reaches it through any command that
starts `sh` in it. [`examples/modal/bridge.py`](../../examples/modal/bridge.py) is one such command, built on
Modal's Python SDK (1.5.5 or later). It creates one throwaway sandbox in your own workspace, CPU only, with a
15-minute timeout as a spend backstop. It records the ID that create returned and a random tag, which it sets in the
create request itself, in a private state file it reserves before it creates anything. If anything fails after the
create, Ctrl-C included, it terminates that sandbox and confirms it finished. `sh` and `rm` act only on the one live
sandbox in the `sandprobe` app that carries the recorded tag and has the recorded ID; anything else, an edited or
copied state file included, refuses and touches nothing. The token stays with Modal's SDK in `~/.modal.toml`; the
script never reads or prints it (FIX-10).

```sh
pip install 'modal>=1.5.5'                             # then `modal setup`, once, for ~/.modal.toml
python3 examples/modal/bridge.py create round-0 r0.state
sandprobe run exec -as root -y -out round-0 -- python3 examples/modal/bridge.py sh r0.state
python3 examples/modal/bridge.py rm r0.state
sandprobe fix round-0/*.json -platform modal            # you name the platform; fix never guesses it
```

Then apply the top action, create a new sandbox, run again into `round-1` (with `-as agent` once the agent has its own
user), and `sandprobe compare round-0/*.json round-1/*.json`. The script's `round-1` and `round-2` setups are the
fixes below.

If the sandbox ended at its timeout before `rm`, `rm` finds no live sandbox with the tag and refuses, touching
nothing. Once Modal shows that sandbox finished, delete the state file yourself. Exit 7 from any command means a
sandbox may still run: it prints the ID, and the sandbox ends at its timeout.

The bridge's guards were added after the three rounds below ran, and are tested only against a fake of Modal's SDK
(`examples/modal/bridge_test.py`), not yet on Modal itself.

`run exec` keeps SEC-4, EGR-3, AMP-6 and AMP-7 off, since each would contact an endpoint Modal owns. Leave them off:
on Modal they are outside Sandprobe's reviewed scope, so Cloud access reads "Not tested", and `fix` lists it as not an
action for an agent.

### The fixes proven on Modal

Three rounds on 24 November 2026, one throwaway sandbox per round (python:3.12-slim-bookworm), each rerun through
`run exec` and compared with the round before (FIX-4):

| Round | `fix` action | The change | Score |
|-|-|-|-|
| 0 | | Modal's defaults: root, network open | 0/6 |
| 1 | `run-as-user` | In the image, `useradd -m -u 1000 -s /bin/bash agent`; run the agent's commands through `setpriv --reuid=1000 --regid=1000 --init-groups --inh-caps=-all --ambient-caps=-all --no-new-privs <cmd>` | 3/6, with `block-network`: Exfiltration, Containment and Privilege turn green |
| 1 | `block-network` | `modal.Sandbox.create(..., block_network=True)` | |
| 2 | `clean-env` | Add `--reset-env` to that `setpriv`, so the agent starts with a minimal environment | 4/6, with `protect-home`: Persistence turns green, and SEC-1 clears |
| 2 | `protect-home` | In the image, `chown -R root:root /home/agent; chmod 0755 /home/agent; mkdir -p /work; chown agent:agent /work`; `workdir="/work"` on exec | |

What it costs, and what stays:

- `block_network=True` also cuts the agent off from its model API. Its model calls must go through something outside
  the sandbox.
- DNS and UDP 53 then have no receipt, which isn't proof, so Exfiltration reads green with "not proven: DNS, UDP 53".
- Modal's domain and CIDR allowlists weren't tested in this loop, so nothing here says how they treat DNS.
- SEC-2 stayed red in every round: the probe counts the shell `run exec` starts as another process of the agent's.
- Cloud access stays "Not tested", as above.

## What's skipped, and why

| Check | Why |
|-|-|
| SEC-4, EGR-3, AMP-6, AMP-7 | Each would send a request to an endpoint Modal owns (PRV-5). |
| PER-5 | No reset: a terminate and recreate would test only a Volume, and the sandbox mounts none. |
| EGR-6 | Contacting public upload sites isn't approved, on any run. |

Also not tested: fronting through a shared CDN, inbound through unencrypted tunnels, GPU sandboxes, the Datadog
integration and the Outbound Policy (POC-4).

## Terms and consent

SPEC.md's Modal row records no terms link. It notes that Modal's terms say nothing about customers testing their own
sandboxes, and that Modal's security page asks bug-bounty research to use a workspace ending `-H1-<username>`. The
proof of concept runs in your own workspace, outside the bug bounty. If a result suggests a real flaw on Modal's
side, the run stops and exits 8, and keeps only a private note (POC-5).

## What the score can and can't reach

- Persistence rests on PER-1 to PER-4. Whether anything survives a reset isn't tested.
- Each setup is one configuration, chosen by `-variant`, not every way a Modal sandbox can be set up.

### Canary and Cloud access (0.3.0)

The proof of concept doesn't use the hosted canary. It needs `-canary <state file>`, naming a canary you deployed with
`deploy/canary.sh`, which it reaches over AWS SSM. Cloud access is not applicable here: PRV-5 excludes Modal's own
metadata and Kubernetes endpoints, so the box holds no cloud identity of yours to check. Cloud access is never green,
the score is out of five, and a line under the score says why. A credential of yours put into the box is still caught
under Secrets.
