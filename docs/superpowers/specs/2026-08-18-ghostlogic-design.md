# GhostLogic — Design

**Date:** 2026-08-18
**Author:** Abdulmajeed Aldulijan
**Repo:** https://github.com/mejooo/ghostlogic
**Event:** OT Cybersecurity Hackathon, Dhahran, 24–27 Aug 2026

---

## 1. What this is

GhostLogic watches Modbus/TCP traffic on a pump skid, decodes the commands that
change the plant, and raises an alert when a command is dangerous. The alert is
decided by plain, readable rules. A local language model then explains that
alert in normal English. The model never decides anything.

One sentence for the stage: **the dangerous moment in an OT attack is the one
where nothing looks wrong, and GhostLogic is the thing that sees it.**

## 2. Context and constraints

- Solo builder, working part-time, 6 days before the event.
- The laptop demo is the guaranteed path. Venue equipment is unknown, so it is
  treated as an optional upgrade, not a dependency.
- The demo must be repeatable. Same run, same picture, every time.
- Local machine: macOS, Python 3.14.6, GitHub account `mejooo`, Linear team
  `Deemware`. Ollama is not installed yet.

## 3. Goals

1. Show a live attack on a simulated pump skid and detect it from traffic alone.
2. Show one legal operator change that produces no alert.
3. Show the physical consequence: pressure climbing past a protection that was
   silently switched off.
4. Explain each alert in plain English, with the raw bytes and the matched rule
   shown beside it.
5. Never fail on stage.

## 4. Non-goals

Explicitly not built. Say these out loud during the pitch; they read as
judgment, not as gaps.

- Decompiling vendor PLC bytecode (Siemens, Schneider). Roadmap slide only.
- Docker and OpenPLC.
- Detecting reconnaissance or scanning (read-side rules).
- Alerting on an unexpected source address.
- Any cloud service, database, or user accounts.

## 5. The demo story

The plant is a pump skid: one pump, one pressure transmitter, one isolation
valve, and a high-pressure trip that protects the vessel.

| Time | Event | What the judge sees |
|---|---|---|
| 0s | HMI polls tags twice a second | Steady: speed 55%, 60 PSI, trip **ARMED** at 95 |
| 10s | Operator raises speed 55 → 70 (legal) | Write appears in the feed, marked allowed. **No alert.** Pressure drifts to 75 |
| 25s | Attacker writes coil 1 = 0 | **CRITICAL.** Trip disarmed. Every process value still looks normal |
| 40s | Attacker writes speed = 110 | **HIGH.** Outside the safe band. Pressure starts climbing |
| ~55s | Pressure crosses 95 and reaches 115 | The line sails past the trip marker. Nothing stops it |

Total run: about 60 seconds.

## 6. Architecture

```
  HMI client  ──┐                          ┌─→ plant.py  (Modbus server
  (polls tags)  │                          │    + physics + trip logic)
                ├─→ capture source ─────────┘
  attacker    ──┘   (proxy | replay | sniff)
                          │ raw frames, both directions
                          ▼
                      dissect.py ──→ writes ──→ detect.py ──→ alert?
                          │                                    │
                          └──→ read replies ──→ live values     ▼
                                      │                    explain.py
                                      ▼                   (Ollama + cache)
                              state.json  +  alerts.jsonl
                                      │
                                      ▼
                            cockpit/index.html (polls both)
```

### Components

| File | Single job |
|---|---|
| `ghostlogic/plant.py` | The PLC. Holds tags, runs the physics, enforces the trip while it is armed |
| `ghostlogic/sources/proxy.py` | Live inline tap. The laptop demo default |
| `ghostlogic/sources/replay.py` | Replays a recorded run. The stage parachute |
| `ghostlogic/sources/sniff.py` | Mirror-port capture. Written only if venue gear appears |
| `ghostlogic/dissect.py` | Raw bytes → write events, and read replies → live tag values |
| `ghostlogic/detect.py` | The rules. Decides alert or silence. No model involved |
| `ghostlogic/explain.py` | Turns an alert into plain English via the local model, cached |
| `ghostlogic/scenario.py` | Starts everything, runs the HMI and the attacker, records the run |
| `ghostlogic/config.py` | Loads and validates `tags.yaml` |
| `cockpit/index.html` | The screen the judges watch |
| `tags.yaml` | One tag dictionary shared by the plant and the rules |

Every component is importable and testable on its own. Nothing reaches into
another component's internals.

## 7. The capture seam

The pipeline reads frames from a **source**. A source is any object that calls a
sink with `(direction, raw_bytes, timestamp)` where direction is `"c->p"` or
`"p->c"`. Three implementations share that one interface:

1. **proxy** — an inline TCP proxy on port 5020 forwarding to the plant on 5502.
   This is a laptop convenience and it is **not passive**. Say so if asked.
2. **replay** — reads a recorded JSONL of frames and feeds them at the original
   timing. Used if anything breaks on stage.
3. **sniff** — a scapy or pyshark capture on a mirror port. This is the honest
   production story: traffic is copied to us, so we cannot delay, drop, or alter
   anything, and we can never destabilise the process.

Recording is one extra line inside the capture callback, so the parachute is
nearly free.

Live plant values are learned **passively**, by decoding the HMI's read replies
off the wire. GhostLogic never *originates* a packet to the plant. The proxy relays what the
client already sent; the sniff backend does not even do that. Matching a reply
to its request uses the MBAP transaction ID, so the dissector keeps a small
pending-request map per connection.

## 8. The tag dictionary

`tags.yaml` is the single source of truth. `plant.py` seeds its initial values
from it. `detect.py` builds its rules from it. They cannot drift apart, and
adding a tag is a config edit, not a code change.

```yaml
plant:   { host: 127.0.0.1, port: 5502 }
proxy:   { host: 127.0.0.1, port: 5020 }
physics: { tick_ms: 250, approach: 0.08, ambient: 5, gain: 1.0, flow_factor: 0.95 }

tags:
  - kind: holding
    addr: 0
    name: PMP101_SPEED_CMD
    unit: "%"
    init: 55
    safe: [0, 80]
  - kind: holding
    addr: 1
    name: FT101_FLOW
    unit: "m3/h"
    init: 52
    readback: true
  - kind: holding
    addr: 2
    name: PT101_PRESSURE
    unit: "PSI"
    init: 60
    readback: true
  - kind: holding
    addr: 3
    name: HP_TRIP_SETPOINT
    unit: "PSI"
    init: 95
    safe: [90, 100]
  - kind: coil
    addr: 0
    name: PMP101_RUN
    init: 1
  - kind: coil
    addr: 1
    name: HP_TRIP_ENABLE
    init: 1
    protective: true
    must_stay: 1
    impact: "Loss of high-pressure protection — over-pressurisation hazard"
  - kind: coil
    addr: 2
    name: XV101_VALVE_OPEN
    init: 1
```

Tags marked `readback: true` are values the plant computes. A write to one of
them is not normal operation and is treated by rule 3.

## 9. Detection rules

| # | Fires when | Severity | ATT&CK for ICS |
|---|---|---|---|
| 1 | A tag marked `protective` is forced off its `must_stay` value | CRITICAL | T0836 Modify Parameter |
| 2 | A tag with a `safe` band is written outside that band | HIGH | T0836 Modify Parameter |
| 3 | A write lands on an address not in the dictionary, or on a readback tag | LOW | T0855 Unauthorized Command Message |

Rule 3 closes a hole in the starter kit, which treated any unknown address as
safe. A write to an undocumented register is now never silent.

Rules run in order and the first match wins. Reads never produce alerts.

## 10. The physics

Deliberately simple, deterministic, no randomness, so the demo looks identical
every run.

```
target = ambient + (speed × gain)        when pump running and valve open
target = ambient                         otherwise
pressure += (target − pressure) × approach     every tick (250 ms)
flow     = speed × flow_factor           when running and valve open, else 0
```

The plant keeps pressure and flow as floats internally but writes them into the
holding registers as rounded integers, because Modbus registers are 16-bit
integers. Everything downstream — the passive decode, `state.json`, the cockpit
chart — therefore sees whole numbers. Real plants scale instead (tenths of a
PSI); that is a roadmap detail, not a demo-day one.

With `ambient = 5` and `gain = 1.0`, the numbers tell the story on their own:

| Speed | Settles at | Meaning |
|---|---|---|
| 55 (start) | 60 PSI | normal running |
| 80 (top of the safe band) | 85 PSI | still under the 95 trip — legal operation can never trip the plant |
| 110 (attack) | 115 PSI | past the trip point |

The trip lives **inside the plant**, where a real one would. On every tick, if
`HP_TRIP_ENABLE` is 1 and pressure is at or above `HP_TRIP_SETPOINT`, the plant
sets `PMP101_RUN` to 0 and speed to 0 and the pressure decays. Disable the trip
and that protection is simply gone.

## 11. Explain layer

`explain.py` builds a prompt from the alert — tag name, value written, the rule
text, the impact line, and the raw hex — and asks the local model for four short
lines: what happened, why it matters physically, and what to do. It is never
asked how confident the finding is — confidence is not the model's to judge.

Three protections:

- **Cache first.** Explanations are keyed by a stable fingerprint of the alert
  (tag, value, rule) and stored in `explanations.json`, which is committed to
  the repo. On stage the text appears instantly and the model still did the real
  work when it was generated.
- **Fallback chain:** cache → model → the canned `impact` text from `tags.yaml`.
  The screen is never blank, whatever fails.
- **The model cannot change the verdict.** Severity, rule text, and ATT&CK ID
  come from `detect.py` and are rendered before any explanation exists. If the
  model produces nonsense, the deterministic finding is still on screen beside
  it. This is the answer to "what if it hallucinates?"

Model: a small local model through Ollama's HTTP API on `localhost:11434`.
Choice of model is fixed in config and recorded in the cockpit, so what is shown
on screen always says which model produced the text and whether it came from
cache.

## 12. Data contracts

`state.json`, rewritten every tick:

```json
{
  "ts": 1755525600.25,
  "source": "LIVE PROXY",
  "tags": { "PMP101_SPEED_CMD": 70, "PT101_PRESSURE": 75,
            "FT101_FLOW": 66, "HP_TRIP_SETPOINT": 95,
            "PMP101_RUN": 1, "HP_TRIP_ENABLE": 1, "XV101_VALVE_OPEN": 1 },
  "counters": { "frames": 412, "writes": 1, "malformed": 0 }
}
```

`alerts.jsonl`, one JSON object appended per alert:

```json
{
  "seq": 1, "ts": 1755525615.10,
  "tag": "HP_TRIP_ENABLE", "kind": "coil", "addr": 1, "value": 0,
  "severity": "CRITICAL",
  "rule": "Protective coil HP_TRIP_ENABLE forced to 0 (must stay 1)",
  "attack_id": "T0836", "attack_name": "Modify Parameter",
  "impact": "Loss of high-pressure protection — over-pressurisation hazard",
  "raw_hex": "000100000006010500010000",
  "explanation": "…", "explain_source": "cache"
}
```

The cockpit reads only these two files. It never talks to Python directly, which
is what makes the GitHub Pages build possible: the same page plus a recorded
pair of files is a working static demo.

## 13. Fixes carried over from the starter kit

The starter kit is a valid base but has three real defects, each of which gets a
test:

1. **Split frames are lost.** The dissector keeps no buffer between chunks, so a
   Modbus frame split across two TCP packets is dropped and that write is never
   seen. Fix: a per-connection buffer.
2. **Malformed frames crash the capture thread.** `struct.unpack` on functions
   0x10 and 0x0F is unguarded, so a lying byte count raises and blinds the tool.
   Fix: guard, count, and carry on.
3. **Unknown addresses are treated as safe.** Fix: rule 3 above.

The malformed-frame counter is shown in the cockpit. A spike in junk frames is
itself worth seeing.

## 14. Testing

| Level | What it proves |
|---|---|
| Unit — `dissect` | split frames reassemble; malformed frames do not raise; read replies decode to values |
| Unit — `detect` | the legal write stays silent; each rule fires with the right severity and ATT&CK ID |
| Unit — `physics` | 80% speed settles below the trip; 110% crosses it; the armed trip stops the pump |
| Unit — `explain` | cache hit returns without calling the model; model failure falls back to canned text |
| End to end | the full 60-second scenario runs headless and emits exactly: no alert, then CRITICAL, then HIGH, in that order |

The end-to-end test is the demo's own safety net. If someone breaks the demo,
the build goes red on the laptop, not in front of judges.

## 15. CI/CD

GitHub Actions, on every push and pull request:

- `ruff` lint and format check
- `pytest` including the end-to-end scenario test
- **Security scans:** CodeQL, `pip-audit` for dependency CVEs, `bandit` for
  unsafe Python patterns, `gitleaks` for committed secrets
- Dependabot for dependency updates

On push to `main`, a second workflow publishes the cockpit to **GitHub Pages**:
the static `index.html` plus a recorded `state.json` and `alerts.jsonl` from a
scenario run. That gives a public URL a judge can open on their own phone, and
it doubles as the replay parachute.

The repository is public, so all of these are free.

## 16. Project management

Linear, team **Deemware**, one project: **GhostLogic — OT Hackathon**, target
date 24 Aug 2026.

| Milestone | By | Done means |
|---|---|---|
| M0 — Prove the ground | Aug 19 | pymodbus runs on Python 3.14, Ollama installed and a model pulled, repo and CI skeleton green |
| M1 — Pipeline live | Aug 20 | HMI and attacker traffic flows through the tap; writes decoded; read replies decoded into live values |
| M2 — Detection and scenario | Aug 21 | Three rules, `tags.yaml`, the 60-second scenario emits exactly the right alerts |
| M3 — Cockpit | Aug 22 | The dashboard tells the story without narration |
| M4 — Explain layer | Aug 23 | Local model explains alerts, cached, with fallback |
| M5 — Ship and rehearse | Aug 23 | Pages deploy live, replay parachute tested, demo run start to finish twice |

M0 comes first on purpose: both unknowns (pymodbus on Python 3.14, and Ollama
existing at all) get answered on day one, while there is still time to change
the plan.

Linear issues are created from the implementation plan, one to one, after the
plan is written. Connecting GitHub to Linear so branches and pull requests
attach to issues is a manual step in Linear's settings.

## 17. Risks

| Risk | Mitigation |
|---|---|
| `pymodbus` does not work on Python 3.14 | First task in M0. If it fails, pin Python 3.12 in a virtual environment |
| Ollama is slow, or never gets installed | Cache-first design; the canned fallback means the demo still runs with no model at all |
| Something breaks live on stage | The replay source plays a recorded run through the identical pipeline, labelled honestly on screen |
| The inline proxy is criticised as "not passive" | Stated up front in the pitch, with `sniff.py` as the production answer |
| Scope creep eats the last two days | Non-goals in section 4 are fixed. Anything new goes on the roadmap slide, not into the build |

## 18. Roadmap slide (what comes after the hackathon)

Real mirror-port capture on plant hardware; alerting on unexpected source
addresses; recon and scan detection; more protocols (DNP3, S7, EtherNet/IP);
vendor bytecode analysis; and integration with a plant historian or SIEM.
