# GhostLogic Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a passive Modbus/TCP attack detector that watches a simulated pump skid, decides alerts with deterministic rules, and has a local model explain them — demoable in 60 seconds on a laptop.

**Architecture:** One Python process starts the plant, taps the traffic, decodes it, applies rules, and writes two small files. A single HTML page polls those files. The traffic tap sits behind a one-method interface so the live proxy, a recorded replay, and (later) a real mirror-port sniff are interchangeable.

**Tech Stack:** Python 3.14 (fallback 3.12), pymodbus 3.6.9, PyYAML, pytest, ruff, vanilla JS + HTML canvas, Ollama HTTP API via stdlib urllib, GitHub Actions.

**Spec:** `docs/superpowers/specs/2026-08-18-ghostlogic-design.md`

## Global Constraints

- **Repo:** https://github.com/mejooo/ghostlogic (public). Local: `/Users/majeed/Projects/OT`.
- **Dependency floor:** `pymodbus==3.6.9` pinned exactly. Its client API uses `slave=` (renamed in later versions) and this plan's code depends on that name.
- **Runtime deps are only** `pymodbus` and `PyYAML`. The Ollama call uses stdlib `urllib`. Do not add `requests`, FastAPI, or any chart library.
- **No randomness anywhere.** The demo must produce an identical picture every run.
- **Modbus registers are 16-bit integers.** Floats live inside the plant only; anything written to a register is `round()`ed first.
- **The model never decides.** `detect.py` must not import `explain.py`. Severity, rule text and ATT&CK ID are computed before any explanation exists.
- **Time is scalable.** Every sleep is divided by a `speed` factor so the 60-second demo runs in 3 seconds under test.
- **Physics constants** (from spec): `tick_ms 250`, `approach 0.08`, `ambient 5`, `gain 1.0`, `flow_factor 0.95`.
- **Ports:** plant `127.0.0.1:5502`, proxy `127.0.0.1:5020`.
- **The capture contract carries connection identity:** `sink(conn, direction, raw, ts)`.
  The proxy taps multiple TCP connections (HMI and attacker are separate clients),
  so the dissector buffers per `(conn, direction)` and matches pending requests per
  `(conn, txn)`. Without this, two clients' byte streams interleave into one buffer.
- **Every task ends with a commit.** Commit messages use `feat:`, `test:`, `ci:`, `docs:`, `fix:`.

## File Structure

| File | Responsibility |
|---|---|
| `tags.yaml` | The tag dictionary. Single source of truth for plant seeding and rules |
| `ghostlogic/config.py` | Load and validate `tags.yaml` into frozen dataclasses |
| `ghostlogic/plant.py` | Modbus server, physics tick, trip logic |
| `ghostlogic/dissect.py` | Frame reassembly, write decoding, read-reply decoding |
| `ghostlogic/detect.py` | The three rules. Pure functions, no I/O |
| `ghostlogic/explain.py` | Cache → Ollama → canned fallback |
| `ghostlogic/sinks.py` | Atomic `state.json` writer, `alerts.jsonl` appender |
| `ghostlogic/sources/__init__.py` | The Source contract and the frame Recorder |
| `ghostlogic/sources/proxy.py` | Live inline tap |
| `ghostlogic/sources/replay.py` | Recorded run playback |
| `ghostlogic/scenario.py` | Orchestrator: plant + tap + HMI + attacker + pipeline |
| `cockpit/index.html` | The screen the judges watch |
| `tests/` | One test file per module, plus the end-to-end scenario test |
| `.github/workflows/ci.yml` | lint, tests, security scans |
| `.github/workflows/pages.yml` | publish the cockpit with recorded data |

`ghostlogic/sources/sniff.py` is **not** in this plan. It is written only if venue equipment turns out to exist (spec section 7).

---

## Milestone M0 — Prove the ground (by Aug 19)

### Task 1: Repo skeleton and pymodbus proof

Both project risks live here: pymodbus on Python 3.14, and whether the starter kit runs at all. Nothing else is worth building until this passes.

**Linear:** M0 · `GhostLogic: repo skeleton and pymodbus proof`

**Files:**
- Create: `requirements.txt`, `pyproject.toml`, `ghostlogic/__init__.py`
- Test: `tests/test_environment.py`

- [ ] **Step 1: Create the virtual environment and install**

```bash
cd /Users/majeed/Projects/OT
python3 -m venv .venv
source .venv/bin/activate
python --version
```

- [ ] **Step 2: Write `requirements.txt`**

```
pymodbus==3.6.9
PyYAML==6.0.2
```

- [ ] **Step 3: Write `requirements-dev.txt`**

```
-r requirements.txt
pytest==8.3.4
ruff==0.9.6
bandit==1.9.4
pip-audit==2.9.0
```

`bandit` must be 1.9.4 or newer. Version 1.8.2 crashes on Python 3.14 (it uses
`ast.Str`, removed in 3.12+) and — the dangerous part — **skips every file while
still exiting 0**. A security scan that silently scans nothing and reports success
is worse than no scan at all.

- [ ] **Step 4: Install and see whether pymodbus survives Python 3.14**

```bash
pip install -r requirements-dev.txt
```

If this fails to build on 3.14, do not fight it. Recreate the venv on 3.12 and carry on:

```bash
deactivate && rm -rf .venv
brew install python@3.12
/opt/homebrew/bin/python3.12 -m venv .venv
source .venv/bin/activate && pip install -r requirements-dev.txt
```

Record which Python you ended up on — Task 3 pins the same version in CI.

- [ ] **Step 5: Write `pyproject.toml`**

```toml
[tool.ruff]
line-length = 100
target-version = "py312"

[tool.ruff.lint]
select = ["E", "F", "I", "UP", "B"]

[tool.pytest.ini_options]
testpaths = ["tests"]
addopts = "-q"
```

- [ ] **Step 6: Write the failing test**

`tests/test_environment.py`:

```python
"""The two risks that could sink the project, checked on day one."""


def test_pymodbus_imports_the_api_we_depend_on():
    from pymodbus.datastore import (
        ModbusSequentialDataBlock,
        ModbusServerContext,
        ModbusSlaveContext,
    )
    from pymodbus.server import StartTcpServer

    assert callable(StartTcpServer)
    assert callable(ModbusSequentialDataBlock)
    assert callable(ModbusSlaveContext)
    assert callable(ModbusServerContext)


def test_datastore_round_trips_a_value():
    """Function code 3 addresses holding registers, 1 addresses coils."""
    from pymodbus.datastore import (
        ModbusSequentialDataBlock,
        ModbusServerContext,
        ModbusSlaveContext,
    )

    slave = ModbusSlaveContext(
        co=ModbusSequentialDataBlock(0, [1, 1, 1]),
        hr=ModbusSequentialDataBlock(0, [55, 52, 60, 95]),
        zero_mode=True,
    )
    context = ModbusServerContext(slaves=slave, single=True)

    assert context[0].getValues(3, 0, count=1) == [55]
    assert context[0].getValues(1, 1, count=1) == [1]

    context[0].setValues(3, 0, [70])
    assert context[0].getValues(3, 0, count=1) == [70]
```

- [ ] **Step 7: Run it**

Run: `pytest tests/test_environment.py -v`
Expected: PASS. If it fails on import, go back to Step 4 and switch to Python 3.12.

- [ ] **Step 8: Create the package marker**

`ghostlogic/__init__.py`:

```python
"""GhostLogic — passive Modbus/TCP attack detection."""

__version__ = "0.1.0"
```

- [ ] **Step 9: Extract the starter kit as reference and commit**

```bash
unzip -o ghostlogic-starter.zip -d reference/
echo "reference/" >> .gitignore
echo "ghostlogic-starter.zip" >> .gitignore
git add requirements.txt requirements-dev.txt pyproject.toml ghostlogic/__init__.py tests/test_environment.py .gitignore
git commit -m "feat: repo skeleton, pinned deps, pymodbus API proof"
```

The starter kit stays out of git on purpose — it is read-only reference, and every part of it is rewritten with tests in later tasks.

---

### Task 2: Ollama installed and reachable

**Linear:** M0 · `GhostLogic: install Ollama and prove the model responds`

**Files:**
- Test: `tests/test_ollama_smoke.py`

- [ ] **Step 1: Install Ollama and pull a small model**

```bash
brew install ollama
brew services start ollama
ollama pull llama3.2:3b
```

`llama3.2:3b` is about 2 GB and answers in a couple of seconds on Apple silicon. Anything larger is too slow to generate the cache comfortably.

- [ ] **Step 2: Prove it answers over HTTP**

```bash
curl -s http://localhost:11434/api/generate -d '{"model":"llama3.2:3b","prompt":"Say OK","stream":false}' | head -c 200
```

Expected: JSON containing a `"response"` field.

- [ ] **Step 3: Write the smoke test**

`tests/test_ollama_smoke.py`:

```python
"""Ollama is optional at run time, so this test skips when it is absent.

It exists so that a machine which *should* have a model gets told when the
model has gone missing, rather than silently demoing the fallback text.
"""

import json
import urllib.error
import urllib.request

import pytest

OLLAMA_URL = "http://localhost:11434/api/generate"
MODEL = "llama3.2:3b"


def _ollama_available() -> bool:
    try:
        urllib.request.urlopen("http://localhost:11434/api/tags", timeout=2)
        return True
    except (urllib.error.URLError, OSError):
        return False


@pytest.mark.skipif(not _ollama_available(), reason="Ollama not running")
def test_model_answers_over_http():
    payload = json.dumps(
        {"model": MODEL, "prompt": "Reply with the single word OK.", "stream": False}
    ).encode()
    req = urllib.request.Request(
        OLLAMA_URL, data=payload, headers={"Content-Type": "application/json"}
    )
    with urllib.request.urlopen(req, timeout=60) as resp:
        body = json.loads(resp.read())

    assert "response" in body
    assert body["response"].strip()
```

- [ ] **Step 4: Run it**

Run: `pytest tests/test_ollama_smoke.py -v`
Expected: PASS locally. In CI it SKIPS, which is correct — CI has no Ollama.

- [ ] **Step 5: Commit**

```bash
git add tests/test_ollama_smoke.py
git commit -m "test: Ollama reachability smoke test, skipped when absent"
```

---

### Task 3: CI with security scanning

**Linear:** M0 · `GhostLogic: CI pipeline with lint, tests and security scans`

**Files:**
- Create: `.github/workflows/ci.yml`, `.github/workflows/codeql.yml`, `.github/dependabot.yml`

- [ ] **Step 1: Write `.github/workflows/ci.yml`**

Python 3.14 is pinned here because Task 1 proved pymodbus 3.6.9 works on it. Pin the minor version `"3.14"`, never a patch like `"3.14.6"` — the local venv already drifted a patch release when Homebrew upgraded underneath it.

```yaml
name: CI

on:
  push:
    branches: [main, "build/**"]
  pull_request:

permissions:
  contents: read

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.14"
          cache: pip
      - run: pip install -r requirements-dev.txt
      - name: Lint
        run: ruff check .
      - name: Tests
        run: pytest -v

  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - uses: actions/setup-python@v5
        with:
          python-version: "3.14"
      - run: pip install -r requirements-dev.txt
      - name: Dependency CVEs
        run: pip-audit -r requirements.txt
      - name: Python SAST
        run: bandit -r ghostlogic/ -ll
      - name: Secret scan
        uses: gitleaks/gitleaks-action@v2
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

`bandit -ll` reports medium severity and above. The proxy binds a socket, which bandit flags at low severity; that is expected and not worth failing a build over.

- [ ] **Step 2: Write `.github/workflows/codeql.yml`**

```yaml
name: CodeQL

on:
  push:
    branches: [main, "build/**"]
  pull_request:
  schedule:
    - cron: "0 3 * * 1"

permissions:
  contents: read
  security-events: write

jobs:
  analyze:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: github/codeql-action/init@v3
        with:
          languages: python
      - uses: github/codeql-action/analyze@v3
```

- [ ] **Step 3: Write `.github/dependabot.yml`**

```yaml
version: 2
updates:
  - package-ecosystem: pip
    directory: "/"
    schedule:
      interval: weekly
  - package-ecosystem: github-actions
    directory: "/"
    schedule:
      interval: weekly
```

- [ ] **Step 4: Verify locally before pushing**

```bash
ruff format . && ruff check . && pytest -v && bandit -r ghostlogic/ -ll
```

`ruff format` is available but deliberately not enforced in CI — a red build over
whitespace costs you time you do not have this week.

Expected: all pass.

- [ ] **Step 5: Commit, push, confirm green**

```bash
git add .github/
git commit -m "ci: lint, tests, CodeQL, pip-audit, bandit, gitleaks, dependabot"
git push
gh run watch
```

Expected: both jobs green. A red build here means CI is broken, not the code — fix it now, while there is nothing else to blame.

---

## Milestone M1 — Pipeline live (by Aug 20)

### Task 4: The tag dictionary and its loader

**Linear:** M1 · `GhostLogic: tags.yaml and validated config loader`

**Files:**
- Create: `tags.yaml`, `ghostlogic/config.py`
- Test: `tests/test_config.py`

**Interfaces:**
- Consumes: nothing.
- Produces: `Tag(kind, addr, name, init, unit, safe, protective, must_stay, readback, impact)`, `Physics(tick_ms, approach, ambient, gain, flow_factor)`, `Config(plant_host, plant_port, proxy_host, proxy_port, physics, tags)` where `tags` is `dict[(kind, addr) -> Tag]`; `Config.by_name(name) -> Tag`; `Config.addr_of(name) -> int`; `load_config(path) -> Config`.

- [ ] **Step 1: Write `tags.yaml`**

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
    impact: "Pump driven outside its safe operating envelope"
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
    impact: "High-pressure protection setpoint moved away from its design value"
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

- [ ] **Step 2: Write the failing test**

`tests/test_config.py`:

```python
import pytest

from ghostlogic.config import load_config

BAD_DUPLICATE = """
plant:   { host: 127.0.0.1, port: 5502 }
proxy:   { host: 127.0.0.1, port: 5020 }
physics: { tick_ms: 250, approach: 0.08, ambient: 5, gain: 1.0, flow_factor: 0.95 }
tags:
  - { kind: coil, addr: 1, name: A, init: 1 }
  - { kind: coil, addr: 1, name: B, init: 0 }
"""

BAD_PROTECTIVE = """
plant:   { host: 127.0.0.1, port: 5502 }
proxy:   { host: 127.0.0.1, port: 5020 }
physics: { tick_ms: 250, approach: 0.08, ambient: 5, gain: 1.0, flow_factor: 0.95 }
tags:
  - { kind: coil, addr: 1, name: A, init: 1, protective: true }
"""


def test_loads_the_real_dictionary():
    cfg = load_config("tags.yaml")

    assert cfg.plant_port == 5502
    assert cfg.proxy_port == 5020
    assert cfg.physics.ambient == 5
    assert len(cfg.tags) == 7

    speed = cfg.by_name("PMP101_SPEED_CMD")
    assert speed.kind == "holding"
    assert speed.addr == 0
    assert speed.init == 55
    assert speed.safe == (0, 80)

    trip = cfg.by_name("HP_TRIP_ENABLE")
    assert trip.protective is True
    assert trip.must_stay == 1

    assert cfg.by_name("PT101_PRESSURE").readback is True
    assert cfg.addr_of("HP_TRIP_SETPOINT") == 3
    assert cfg.tags[("coil", 1)].name == "HP_TRIP_ENABLE"


def test_duplicate_address_is_rejected(tmp_path):
    path = tmp_path / "dup.yaml"
    path.write_text(BAD_DUPLICATE)
    with pytest.raises(ValueError, match="duplicate"):
        load_config(path)


def test_protective_tag_without_must_stay_is_rejected(tmp_path):
    path = tmp_path / "bad.yaml"
    path.write_text(BAD_PROTECTIVE)
    with pytest.raises(ValueError, match="must_stay"):
        load_config(path)


def test_unknown_tag_name_raises():
    cfg = load_config("tags.yaml")
    with pytest.raises(KeyError):
        cfg.by_name("NOPE")
```

- [ ] **Step 3: Run it to see it fail**

Run: `pytest tests/test_config.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'ghostlogic.config'`

- [ ] **Step 4: Write `ghostlogic/config.py`**

```python
"""Load and validate tags.yaml.

This file is the single source of truth for the demo: plant.py seeds its
registers from it and detect.py builds its rules from it, so the simulation
and the detection logic cannot drift apart.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import yaml

HOLDING = "holding"
COIL = "coil"
KINDS = (HOLDING, COIL)


@dataclass(frozen=True)
class Tag:
    kind: str
    addr: int
    name: str
    init: int
    unit: str = ""
    safe: tuple[int, int] | None = None
    protective: bool = False
    must_stay: int | None = None
    readback: bool = False
    impact: str = ""


@dataclass(frozen=True)
class Physics:
    tick_ms: int
    approach: float
    ambient: int
    gain: float
    flow_factor: float


@dataclass(frozen=True)
class Config:
    plant_host: str
    plant_port: int
    proxy_host: str
    proxy_port: int
    physics: Physics
    tags: dict[tuple[str, int], Tag]

    def by_name(self, name: str) -> Tag:
        for tag in self.tags.values():
            if tag.name == name:
                return tag
        raise KeyError(f"no tag named {name}")

    def addr_of(self, name: str) -> int:
        return self.by_name(name).addr


def _parse_tag(raw: dict) -> Tag:
    kind = raw["kind"]
    if kind not in KINDS:
        raise ValueError(f"tag {raw.get('name')}: kind must be one of {KINDS}")

    safe = raw.get("safe")
    if safe is not None:
        if len(safe) != 2 or safe[0] > safe[1]:
            raise ValueError(f"tag {raw['name']}: safe must be [low, high]")
        safe = (int(safe[0]), int(safe[1]))

    protective = bool(raw.get("protective", False))
    must_stay = raw.get("must_stay")
    if protective and must_stay is None:
        raise ValueError(f"tag {raw['name']}: protective tags need must_stay")

    return Tag(
        kind=kind,
        addr=int(raw["addr"]),
        name=raw["name"],
        init=int(raw["init"]),
        unit=raw.get("unit", ""),
        safe=safe,
        protective=protective,
        must_stay=must_stay,
        readback=bool(raw.get("readback", False)),
        impact=raw.get("impact", ""),
    )


def load_config(path: str | Path) -> Config:
    data = yaml.safe_load(Path(path).read_text())

    tags: dict[tuple[str, int], Tag] = {}
    for raw in data["tags"]:
        tag = _parse_tag(raw)
        key = (tag.kind, tag.addr)
        if key in tags:
            raise ValueError(f"duplicate tag address {key}")
        tags[key] = tag

    return Config(
        plant_host=data["plant"]["host"],
        plant_port=int(data["plant"]["port"]),
        proxy_host=data["proxy"]["host"],
        proxy_port=int(data["proxy"]["port"]),
        physics=Physics(**data["physics"]),
        tags=tags,
    )
```

- [ ] **Step 5: Run the tests**

Run: `pytest tests/test_config.py -v`
Expected: 4 passed.

- [ ] **Step 6: Commit**

```bash
git add tags.yaml ghostlogic/config.py tests/test_config.py
git commit -m "feat: tag dictionary and validated config loader"
```

---

### Task 5: The plant as a Modbus server

**Linear:** M1 · `GhostLogic: Modbus server seeded from the tag dictionary`

**Files:**
- Create: `ghostlogic/plant.py`
- Test: `tests/test_plant_server.py`

**Interfaces:**
- Consumes: `load_config`, `Config`, `Tag` from Task 4.
- Produces: `build_context(cfg) -> ModbusServerContext`; `Plant(cfg, speed=1.0)` with `.context`, `.start()`, `.stop()`, `.pressure` (float), `.tripped` (bool). `Plant.tick()` arrives in Task 6.

- [ ] **Step 1: Write the failing test**

`tests/test_plant_server.py`:

```python
import time

import pytest
from pymodbus.client import ModbusTcpClient

from ghostlogic.config import load_config
from ghostlogic.plant import Plant


@pytest.fixture(scope="module")
def running_plant():
    cfg = load_config("tags.yaml")
    plant = Plant(cfg)
    plant.start()
    yield cfg, plant
    plant.stop()


def _connect(cfg, attempts=20):
    for _ in range(attempts):
        client = ModbusTcpClient(cfg.plant_host, port=cfg.plant_port)
        if client.connect():
            return client
        time.sleep(0.1)
    raise AssertionError("plant never accepted a connection")


def test_registers_start_at_their_configured_values(running_plant):
    cfg, _ = running_plant
    client = _connect(cfg)
    try:
        regs = client.read_holding_registers(0, count=4, slave=1)
        assert regs.registers == [55, 52, 60, 95]

        coils = client.read_coils(0, count=3, slave=1)
        assert coils.bits[:3] == [True, True, True]
    finally:
        client.close()


def test_a_write_lands_in_the_datastore(running_plant):
    cfg, plant = running_plant
    client = _connect(cfg)
    try:
        client.write_coil(cfg.addr_of("HP_TRIP_ENABLE"), False, slave=1)
        assert plant.context[0].getValues(1, 1, count=1) == [0]
    finally:
        client.close()
```

- [ ] **Step 2: Run it to see it fail**

Run: `pytest tests/test_plant_server.py -v`
Expected: FAIL — no module named `ghostlogic.plant`.

- [ ] **Step 3: Write `ghostlogic/plant.py`**

```python
"""The plant: a Modbus/TCP pump skid with its own protective trip.

The trip lives here, inside the device, exactly where a real one would.
That is what makes the demo honest: switching the trip off does not disable
a detection rule, it removes a real protection from a real controller.
"""

from __future__ import annotations

import threading

from pymodbus.datastore import (
    ModbusSequentialDataBlock,
    ModbusServerContext,
    ModbusSlaveContext,
)
from pymodbus.server import StartTcpServer

from ghostlogic.config import COIL, HOLDING, Config

FC_COIL = 1
FC_HOLDING = 3


def build_context(cfg: Config) -> ModbusServerContext:
    """Seed the datastore from the tag dictionary, in address order."""
    holdings = [t for t in cfg.tags.values() if t.kind == HOLDING]
    coils = [t for t in cfg.tags.values() if t.kind == COIL]

    hr = [t.init for t in sorted(holdings, key=lambda t: t.addr)]
    co = [t.init for t in sorted(coils, key=lambda t: t.addr)]

    slave = ModbusSlaveContext(
        co=ModbusSequentialDataBlock(0, co),
        hr=ModbusSequentialDataBlock(0, hr),
        zero_mode=True,
    )
    return ModbusServerContext(slaves=slave, single=True)


class Plant:
    """Holds the process state and runs the simulation."""

    def __init__(self, cfg: Config, speed: float = 1.0) -> None:
        self.cfg = cfg
        self.speed = speed
        self.context = build_context(cfg)
        self.pressure = float(cfg.by_name("PT101_PRESSURE").init)
        self.tripped = False

        self._a_speed = cfg.addr_of("PMP101_SPEED_CMD")
        self._a_flow = cfg.addr_of("FT101_FLOW")
        self._a_pressure = cfg.addr_of("PT101_PRESSURE")
        self._a_setpoint = cfg.addr_of("HP_TRIP_SETPOINT")
        self._a_run = cfg.addr_of("PMP101_RUN")
        self._a_trip_en = cfg.addr_of("HP_TRIP_ENABLE")
        self._a_valve = cfg.addr_of("XV101_VALVE_OPEN")

        self._stop = threading.Event()
        self._threads: list[threading.Thread] = []

    # --- register helpers -------------------------------------------------
    def _get(self, fc: int, addr: int) -> int:
        return self.context[0].getValues(fc, addr, count=1)[0]

    def _set(self, fc: int, addr: int, value: int) -> None:
        self.context[0].setValues(fc, addr, [int(value)])

    # --- lifecycle --------------------------------------------------------
    def start(self) -> None:
        server = threading.Thread(target=self._serve, daemon=True)
        server.start()
        self._threads.append(server)

    def _serve(self) -> None:
        StartTcpServer(
            context=self.context,
            address=(self.cfg.plant_host, self.cfg.plant_port),
        )

    def stop(self) -> None:
        self._stop.set()
```

`StartTcpServer` blocks forever, so it runs on a daemon thread and dies with the process. That is acceptable here: the plant is a simulation, and no test asserts on shutdown.

- [ ] **Step 4: Run the tests**

Run: `pytest tests/test_plant_server.py -v`
Expected: 2 passed.

- [ ] **Step 5: Commit**

```bash
git add ghostlogic/plant.py tests/test_plant_server.py
git commit -m "feat: Modbus server seeded from the tag dictionary"
```

---

### Task 6: Physics and the trip

**Linear:** M1 · `GhostLogic: pressure physics and high-pressure trip logic`

**Files:**
- Modify: `ghostlogic/plant.py`
- Test: `tests/test_physics.py`

**Interfaces:**
- Consumes: `Plant` from Task 5.
- Produces: `Plant.tick()` advancing the simulation one step; `Plant.run_physics()` looping until stopped; `Plant.start()` now also starts the physics thread.

- [ ] **Step 1: Write the failing test**

`tests/test_physics.py`:

```python
"""The numbers that make the demo tell its own story.

Legal operation must never be able to trip the plant, and the attack must
be able to sail past the trip point once the trip is switched off.
"""

from ghostlogic.config import load_config
from ghostlogic.plant import FC_COIL, FC_HOLDING, Plant


def _plant():
    return Plant(load_config("tags.yaml"))


def _settle(plant, ticks=400):
    for _ in range(ticks):
        plant.tick()


def test_top_of_the_safe_band_stays_below_the_trip():
    plant = _plant()
    plant._set(FC_HOLDING, plant._a_speed, 80)
    _settle(plant)

    assert 84 <= plant.pressure <= 86
    assert plant.pressure < 95
    assert plant.tripped is False
    assert plant._get(FC_COIL, plant._a_run) == 1


def test_starting_speed_settles_at_sixty():
    plant = _plant()
    _settle(plant)
    assert 59 <= plant.pressure <= 61


def test_overspeed_with_the_trip_armed_stops_the_pump():
    plant = _plant()
    plant._set(FC_HOLDING, plant._a_speed, 110)
    _settle(plant)

    assert plant.tripped is True
    assert plant._get(FC_COIL, plant._a_run) == 0
    assert plant._get(FC_HOLDING, plant._a_speed) == 0


def test_overspeed_with_the_trip_disabled_runs_away():
    plant = _plant()
    plant._set(FC_COIL, plant._a_trip_en, 0)
    plant._set(FC_HOLDING, plant._a_speed, 110)
    _settle(plant)

    assert plant.tripped is False
    assert 114 <= plant.pressure <= 116
    assert plant._get(FC_COIL, plant._a_run) == 1


def test_registers_hold_whole_numbers():
    plant = _plant()
    plant._set(FC_HOLDING, plant._a_speed, 70)
    _settle(plant)

    pressure = plant._get(FC_HOLDING, plant._a_pressure)
    flow = plant._get(FC_HOLDING, plant._a_flow)
    assert isinstance(pressure, int)
    assert pressure == 75
    assert flow == 66


def test_closing_the_valve_drops_pressure_to_ambient():
    plant = _plant()
    plant._set(FC_COIL, plant._a_valve, 0)
    _settle(plant)

    assert 4 <= plant.pressure <= 6
    assert plant._get(FC_HOLDING, plant._a_flow) == 0
```

- [ ] **Step 2: Run it to see it fail**

Run: `pytest tests/test_physics.py -v`
Expected: FAIL — `Plant` has no attribute `tick`.

- [ ] **Step 3: Add the physics to `ghostlogic/plant.py`**

Add `import time` at the top, then these methods to `Plant`:

```python
    # --- simulation -------------------------------------------------------
    def tick(self) -> None:
        """Advance the process one step. Pure state, no I/O."""
        p = self.cfg.physics

        speed = self._get(FC_HOLDING, self._a_speed)
        setpoint = self._get(FC_HOLDING, self._a_setpoint)
        running = self._get(FC_COIL, self._a_run)
        trip_armed = self._get(FC_COIL, self._a_trip_en)
        valve_open = self._get(FC_COIL, self._a_valve)

        if running and valve_open:
            target = p.ambient + speed * p.gain
            flow = speed * p.flow_factor
        else:
            target = float(p.ambient)
            flow = 0.0

        self.pressure += (target - self.pressure) * p.approach

        if trip_armed and self.pressure >= setpoint:
            self._set(FC_COIL, self._a_run, 0)
            self._set(FC_HOLDING, self._a_speed, 0)
            self.tripped = True

        self._set(FC_HOLDING, self._a_pressure, round(self.pressure))
        self._set(FC_HOLDING, self._a_flow, round(flow))

    def run_physics(self) -> None:
        interval = (self.cfg.physics.tick_ms / 1000.0) / self.speed
        while not self._stop.is_set():
            self.tick()
            time.sleep(interval)
```

Then extend `start()` so the physics run alongside the server:

```python
    def start(self) -> None:
        server = threading.Thread(target=self._serve, daemon=True)
        physics = threading.Thread(target=self.run_physics, daemon=True)
        server.start()
        physics.start()
        self._threads.extend([server, physics])
```

- [ ] **Step 4: Run the tests**

Run: `pytest tests/test_physics.py -v`
Expected: 6 passed.

If `test_registers_hold_whole_numbers` gives 76 instead of 75, the pressure has overshot because `approach` compounds — check that `tick` adds the delta rather than assigning the target.

- [ ] **Step 5: Commit**

```bash
git add ghostlogic/plant.py tests/test_physics.py
git commit -m "feat: pressure physics and in-plant high-pressure trip"
```

---

### Task 7: Decode writes, survive bad frames

**Linear:** M1 · `GhostLogic: Modbus dissector for write commands`

**Files:**
- Create: `ghostlogic/dissect.py`
- Test: `tests/test_dissect_writes.py`

**Interfaces:**
- Consumes: nothing.
- Produces: constants `C_TO_P = "c->p"`, `P_TO_C = "p->c"`; `WriteEvent(kind, addr, value, func, txn, raw_hex)`; `Dissector()` with `.feed(conn, direction, raw) -> list[WriteEvent | ValueUpdate]` (conn identifies the TCP connection), `.frames: int`, `.malformed: int`. `ValueUpdate` arrives in Task 8.

- [ ] **Step 1: Create the shared frame builders**

`tests/__init__.py` (empty file, so `tests.helpers` is importable):

```python
```

`tests/helpers.py`:

```python
"""Modbus frame builders shared by the dissector tests."""

import struct

CONN = "c1"  # a single client connection; see the two-connection test


def mbap(pdu: bytes, txn: int = 1, unit: int = 1) -> bytes:
    """Wrap a PDU in an MBAP header. Length counts the unit byte plus PDU."""
    return struct.pack(">HHHB", txn, 0, len(pdu) + 1, unit) + pdu


def write_coil(addr: int, on: bool, txn: int = 1) -> bytes:
    return mbap(struct.pack(">BHH", 0x05, addr, 0xFF00 if on else 0x0000), txn)


def write_register(addr: int, value: int, txn: int = 1) -> bytes:
    return mbap(struct.pack(">BHH", 0x06, addr, value), txn)
```

- [ ] **Step 2: Write the failing test**

`tests/test_dissect_writes.py`:

```python
"""Three defects in the starter dissector, each pinned by a test."""

import struct

from ghostlogic.dissect import C_TO_P, P_TO_C, Dissector, WriteEvent
from tests.helpers import CONN, mbap, write_coil, write_register


def test_write_single_coil_decodes():
    d = Dissector()
    events = d.feed(CONN, C_TO_P, write_coil(1, False))

    assert events == [
        WriteEvent(kind="coil", addr=1, value=0, func=0x05, txn=1,
                   raw_hex=write_coil(1, False).hex())
    ]
    assert d.malformed == 0


def test_write_single_register_decodes():
    d = Dissector()
    events = d.feed(CONN, C_TO_P, write_register(0, 110, txn=7))

    assert len(events) == 1
    assert events[0].kind == "holding"
    assert events[0].addr == 0
    assert events[0].value == 110
    assert events[0].txn == 7


def test_two_frames_in_one_chunk_both_decode():
    d = Dissector()
    events = d.feed(CONN, C_TO_P, write_register(0, 70) + write_coil(1, False))

    assert len(events) == 2
    assert events[0].value == 70
    assert events[1].kind == "coil"


def test_a_frame_split_across_two_chunks_is_not_lost():
    """The starter kit dropped these. This is the fix."""
    d = Dissector()
    frame = write_register(0, 110)

    assert d.feed(CONN, C_TO_P, frame[:5]) == []
    events = d.feed(CONN, C_TO_P, frame[5:])

    assert len(events) == 1
    assert events[0].value == 110
    assert d.malformed == 0


def test_a_frame_split_into_many_chunks_is_not_lost():
    d = Dissector()
    frame = write_coil(1, False)
    collected = []
    for i in range(len(frame)):
        collected += d.feed(CONN, C_TO_P, frame[i : i + 1])

    assert len(collected) == 1
    assert collected[0].value == 0


def test_two_connections_do_not_corrupt_each_other():
    """The HMI and the attacker are separate TCP connections through one tap.

    Without per-connection buffering, this interleaving produces garbage and a
    false malformed count — a race that would make the demo flaky.
    """
    d = Dissector()
    a, b = write_register(0, 70, txn=1), write_coil(1, False, txn=1)

    assert d.feed("hmi", C_TO_P, a[:5]) == []
    assert d.feed("attacker", C_TO_P, b[:5]) == []
    from_a = d.feed("hmi", C_TO_P, a[5:])
    from_b = d.feed("attacker", C_TO_P, b[5:])

    assert [e.value for e in from_a] == [70]
    assert [e.value for e in from_b] == [0]
    assert d.malformed == 0


def test_write_multiple_registers_decodes_each_value():
    d = Dissector()
    pdu = struct.pack(">BHHB", 0x10, 0, 2, 4) + struct.pack(">HH", 70, 52)
    events = d.feed(CONN, C_TO_P, mbap(pdu))

    assert [(e.addr, e.value) for e in events] == [(0, 70), (1, 52)]


def test_write_multiple_coils_decodes_each_bit():
    d = Dissector()
    pdu = struct.pack(">BHHB", 0x0F, 0, 3, 1) + bytes([0b00000101])
    events = d.feed(CONN, C_TO_P, mbap(pdu))

    assert [(e.addr, e.value) for e in events] == [(0, 1), (1, 0), (2, 1)]


def test_a_lying_byte_count_is_counted_not_crashed():
    """The starter kit raised here, which would blind the capture thread."""
    d = Dissector()
    pdu = struct.pack(">BHHB", 0x10, 0, 8, 4) + b"\x00\x46"

    events = d.feed(CONN, C_TO_P, mbap(pdu))

    assert events == []
    assert d.malformed == 1


def test_a_truncated_pdu_is_counted_not_crashed():
    d = Dissector()
    events = d.feed(CONN, C_TO_P, mbap(struct.pack(">BH", 0x06, 0)))

    assert events == []
    assert d.malformed == 1


def test_a_non_modbus_protocol_id_is_rejected():
    d = Dissector()
    events = d.feed(CONN, C_TO_P, struct.pack(">HHHB", 1, 99, 6, 1) + b"\x06\x00\x00\x00\x46")

    assert events == []
    assert d.malformed == 1


def test_exception_responses_are_ignored():
    d = Dissector()
    assert d.feed(CONN, P_TO_C, mbap(struct.pack(">BB", 0x86, 0x02))) == []


def test_writes_from_the_plant_side_are_ignored():
    """Only client-to-plant traffic carries commands."""
    d = Dissector()
    assert d.feed(CONN, P_TO_C, write_coil(1, False)) == []
```

- [ ] **Step 3: Run it to see it fail**

Run: `pytest tests/test_dissect_writes.py -v`
Expected: FAIL — no module named `ghostlogic.dissect`.

- [ ] **Step 4: Write `ghostlogic/dissect.py`**

```python
"""Turn captured bytes into structured events.

TCP does not respect message boundaries: one read can hold two Modbus frames,
or half of one. The starter kit assumed the tidy case and silently dropped
split frames, so an attacker whose write happened to land across a packet
boundary was invisible. This dissector buffers per direction instead.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

C_TO_P = "c->p"
P_TO_C = "p->c"

WRITE_FUNCS = frozenset({0x05, 0x06, 0x0F, 0x10})
READ_FUNCS = frozenset({0x01, 0x03})
MAX_LENGTH = 254
MBAP_SIZE = 7


@dataclass(frozen=True)
class WriteEvent:
    kind: str
    addr: int
    value: int
    func: int
    txn: int
    raw_hex: str


class Dissector:
    """Buffers per (connection, direction).

    The proxy taps several TCP connections at once — in the demo the HMI and
    the attacker are two separate clients. Buffering per direction alone would
    interleave their byte streams: a partial frame from one client followed by
    bytes from the other yields a corrupted frame and a false malformed count.
    Transaction IDs collide the same way, since every client starts at 1.
    """

    def __init__(self) -> None:
        self._buf: dict[tuple[str, str], bytes] = {}
        self._pending: dict[tuple[str, int], tuple[int, int, int]] = {}
        self.frames = 0
        self.malformed = 0

    def feed(self, conn: str, direction: str, raw: bytes) -> list:
        """Decode whatever complete frames this chunk completes."""
        events: list = []
        buf = self._buf.get((conn, direction), b"") + raw

        while len(buf) >= MBAP_SIZE:
            txn, proto, length, _unit = struct.unpack(">HHHB", buf[:MBAP_SIZE])

            if proto != 0 or length < 2 or length > MAX_LENGTH:
                self.malformed += 1
                buf = b""  # the stream is out of step; resynchronising is not worth it
                break

            total = 6 + length
            if len(buf) < total:
                break  # incomplete frame — keep it and wait for the rest

            frame, buf = buf[:total], buf[total:]
            self.frames += 1
            try:
                events.extend(self._handle(conn, direction, txn, frame))
            except (struct.error, IndexError, ValueError):
                self.malformed += 1

        self._buf[(conn, direction)] = buf
        return events

    def _handle(self, conn: str, direction: str, txn: int, frame: bytes) -> list:
        pdu = frame[MBAP_SIZE:]
        if not pdu:
            raise ValueError("empty pdu")

        func, data = pdu[0], pdu[1:]
        if func & 0x80:
            return []  # exception response

        if direction == C_TO_P:
            if func in WRITE_FUNCS:
                return self._writes(func, data, txn, frame)
            if func in READ_FUNCS:
                start, qty = struct.unpack(">HH", data[:4])
                self._pending[(conn, txn)] = (func, start, qty)
            return []

        return []  # replies are handled in Task 8

    def _writes(self, func: int, data: bytes, txn: int, frame: bytes) -> list[WriteEvent]:
        raw_hex = frame.hex()

        if func == 0x05:
            addr, value = struct.unpack(">HH", data[:4])
            return [WriteEvent("coil", addr, 1 if value == 0xFF00 else 0, func, txn, raw_hex)]

        if func == 0x06:
            addr, value = struct.unpack(">HH", data[:4])
            return [WriteEvent("holding", addr, value, func, txn, raw_hex)]

        if func == 0x10:
            start, qty, count = struct.unpack(">HHB", data[:5])
            if count != qty * 2 or len(data) < 5 + count:
                raise ValueError("byte count does not match quantity")
            values = struct.unpack(">" + "H" * qty, data[5 : 5 + count])
            return [
                WriteEvent("holding", start + i, v, func, txn, raw_hex)
                for i, v in enumerate(values)
            ]

        start, qty, count = struct.unpack(">HHB", data[:5])
        if count != (qty + 7) // 8 or len(data) < 5 + count:
            raise ValueError("byte count does not match quantity")
        bits = data[5 : 5 + count]
        return [
            WriteEvent("coil", start + i, (bits[i // 8] >> (i % 8)) & 1, func, txn, raw_hex)
            for i in range(qty)
        ]
```

- [ ] **Step 5: Run the tests**

Run: `pytest tests/test_dissect_writes.py -v`
Expected: 12 passed.

- [ ] **Step 6: Commit**

```bash
git add ghostlogic/dissect.py tests/__init__.py tests/helpers.py tests/test_dissect_writes.py
git commit -m "feat: Modbus write dissector with frame reassembly and malformed-frame guards"
```

---

### Task 8: Learn the plant state passively from read replies

This is what lets you say GhostLogic never originates a packet to the plant. The live values on the dashboard come from the HMI's own polling traffic.

**Linear:** M1 · `GhostLogic: decode read replies into live tag values`

**Files:**
- Modify: `ghostlogic/dissect.py`
- Test: `tests/test_dissect_reads.py`

**Interfaces:**
- Consumes: `Dissector` from Task 7.
- Produces: `ValueUpdate(kind, addr, value)`, returned from `.feed()` alongside `WriteEvent`s.

- [ ] **Step 1: Write the failing test**

`tests/test_dissect_reads.py`:

```python
import struct

from ghostlogic.dissect import C_TO_P, P_TO_C, Dissector, ValueUpdate
from tests.helpers import CONN, mbap


def read_holding_request(start: int, qty: int, txn: int = 3) -> bytes:
    return mbap(struct.pack(">BHH", 0x03, start, qty), txn)


def read_holding_reply(values: list[int], txn: int = 3) -> bytes:
    body = struct.pack(">" + "H" * len(values), *values)
    return mbap(struct.pack(">BB", 0x03, len(body)) + body, txn)


def read_coils_request(start: int, qty: int, txn: int = 4) -> bytes:
    return mbap(struct.pack(">BHH", 0x01, start, qty), txn)


def read_coils_reply(bits: list[int], txn: int = 4) -> bytes:
    packed = 0
    for i, bit in enumerate(bits):
        packed |= (bit & 1) << i
    return mbap(struct.pack(">BB", 0x01, 1) + bytes([packed]), txn)


def test_a_holding_reply_becomes_live_values():
    d = Dissector()
    d.feed(CONN, C_TO_P, read_holding_request(0, 4))
    events = d.feed(CONN, P_TO_C, read_holding_reply([70, 66, 75, 95]))

    assert events == [
        ValueUpdate("holding", 0, 70),
        ValueUpdate("holding", 1, 66),
        ValueUpdate("holding", 2, 75),
        ValueUpdate("holding", 3, 95),
    ]


def test_a_coil_reply_becomes_live_values():
    d = Dissector()
    d.feed(CONN, C_TO_P, read_coils_request(0, 3))
    events = d.feed(CONN, P_TO_C, read_coils_reply([1, 0, 1]))

    assert events == [
        ValueUpdate("coil", 0, 1),
        ValueUpdate("coil", 1, 0),
        ValueUpdate("coil", 2, 1),
    ]


def test_a_reply_without_its_request_is_ignored():
    """We cannot know which addresses it refers to, so we must not guess."""
    d = Dissector()
    assert d.feed(CONN, P_TO_C, read_holding_reply([70, 66, 75, 95])) == []


def test_replies_are_matched_by_transaction_id():
    d = Dissector()
    d.feed(CONN, C_TO_P, read_holding_request(0, 1, txn=11))
    d.feed(CONN, C_TO_P, read_holding_request(3, 1, txn=12))

    second = d.feed(CONN, P_TO_C, read_holding_reply([95], txn=12))
    first = d.feed(CONN, P_TO_C, read_holding_reply([70], txn=11))

    assert second == [ValueUpdate("holding", 3, 95)]
    assert first == [ValueUpdate("holding", 0, 70)]


def test_a_reply_that_contradicts_its_request_is_counted_malformed():
    d = Dissector()
    d.feed(CONN, C_TO_P, read_holding_request(0, 4))
    events = d.feed(CONN, P_TO_C, read_holding_reply([70]))

    assert events == []
    assert d.malformed == 1


def test_a_split_reply_is_not_lost():
    d = Dissector()
    d.feed(CONN, C_TO_P, read_holding_request(0, 4))
    reply = read_holding_reply([70, 66, 75, 95])

    assert d.feed(CONN, P_TO_C, reply[:6]) == []
    assert len(d.feed(CONN, P_TO_C, reply[6:])) == 4
```

- [ ] **Step 2: Run it to see it fail**

Run: `pytest tests/test_dissect_reads.py -v`
Expected: FAIL — cannot import `ValueUpdate`.

- [ ] **Step 3: Extend `ghostlogic/dissect.py`**

Add the dataclass next to `WriteEvent`:

```python
@dataclass(frozen=True)
class ValueUpdate:
    kind: str
    addr: int
    value: int
```

Replace the final line of `_handle` (`return []  # replies are handled in Task 8`) with:

```python
        pending = self._pending.pop((conn, txn), None)
        if pending is None or pending[0] != func:
            return []
        return self._reply_values(func, data, pending)
```

And add the decoder:

```python
    def _reply_values(self, func: int, data: bytes, pending: tuple[int, int, int]) -> list[ValueUpdate]:
        _, start, qty = pending
        count = data[0]
        body = data[1 : 1 + count]
        if len(body) < count:
            raise ValueError("short reply body")

        if func == 0x03:
            if count != qty * 2:
                raise ValueError("reply byte count does not match the request")
            values = struct.unpack(">" + "H" * qty, body)
            return [ValueUpdate("holding", start + i, v) for i, v in enumerate(values)]

        if count != (qty + 7) // 8:
            raise ValueError("reply byte count does not match the request")
        return [
            ValueUpdate("coil", start + i, (body[i // 8] >> (i % 8)) & 1) for i in range(qty)
        ]
```

- [ ] **Step 4: Run the whole dissector suite**

Run: `pytest tests/test_dissect_writes.py tests/test_dissect_reads.py -v`
Expected: 18 passed.

- [ ] **Step 5: Commit**

```bash
git add ghostlogic/dissect.py tests/test_dissect_reads.py
git commit -m "feat: decode read replies into live tag values, matched by transaction id"
```

---

### Task 9: The capture seam and the live proxy

**Linear:** M1 · `GhostLogic: capture source interface, live proxy and frame recorder`

**Files:**
- Create: `ghostlogic/sources/__init__.py`, `ghostlogic/sources/proxy.py`
- Test: `tests/test_proxy.py`

**Interfaces:**
- Consumes: `Config` from Task 4.
- Produces: type alias `Sink = Callable[[str, str, bytes, float], None]` — `sink(conn, direction, raw, ts)`, where conn identifies the TCP connection (the proxy uses `host:port` of the client); `Recorder(path, inner)` callable as a sink with `.close()`; `proxy.serve(cfg, sink, stop, ready=None)` blocking until `stop` is set.

- [ ] **Step 1: Write the failing test**

`tests/test_proxy.py`:

```python
"""The proxy is a laptop convenience and it is NOT passive — bytes flow
through it. The production answer is a mirror-port sniff behind the same
interface. These tests pin the interface, not the plumbing."""

import dataclasses
import json
import socket
import threading
import time

from ghostlogic.config import load_config
from ghostlogic.sources import Recorder
from ghostlogic.sources.proxy import serve


def _echo_server(port: int, stop: threading.Event) -> None:
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port))
    srv.listen(1)
    srv.settimeout(0.5)
    while not stop.is_set():
        try:
            conn, _ = srv.accept()
        except socket.timeout:
            continue
        data = conn.recv(1024)
        conn.sendall(b"PONG:" + data)
        conn.close()
    srv.close()


def test_proxy_forwards_both_ways_and_taps_every_frame(tmp_path):
    cfg = dataclasses.replace(load_config("tags.yaml"), plant_port=15502, proxy_port=15020)

    stop = threading.Event()
    ready = threading.Event()
    seen: list[tuple[str, bytes]] = []

    threading.Thread(target=_echo_server, args=(15502, stop), daemon=True).start()
    threading.Thread(
        target=serve,
        args=(cfg, lambda c, d, raw, ts: seen.append((d, raw)), stop, ready),
        daemon=True,
    ).start()
    assert ready.wait(timeout=5)

    client = socket.create_connection(("127.0.0.1", 15020), timeout=5)
    client.sendall(b"PING")
    assert client.recv(1024) == b"PONG:PING"
    client.close()

    time.sleep(0.2)
    stop.set()

    assert ("c->p", b"PING") in seen
    assert ("p->c", b"PONG:PING") in seen


def test_recorder_writes_every_frame_as_replayable_jsonl(tmp_path):
    path = tmp_path / "run.jsonl"
    inner_calls = []
    rec = Recorder(path, lambda c, d, raw, ts: inner_calls.append((d, raw)))

    rec("c1", "c->p", b"\x01\x02", 100.0)
    rec("c1", "p->c", b"\x03", 100.5)
    rec.close()

    lines = [json.loads(line) for line in path.read_text().splitlines()]
    assert lines[0] == {"t": 0.0, "conn": "c1", "direction": "c->p", "hex": "0102"}
    assert lines[1] == {"t": 0.5, "conn": "c1", "direction": "p->c", "hex": "03"}
    assert inner_calls == [("c->p", b"\x01\x02"), ("p->c", b"\x03")]
```

- [ ] **Step 2: Run it to see it fail**

Run: `pytest tests/test_proxy.py -v`
Expected: FAIL — no module named `ghostlogic.sources`.

- [ ] **Step 3: Write `ghostlogic/sources/__init__.py`**

```python
"""The capture seam.

A source observes frames and calls a sink with (direction, raw, timestamp).
Three implementations share that one contract:

  proxy   — inline tap. Laptop convenience. NOT passive: bytes flow through it.
  replay  — a recorded run, played back at original timing. The stage parachute.
  sniff   — a mirror-port capture. The production answer, where traffic is
            copied to us and we can never delay, drop or alter anything.

Everything downstream of a sink is identical for all three.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path

# Imported, not redefined: dissect.py owns the wire vocabulary and imports
# nothing itself, so there is no cycle and no second definition to drift.
from ghostlogic.dissect import C_TO_P, P_TO_C  # noqa: F401  (re-exported)

Sink = Callable[[str, str, bytes, float], None]


class Recorder:
    """Pass frames through to `inner` while writing them for later replay."""

    def __init__(self, path: str | Path, inner: Sink) -> None:
        self._fh = Path(path).open("w")
        self._inner = inner
        self._start: float | None = None

    def __call__(self, conn: str, direction: str, raw: bytes, ts: float) -> None:
        if self._start is None:
            self._start = ts
        record = {
            "t": round(ts - self._start, 4),
            "conn": conn,
            "direction": direction,
            "hex": raw.hex(),
        }
        self._fh.write(json.dumps(record) + "\n")
        self._fh.flush()
        self._inner(conn, direction, raw, ts)

    def close(self) -> None:
        self._fh.close()
```

- [ ] **Step 4: Write `ghostlogic/sources/proxy.py`**

```python
"""Inline TCP tap: clients connect here believing it is the PLC.

Honest caveat for the pitch: this is INLINE, so it is not passive. It is a
laptop lab convenience that needs no root and no NIC mirroring. On real plant
hardware, swap it for sources/sniff.py on a mirror port.
"""

from __future__ import annotations

import socket
import threading
import time

from ghostlogic.config import Config
from ghostlogic.sources import C_TO_P, P_TO_C, Sink


def _pump(conn: str, src: socket.socket, dst: socket.socket, direction: str,
          sink: Sink, stop: threading.Event) -> None:
    try:
        while not stop.is_set():
            data = src.recv(4096)
            if not data:
                break
            sink(conn, direction, data, time.monotonic())
            dst.sendall(data)
    except OSError:
        pass
    finally:
        for sock in (src, dst):
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass


def _handle(conn: str, client: socket.socket, plant_addr: tuple[str, int],
            sink: Sink, stop: threading.Event) -> None:
    plant = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        plant.connect(plant_addr)
    except OSError:
        client.close()
        return

    threads = [
        threading.Thread(target=_pump, args=(conn, client, plant, C_TO_P, sink, stop),
                         daemon=True),
        threading.Thread(target=_pump, args=(conn, plant, client, P_TO_C, sink, stop),
                         daemon=True),
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    client.close()
    plant.close()


def serve(cfg: Config, sink: Sink, stop: threading.Event,
          ready: threading.Event | None = None) -> None:
    """Run until `stop` is set, calling `sink` for every frame in both directions."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((cfg.proxy_host, cfg.proxy_port))
    srv.listen(5)
    srv.settimeout(0.5)

    if ready is not None:
        ready.set()

    while not stop.is_set():
        try:
            client, peer = srv.accept()
        except socket.timeout:
            continue
        except OSError:
            break
        threading.Thread(
            target=_handle,
            args=(f"{peer[0]}:{peer[1]}", client, (cfg.plant_host, cfg.plant_port),
                  sink, stop),
            daemon=True,
        ).start()

    srv.close()
```

- [ ] **Step 5: Run the tests**

Run: `pytest tests/test_proxy.py -v`
Expected: 2 passed.

- [ ] **Step 6: Commit**

```bash
git add ghostlogic/sources/ tests/test_proxy.py
git commit -m "feat: capture source interface, inline proxy tap and frame recorder"
```

---

## Milestone M2 — Detection and scenario (by Aug 21)

### Task 10: The three rules

**Linear:** M2 · `GhostLogic: deterministic detection rules`

**Files:**
- Create: `ghostlogic/detect.py`
- Test: `tests/test_detect.py`

**Interfaces:**
- Consumes: `Config`, `Tag` (Task 4), `WriteEvent` (Task 7).
- Produces: `Alert(seq, ts, tag, kind, addr, value, severity, rule, attack_id, attack_name, impact, raw_hex, explanation, explain_source)` with `.to_dict()`; `evaluate(cfg, event, seq, ts) -> Alert | None`.

- [ ] **Step 1: Write the failing test**

`tests/test_detect.py`:

```python
"""The rules an engineer has to defend on stage. Keep them boring."""

from pathlib import Path

from ghostlogic.config import load_config
from ghostlogic.detect import evaluate
from ghostlogic.dissect import WriteEvent

CFG = load_config("tags.yaml")


def ev(kind: str, addr: int, value: int) -> WriteEvent:
    return WriteEvent(kind=kind, addr=addr, value=value, func=0x06, txn=1, raw_hex="deadbeef")


def test_the_legal_operator_change_stays_silent():
    """55 -> 70 is inside the safe band. This is the false-positive proof."""
    assert evaluate(CFG, ev("holding", 0, 70), 1, 0.0) is None


def test_disabling_the_trip_is_critical():
    alert = evaluate(CFG, ev("coil", 1, 0), 1, 123.0)

    assert alert is not None
    assert alert.severity == "CRITICAL"
    assert alert.tag == "HP_TRIP_ENABLE"
    assert alert.attack_id == "T0836"
    assert alert.attack_name == "Modify Parameter"
    assert "must stay 1" in alert.rule
    assert "over-pressurisation" in alert.impact
    assert alert.seq == 1
    assert alert.ts == 123.0
    assert alert.raw_hex == "deadbeef"


def test_re_arming_the_trip_is_not_an_alert():
    assert evaluate(CFG, ev("coil", 1, 1), 1, 0.0) is None


def test_overspeed_is_high():
    alert = evaluate(CFG, ev("holding", 0, 110), 2, 0.0)

    assert alert is not None
    assert alert.severity == "HIGH"
    assert alert.attack_id == "T0836"
    assert "0..80" in alert.rule


def test_moving_the_trip_setpoint_is_high():
    alert = evaluate(CFG, ev("holding", 3, 200), 1, 0.0)
    assert alert is not None
    assert alert.severity == "HIGH"
    assert alert.tag == "HP_TRIP_SETPOINT"


def test_the_safe_band_boundaries_are_inclusive():
    assert evaluate(CFG, ev("holding", 0, 80), 1, 0.0) is None
    assert evaluate(CFG, ev("holding", 0, 0), 1, 0.0) is None
    assert evaluate(CFG, ev("holding", 0, 81), 1, 0.0) is not None


def test_a_write_to_an_undocumented_address_is_low_not_silent():
    """The starter kit let these through in silence."""
    alert = evaluate(CFG, ev("holding", 99, 1), 1, 0.0)

    assert alert is not None
    assert alert.severity == "LOW"
    assert alert.attack_id == "T0855"
    assert alert.tag == "HOLDING[99]"


def test_a_write_to_a_readback_value_is_low():
    """Nobody writes the pressure transmitter's own reading."""
    alert = evaluate(CFG, ev("holding", 2, 10), 1, 0.0)

    assert alert is not None
    assert alert.severity == "LOW"
    assert alert.tag == "PT101_PRESSURE"


def test_ordinary_control_writes_stay_silent():
    assert evaluate(CFG, ev("coil", 0, 0), 1, 0.0) is None
    assert evaluate(CFG, ev("coil", 2, 0), 1, 0.0) is None


def test_an_alert_serialises_for_the_cockpit():
    alert = evaluate(CFG, ev("coil", 1, 0), 4, 9.0)
    data = alert.to_dict()

    assert data["severity"] == "CRITICAL"
    assert data["explanation"] == ""
    assert data["explain_source"] == ""
    assert set(data) >= {"seq", "ts", "tag", "kind", "addr", "value", "rule", "raw_hex"}


def test_the_rules_do_not_depend_on_the_model():
    """Structural guard: if this ever fails, the pitch is no longer true."""
    source = Path("ghostlogic/detect.py").read_text()
    assert "explain" not in source
    assert "ollama" not in source.lower()
```

- [ ] **Step 2: Run it to see it fail**

Run: `pytest tests/test_detect.py -v`
Expected: FAIL — no module named `ghostlogic.detect`.

- [ ] **Step 3: Write `ghostlogic/detect.py`**

```python
"""The deterministic detection core.

Nothing generated is imported here and nothing generated ever should be.
Severity, rule text and ATT&CK identifier come from the tag dictionary alone,
so an engineer can defend every alert without trusting a model.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass

from ghostlogic.config import Config
from ghostlogic.dissect import WriteEvent

MODIFY_PARAMETER = ("T0836", "Modify Parameter")
UNAUTHORIZED_COMMAND = ("T0855", "Unauthorized Command Message")


@dataclass(frozen=True)
class Alert:
    seq: int
    ts: float
    tag: str
    kind: str
    addr: int
    value: int
    severity: str
    rule: str
    attack_id: str
    attack_name: str
    impact: str
    raw_hex: str
    explanation: str = ""
    explain_source: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


def evaluate(cfg: Config, event: WriteEvent, seq: int, ts: float) -> Alert | None:
    """Return an Alert for a write worth raising, or None for normal operation."""
    tag = cfg.tags.get((event.kind, event.addr))

    def build(severity: str, rule: str, attack: tuple[str, str], impact: str) -> Alert:
        return Alert(
            seq=seq,
            ts=ts,
            tag=tag.name if tag else f"{event.kind.upper()}[{event.addr}]",
            kind=event.kind,
            addr=event.addr,
            value=event.value,
            severity=severity,
            rule=rule,
            attack_id=attack[0],
            attack_name=attack[1],
            impact=impact,
            raw_hex=event.raw_hex,
        )

    # Rule 1 — a protective tag forced off the value it must hold.
    if tag is not None and tag.protective and event.value != tag.must_stay:
        return build(
            "CRITICAL",
            f"Protective tag {tag.name} forced to {event.value} "
            f"(must stay {tag.must_stay})",
            MODIFY_PARAMETER,
            tag.impact,
        )

    # Rule 2 — a setpoint written outside its safe band.
    if tag is not None and tag.safe is not None:
        low, high = tag.safe
        if not low <= event.value <= high:
            return build(
                "HIGH",
                f"{tag.name} written {event.value}{tag.unit} "
                f"outside safe band {low}..{high}",
                MODIFY_PARAMETER,
                tag.impact,
            )

    # Rule 3 — a write nobody should be making at all.
    if tag is None:
        return build(
            "LOW",
            f"Write to {event.kind.upper()}[{event.addr}], "
            f"an address not in the tag dictionary",
            UNAUTHORIZED_COMMAND,
            "Undocumented write — intent unknown",
        )
    if tag.readback:
        return build(
            "LOW",
            f"Write to {tag.name}, a readback value the plant computes itself",
            UNAUTHORIZED_COMMAND,
            "Process readback overwritten — operators may be shown false values",
        )

    return None
```

- [ ] **Step 4: Run the tests**

Run: `pytest tests/test_detect.py -v`
Expected: 11 passed.

- [ ] **Step 5: Commit**

```bash
git add ghostlogic/detect.py tests/test_detect.py
git commit -m "feat: three deterministic detection rules with ATT&CK for ICS mapping"
```

---

### Task 11: The files the cockpit reads

**Linear:** M2 · `GhostLogic: atomic state.json writer and alerts.jsonl log`

**Files:**
- Create: `ghostlogic/sinks.py`
- Test: `tests/test_sinks.py`

**Interfaces:**
- Consumes: `Alert` (Task 10).
- Produces: `StateWriter(path, source_label)` with `.update(name, value)`, `.set_counters(frames, writes, malformed)`, `.write(ts)`; `AlertLog(path)` with `.append(alert)`.

- [ ] **Step 1: Write the failing test**

`tests/test_sinks.py`:

```python
import json

from ghostlogic.config import load_config
from ghostlogic.detect import evaluate
from ghostlogic.dissect import WriteEvent
from ghostlogic.sinks import AlertLog, StateWriter


def test_state_is_written_as_a_complete_document(tmp_path):
    path = tmp_path / "state.json"
    writer = StateWriter(path, "LIVE PROXY")

    writer.update("PT101_PRESSURE", 75)
    writer.update("HP_TRIP_ENABLE", 0)
    writer.set_counters(frames=412, writes=3, malformed=0)
    writer.write(1755525600.25)

    data = json.loads(path.read_text())
    assert data["source"] == "LIVE PROXY"
    assert data["ts"] == 1755525600.25
    assert data["tags"]["PT101_PRESSURE"] == 75
    assert data["tags"]["HP_TRIP_ENABLE"] == 0
    assert data["counters"] == {"frames": 412, "writes": 3, "malformed": 0}


def test_rewriting_state_never_leaves_a_partial_file(tmp_path):
    """The browser polls this file while it is being rewritten."""
    path = tmp_path / "state.json"
    writer = StateWriter(path, "LIVE PROXY")

    for i in range(50):
        writer.update("PT101_PRESSURE", 60 + i)
        writer.write(float(i))
        json.loads(path.read_text())  # would raise on a half-written file

    assert json.loads(path.read_text())["tags"]["PT101_PRESSURE"] == 109


def test_alerts_are_appended_one_json_object_per_line(tmp_path):
    cfg = load_config("tags.yaml")
    path = tmp_path / "alerts.jsonl"
    log = AlertLog(path)

    for seq, (kind, addr, value) in enumerate([("coil", 1, 0), ("holding", 0, 110)], 1):
        event = WriteEvent(kind=kind, addr=addr, value=value, func=0x06, txn=seq, raw_hex="ab")
        log.append(evaluate(cfg, event, seq, float(seq)))

    lines = [json.loads(line) for line in path.read_text().splitlines()]
    assert [line["severity"] for line in lines] == ["CRITICAL", "HIGH"]
    assert lines[0]["seq"] == 1


def test_a_new_run_starts_from_an_empty_log(tmp_path):
    path = tmp_path / "alerts.jsonl"
    path.write_text('{"stale": true}\n')

    AlertLog(path)

    assert path.read_text() == ""
```

- [ ] **Step 2: Run it to see it fail**

Run: `pytest tests/test_sinks.py -v`
Expected: FAIL — no module named `ghostlogic.sinks`.

- [ ] **Step 3: Write `ghostlogic/sinks.py`**

```python
"""Write the two files the cockpit reads.

state.json is rewritten several times a second while a browser is polling it.
It is written to a temporary file in the same directory and moved into place,
because os.replace is atomic on POSIX — the cockpit can never read half a file.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

from ghostlogic.detect import Alert


class StateWriter:
    def __init__(self, path: str | Path, source_label: str) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.source = source_label
        self.tags: dict[str, int] = {}
        self.counters = {"frames": 0, "writes": 0, "malformed": 0}

    def update(self, name: str, value: int) -> None:
        self.tags[name] = value

    def set_counters(self, frames: int, writes: int, malformed: int) -> None:
        self.counters = {"frames": frames, "writes": writes, "malformed": malformed}

    def write(self, ts: float) -> None:
        payload = {
            "ts": ts,
            "source": self.source,
            "tags": dict(self.tags),
            "counters": dict(self.counters),
        }
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(payload))
        os.replace(tmp, self.path)


class AlertLog:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text("")  # a run always starts clean

    def append(self, alert: Alert) -> None:
        with self.path.open("a") as fh:
            fh.write(json.dumps(alert.to_dict()) + "\n")
            fh.flush()
```

- [ ] **Step 4: Run the tests**

Run: `pytest tests/test_sinks.py -v`
Expected: 4 passed.

- [ ] **Step 5: Commit**

```bash
git add ghostlogic/sinks.py tests/test_sinks.py
git commit -m "feat: atomic state writer and alert log"
```

---

### Task 12: The scenario runner

**Linear:** M2 · `GhostLogic: scenario orchestrator with HMI poller and attacker`

**Files:**
- Create: `ghostlogic/scenario.py`
- Test: covered by Task 13

**Interfaces:**
- Consumes: everything from Tasks 4–11.
- Produces: `Pipeline(cfg, state, alerts, explain=None)` callable as a `Sink`, exposing `.alerts_raised: list[Alert]`; `run(cfg, speed=1.0, out_dir="out", record=None, explain=None) -> list[Alert]`; a `__main__` entry point.

- [ ] **Step 1: Write `ghostlogic/scenario.py`**

```python
"""Run the demo end to end.

Timeline (seconds, divided by `speed`):
    0   HMI starts polling
    10  operator raises pump speed 55 -> 70   legal, no alert
    25  attacker disables the high-pressure trip   CRITICAL
    40  attacker drives the pump to 110%          HIGH
    60  end. Pressure has passed the trip point with nothing to stop it.
"""

from __future__ import annotations

import argparse
import shutil
import threading
import time
from pathlib import Path

from pymodbus.client import ModbusTcpClient

from ghostlogic.config import Config, load_config
from ghostlogic.detect import Alert, evaluate
from ghostlogic.dissect import Dissector, ValueUpdate
from ghostlogic.plant import Plant
from ghostlogic.sinks import AlertLog, StateWriter
from ghostlogic.sources import Recorder
from ghostlogic.sources.proxy import serve

DURATION = 60.0
HMI_POLL_SECONDS = 0.5

# (at_second, kind, tag_name, value)
SCRIPT = [
    (10.0, "holding", "PMP101_SPEED_CMD", 70),
    (25.0, "coil", "HP_TRIP_ENABLE", 0),
    (40.0, "holding", "PMP101_SPEED_CMD", 110),
]


class Pipeline:
    """dissect -> detect -> explain -> files. Called for every captured frame."""

    def __init__(self, cfg: Config, state: StateWriter, alerts: AlertLog, explain=None) -> None:
        self.cfg = cfg
        self.state = state
        self.alerts = alerts
        self.explain = explain
        self.dissector = Dissector()
        self.alerts_raised: list[Alert] = []
        self._writes = 0
        self._seq = 0

    def __call__(self, conn: str, direction: str, raw: bytes, ts: float) -> None:
        for event in self.dissector.feed(conn, direction, raw):
            if isinstance(event, ValueUpdate):
                tag = self.cfg.tags.get((event.kind, event.addr))
                if tag is not None:
                    self.state.update(tag.name, event.value)
                continue

            self._writes += 1
            self._seq += 1
            alert = evaluate(self.cfg, event, self._seq, time.time())
            if alert is None:
                continue
            if self.explain is not None:
                alert = self.explain(alert)
            self.alerts_raised.append(alert)
            self.alerts.append(alert)

        self.state.set_counters(
            frames=self.dissector.frames,
            writes=self._writes,
            malformed=self.dissector.malformed,
        )
        self.state.write(time.time())


def _hmi(cfg: Config, stop: threading.Event, speed: float) -> None:
    """A normal operator station: connects through the tap and polls its tags.

    Its read replies are how GhostLogic learns the live process values, so the
    tool never has to send a packet of its own.
    """
    client = ModbusTcpClient(cfg.proxy_host, port=cfg.proxy_port)
    client.connect()
    interval = HMI_POLL_SECONDS / speed
    try:
        while not stop.is_set():
            client.read_holding_registers(0, count=4, slave=1)
            client.read_coils(0, count=3, slave=1)
            time.sleep(interval)
    finally:
        client.close()


def _attacker(cfg: Config, stop: threading.Event, speed: float) -> None:
    client = ModbusTcpClient(cfg.proxy_host, port=cfg.proxy_port)
    client.connect()
    started = time.monotonic()
    try:
        for at, kind, name, value in SCRIPT:
            wait = at / speed - (time.monotonic() - started)
            if wait > 0 and stop.wait(wait):
                return
            addr = cfg.addr_of(name)
            if kind == "coil":
                client.write_coil(addr, bool(value), slave=1)
            else:
                client.write_register(addr, value, slave=1)
    finally:
        client.close()


def run(cfg: Config, speed: float = 1.0, out_dir: str | Path = "out",
        record: str | Path | None = None, explain=None) -> list[Alert]:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)

    cockpit = Path("cockpit/index.html")
    if cockpit.exists():
        shutil.copy(cockpit, out / "index.html")

    state = StateWriter(out / "state.json", "LIVE PROXY")
    alerts = AlertLog(out / "alerts.jsonl")
    pipeline = Pipeline(cfg, state, alerts, explain=explain)

    sink = pipeline
    recorder = None
    if record is not None:
        recorder = Recorder(record, pipeline)
        sink = recorder

    plant = Plant(cfg, speed=speed)
    plant.start()

    stop = threading.Event()
    ready = threading.Event()
    threads = [
        threading.Thread(target=serve, args=(cfg, sink, stop, ready), daemon=True),
    ]
    threads[0].start()
    ready.wait(timeout=5)

    threads.append(threading.Thread(target=_hmi, args=(cfg, stop, speed), daemon=True))
    threads.append(threading.Thread(target=_attacker, args=(cfg, stop, speed), daemon=True))
    for t in threads[1:]:
        t.start()

    time.sleep(DURATION / speed)
    stop.set()
    plant.stop()
    if recorder is not None:
        recorder.close()

    return pipeline.alerts_raised


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the GhostLogic demo")
    parser.add_argument("--speed", type=float, default=1.0,
                        help="time multiplier; 20 runs the 60s demo in 3s")
    parser.add_argument("--out", default="out", help="directory for state.json and alerts.jsonl")
    parser.add_argument("--record", default=None, help="write a replayable frame log here")
    parser.add_argument("--config", default="tags.yaml")
    args = parser.parse_args()

    cfg = load_config(args.config)
    raised = run(cfg, speed=args.speed, out_dir=args.out, record=args.record)

    print(f"\n{len(raised)} alert(s):")
    for alert in raised:
        print(f"  [{alert.severity}] {alert.tag} = {alert.value} — {alert.rule}")


if __name__ == "__main__":
    main()
```

- [ ] **Step 2: Run it once by hand at high speed**

```bash
python -m ghostlogic.scenario --speed 20 --out out
```

Expected: two alerts printed, CRITICAL then HIGH.

- [ ] **Step 3: Commit**

```bash
git add ghostlogic/scenario.py
git commit -m "feat: scenario orchestrator with HMI poller, attacker and detection pipeline"
```

---

### Task 13: The end-to-end test that guards the demo

If this test is green, the demo works. That is the whole point of it.

**Linear:** M2 · `GhostLogic: end-to-end scenario test`

**Files:**
- Test: `tests/test_scenario_e2e.py`

**Interfaces:**
- Consumes: `run` from Task 12.
- Produces: nothing.

- [ ] **Step 1: Write the test**

`tests/test_scenario_e2e.py`:

```python
"""The demo, run headless at 20x. Green here means the stage run works.

It uses its own ports so it cannot collide with the plant server started by
tests/test_plant_server.py inside the same pytest process.
"""

import dataclasses
import json

import pytest

from ghostlogic.config import load_config
from ghostlogic.scenario import run


@pytest.fixture(scope="module")
def demo(tmp_path_factory):
    cfg = load_config("tags.yaml")
    cfg = dataclasses.replace(cfg, plant_port=25502, proxy_port=25020)
    out = tmp_path_factory.mktemp("demo")
    alerts = run(cfg, speed=20.0, out_dir=out)
    return alerts, out


def test_exactly_two_alerts_in_the_right_order(demo):
    alerts, _ = demo
    assert [a.severity for a in alerts] == ["CRITICAL", "HIGH"]
    assert [a.tag for a in alerts] == ["HP_TRIP_ENABLE", "PMP101_SPEED_CMD"]


def test_the_legal_write_raised_nothing(demo):
    alerts, _ = demo
    assert not [a for a in alerts if a.value == 70]


def test_the_pressure_ran_away_past_the_trip_point(demo):
    _, out = demo
    state = json.loads((out / "state.json").read_text())

    assert state["tags"]["PT101_PRESSURE"] > 95
    assert state["tags"]["HP_TRIP_ENABLE"] == 0
    assert state["tags"]["PMP101_RUN"] == 1  # the trip never fired: it was switched off


def test_the_live_values_were_learned_passively(demo):
    _, out = demo
    state = json.loads((out / "state.json").read_text())

    assert set(state["tags"]) >= {
        "PMP101_SPEED_CMD", "FT101_FLOW", "PT101_PRESSURE",
        "HP_TRIP_SETPOINT", "PMP101_RUN", "HP_TRIP_ENABLE", "XV101_VALVE_OPEN",
    }
    assert state["counters"]["frames"] > 50


def test_no_frame_was_dropped_or_mangled(demo):
    _, out = demo
    state = json.loads((out / "state.json").read_text())
    assert state["counters"]["malformed"] == 0


def test_the_alert_log_matches_what_was_raised(demo):
    alerts, out = demo
    lines = [json.loads(line) for line in (out / "alerts.jsonl").read_text().splitlines()]

    assert len(lines) == len(alerts) == 2
    assert lines[0]["attack_id"] == "T0836"
    assert lines[0]["raw_hex"]
```

- [ ] **Step 2: Run it**

Run: `pytest tests/test_scenario_e2e.py -v`
Expected: 6 passed, in about 5 seconds.

If the pressure assertion fails, check that `Plant(cfg, speed=speed)` is passing the speed through — the physics must tick at the same multiplier as the script, or the attack lands before the pressure has time to move.

- [ ] **Step 3: Run the whole suite**

Run: `pytest -v`
Expected: everything passes.

- [ ] **Step 4: Commit and push**

```bash
git add tests/test_scenario_e2e.py
git commit -m "test: end-to-end scenario guard for the demo"
git push && gh run watch
```

---

### Task 14: The replay parachute

**Linear:** M2 · `GhostLogic: replay source for recorded runs`

**Files:**
- Create: `ghostlogic/sources/replay.py`
- Modify: `ghostlogic/scenario.py`
- Test: `tests/test_replay.py`

**Interfaces:**
- Consumes: `Recorder` (Task 9), `Pipeline` (Task 12).
- Produces: `play(path, sink, stop, speed=1.0) -> int` returning the number of frames replayed; `scenario.replay(cfg, path, out_dir, speed)`.

- [ ] **Step 1: Write the failing test**

`tests/test_replay.py`:

```python
import threading

from ghostlogic.sources import Recorder
from ghostlogic.sources.replay import play


def test_a_recorded_run_plays_back_in_order(tmp_path):
    path = tmp_path / "run.jsonl"
    rec = Recorder(path, lambda c, d, raw, ts: None)
    rec("c1", "c->p", b"\x01", 10.0)
    rec("c1", "p->c", b"\x02\x03", 10.2)
    rec("c1", "c->p", b"\x04", 10.4)
    rec.close()

    seen = []
    frames = play(path, lambda c, d, raw, ts: seen.append((d, raw)), threading.Event(),
                  speed=100.0)

    assert frames == 3
    assert seen == [("c->p", b"\x01"), ("p->c", b"\x02\x03"), ("c->p", b"\x04")]


def test_replay_stops_when_asked(tmp_path):
    path = tmp_path / "run.jsonl"
    rec = Recorder(path, lambda c, d, raw, ts: None)
    for i in range(20):
        rec("c1", "c->p", bytes([i]), float(i))
    rec.close()

    stop = threading.Event()
    seen = []

    def sink(conn, direction, raw, ts):
        seen.append(raw)
        if len(seen) == 3:
            stop.set()

    play(path, sink, stop, speed=1000.0)
    assert len(seen) == 3
```

- [ ] **Step 2: Run it to see it fail**

Run: `pytest tests/test_replay.py -v`
Expected: FAIL — no module named `ghostlogic.sources.replay`.

- [ ] **Step 3: Write `ghostlogic/sources/replay.py`**

```python
"""Replay a recorded run through the identical pipeline.

This is the stage parachute. The cockpit always shows which source produced
what is on screen, so a replayed run is never passed off as a live one.
"""

from __future__ import annotations

import json
import threading
import time
from pathlib import Path

from ghostlogic.sources import Sink


def play(path: str | Path, sink: Sink, stop: threading.Event, speed: float = 1.0) -> int:
    records = [json.loads(line) for line in Path(path).read_text().splitlines() if line.strip()]

    started = time.monotonic()
    played = 0
    for record in records:
        if stop.is_set():
            break
        wait = record["t"] / speed - (time.monotonic() - started)
        if wait > 0:
            time.sleep(wait)
        sink(record["conn"], record["direction"], bytes.fromhex(record["hex"]),
             time.monotonic())
        played += 1

    return played
```

- [ ] **Step 4: Add a replay entry point to `ghostlogic/scenario.py`**

Add the import:

```python
from ghostlogic.sources.replay import play
```

Add the function after `run`:

```python
def replay(cfg: Config, path: str | Path, out_dir: str | Path = "out",
           speed: float = 1.0, explain=None) -> list[Alert]:
    """Feed a recorded run through the same pipeline, labelled honestly."""
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)

    cockpit = Path("cockpit/index.html")
    if cockpit.exists():
        shutil.copy(cockpit, out / "index.html")

    state = StateWriter(out / "state.json", "REPLAY")
    alerts = AlertLog(out / "alerts.jsonl")
    pipeline = Pipeline(cfg, state, alerts, explain=explain)

    play(path, pipeline, threading.Event(), speed=speed)
    return pipeline.alerts_raised
```

Extend `main()` with the flag, just before `cfg = load_config(args.config)`:

```python
    parser.add_argument("--replay", default=None, help="replay a recorded frame log instead")
```

and replace the `raised = run(...)` line with:

```python
    if args.replay:
        raised = replay(cfg, args.replay, out_dir=args.out, speed=args.speed)
    else:
        raised = run(cfg, speed=args.speed, out_dir=args.out, record=args.record)
```

- [ ] **Step 5: Record a run and replay it**

```bash
python -m ghostlogic.scenario --speed 20 --out out --record demo-run.jsonl
python -m ghostlogic.scenario --speed 20 --out out --replay demo-run.jsonl
```

Expected: both print the same two alerts. The second reports `REPLAY` in `out/state.json`.

- [ ] **Step 6: Commit**

```bash
git add ghostlogic/sources/replay.py ghostlogic/scenario.py tests/test_replay.py
git commit -m "feat: replay source so a recorded run drives the identical pipeline"
```

---

## Milestone M3 — Cockpit (by Aug 22)

### Task 15: The single-file dashboard

**Linear:** M3 · `GhostLogic: single-file cockpit dashboard`

**Files:**
- Create: `cockpit/index.html`
- Test: manual, described below

**Interfaces:**
- Consumes: `state.json` and `alerts.jsonl` as written in Task 11.
- Produces: nothing importable.

- [ ] **Step 1: Write `cockpit/index.html`**

```html
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>GhostLogic — pump skid</title>
<style>
  :root { --bg:#0d1117; --panel:#161b22; --line:#30363d; --text:#e6edf3;
          --dim:#8b949e; --ok:#3fb950; --high:#d29922; --crit:#f85149; }
  * { box-sizing: border-box; }
  body { margin:0; background:var(--bg); color:var(--text);
         font:16px/1.5 ui-monospace, SFMono-Regular, Menlo, monospace; }
  header { display:flex; gap:32px; align-items:center; flex-wrap:wrap;
           padding:16px 24px; border-bottom:1px solid var(--line); }
  .metric b { display:block; font-size:32px; font-weight:600; }
  .metric span { color:var(--dim); font-size:13px; text-transform:uppercase; }
  .badge { margin-left:auto; padding:10px 18px; border-radius:6px; font-weight:700;
           font-size:20px; }
  .armed { background:rgba(63,185,80,.15); color:var(--ok); border:1px solid var(--ok); }
  .disarmed { background:rgba(248,81,73,.15); color:var(--crit); border:1px solid var(--crit); }
  .source { font-size:13px; color:var(--dim); }
  main { display:grid; grid-template-columns: 1fr 420px; gap:16px; padding:16px 24px; }
  .panel { background:var(--panel); border:1px solid var(--line); border-radius:8px; padding:16px; }
  canvas { width:100%; height:320px; display:block; }
  .alert { border-left:4px solid var(--dim); padding:12px 14px; margin-bottom:12px;
           background:#0d1117; border-radius:0 6px 6px 0; }
  .alert.CRITICAL { border-left-color:var(--crit); }
  .alert.HIGH { border-left-color:var(--high); }
  .alert.LOW { border-left-color:var(--dim); }
  .sev { font-weight:700; letter-spacing:.05em; }
  .sev.CRITICAL { color:var(--crit); } .sev.HIGH { color:var(--high); }
  .att { float:right; color:var(--dim); font-size:13px; }
  .rule { margin:8px 0; }
  .hex { color:var(--dim); font-size:12px; word-break:break-all; }
  .why { margin-top:10px; padding-top:10px; border-top:1px dashed var(--line); color:#c9d1d9; }
  .why em { color:var(--dim); font-style:normal; font-size:12px; }
  footer { padding:12px 24px; border-top:1px solid var(--line); color:var(--dim); font-size:13px; }
  .w { display:inline-block; margin-right:14px; }
  .w.flag { color:var(--crit); }
  h2 { margin:0 0 12px; font-size:13px; color:var(--dim); text-transform:uppercase; }
</style>
</head>
<body>
<header>
  <div class="metric"><b id="speed">–</b><span>PMP101 speed %</span></div>
  <div class="metric"><b id="flow">–</b><span>FT101 flow m³/h</span></div>
  <div class="metric"><b id="press">–</b><span>PT101 pressure PSI</span></div>
  <div>
    <div id="trip" class="badge armed">TRIP ARMED</div>
    <div class="source">source: <span id="source">–</span></div>
  </div>
</header>

<main>
  <div class="panel">
    <h2>PT101 pressure — dashed line is the trip setpoint</h2>
    <canvas id="chart"></canvas>
  </div>
  <div class="panel">
    <h2>Alerts</h2>
    <div id="alerts"><p style="color:var(--dim)">No alerts. Traffic looks normal.</p></div>
  </div>
</main>

<footer>
  <span class="w">frames <b id="frames">0</b></span>
  <span class="w">writes <b id="writes">0</b></span>
  <span class="w" id="malwrap">malformed <b id="malformed">0</b></span>
</footer>

<script>
const history = [];
const MAX_POINTS = 300;
let setpoint = 95;

async function poll() {
  try {
    const state = await (await fetch('state.json?_=' + Date.now())).json();
    render(state);
  } catch (e) { /* the file is being written; try again next tick */ }

  try {
    const text = await (await fetch('alerts.jsonl?_=' + Date.now())).text();
    renderAlerts(text.trim().split('\n').filter(Boolean).map(JSON.parse));
  } catch (e) { /* no alerts yet */ }
}

function render(state) {
  const t = state.tags || {};
  document.getElementById('speed').textContent = t.PMP101_SPEED_CMD ?? '–';
  document.getElementById('flow').textContent = t.FT101_FLOW ?? '–';
  document.getElementById('press').textContent = t.PT101_PRESSURE ?? '–';
  document.getElementById('source').textContent = state.source || '–';

  if (t.HP_TRIP_SETPOINT) setpoint = t.HP_TRIP_SETPOINT;

  const armed = t.HP_TRIP_ENABLE === 1;
  const badge = document.getElementById('trip');
  badge.textContent = armed ? 'TRIP ARMED' : 'TRIP DISARMED';
  badge.className = 'badge ' + (armed ? 'armed' : 'disarmed');

  const c = state.counters || {};
  document.getElementById('frames').textContent = c.frames ?? 0;
  document.getElementById('writes').textContent = c.writes ?? 0;
  document.getElementById('malformed').textContent = c.malformed ?? 0;
  document.getElementById('malwrap').className = 'w' + (c.malformed ? ' flag' : '');

  if (typeof t.PT101_PRESSURE === 'number') {
    history.push(t.PT101_PRESSURE);
    if (history.length > MAX_POINTS) history.shift();
  }
  drawChart();
}

function drawChart() {
  const canvas = document.getElementById('chart');
  const dpr = window.devicePixelRatio || 1;
  const w = canvas.clientWidth, h = canvas.clientHeight;
  canvas.width = w * dpr; canvas.height = h * dpr;
  const ctx = canvas.getContext('2d');
  ctx.scale(dpr, dpr);
  ctx.clearRect(0, 0, w, h);

  const max = Math.max(130, setpoint + 25, ...history);
  const y = v => h - (v / max) * (h - 20) - 10;

  ctx.strokeStyle = '#f85149';
  ctx.setLineDash([6, 6]);
  ctx.beginPath(); ctx.moveTo(0, y(setpoint)); ctx.lineTo(w, y(setpoint)); ctx.stroke();
  ctx.setLineDash([]);
  ctx.fillStyle = '#f85149'; ctx.font = '12px monospace';
  ctx.fillText('trip ' + setpoint + ' PSI', 8, y(setpoint) - 6);

  if (history.length < 2) return;
  const step = w / (MAX_POINTS - 1);
  ctx.strokeStyle = '#58a6ff'; ctx.lineWidth = 2;
  ctx.beginPath();
  history.forEach((v, i) => i ? ctx.lineTo(i * step, y(v)) : ctx.moveTo(0, y(v)));
  ctx.stroke();
}

function renderAlerts(alerts) {
  const box = document.getElementById('alerts');
  if (!alerts.length) return;
  box.innerHTML = alerts.slice().reverse().map(a => `
    <div class="alert ${a.severity}">
      <span class="att">${a.attack_id} ${a.attack_name}</span>
      <span class="sev ${a.severity}">${a.severity}</span>
      <div class="rule"><b>${a.tag}</b> = ${a.value}<br>${a.rule}</div>
      <div class="hex">${a.raw_hex}</div>
      ${a.explanation ? `<div class="why">${a.explanation}
         <em>— ${a.explain_source}</em></div>` : ''}
    </div>`).join('');
}

setInterval(poll, 250);
poll();
</script>
</body>
</html>
```

- [ ] **Step 2: Watch it run**

```bash
python -m ghostlogic.scenario --speed 1 --out out --record demo-run.jsonl &
python -m http.server 8000 --directory out
```

Open http://localhost:8000 and watch the whole 60 seconds.

- [ ] **Step 3: Check the three things that must be true on stage**

- At 25 seconds the badge flips to **TRIP DISARMED** while every number stays normal.
- The pressure line crosses the dashed trip line after 40 seconds and keeps going.
- The alert panel shows severity, rule and raw hex — with no explanation text yet, which is correct until Task 16.

- [ ] **Step 4: Commit**

```bash
git add cockpit/index.html
git commit -m "feat: single-file cockpit with pressure chart, trip badge and alert cards"
```

---

## Milestone M4 — Explain layer (by Aug 23)

### Task 16: Cache-first explanations with a fallback

**Linear:** M4 · `GhostLogic: local model explain layer with cache and fallback`

**Files:**
- Create: `ghostlogic/explain.py`
- Test: `tests/test_explain.py`

**Interfaces:**
- Consumes: `Alert` (Task 10).
- Produces: `fingerprint(alert) -> str`; `Explainer(cache_path, model, host, timeout, allow_model)` callable as `explain(alert) -> Alert` (a new Alert with `explanation` and `explain_source` filled), plus `.save()`.

- [ ] **Step 1: Write the failing test**

`tests/test_explain.py`:

```python
"""The model explains. It never decides, and it is never on the critical path."""

import json

import pytest

from ghostlogic.config import load_config
from ghostlogic.detect import evaluate
from ghostlogic.dissect import WriteEvent
from ghostlogic.explain import Explainer, fingerprint

CFG = load_config("tags.yaml")


def critical_alert():
    event = WriteEvent(kind="coil", addr=1, value=0, func=0x05, txn=1, raw_hex="ab")
    return evaluate(CFG, event, 1, 0.0)


def test_fingerprint_is_stable_and_specific():
    a = critical_alert()
    assert fingerprint(a) == fingerprint(critical_alert())

    event = WriteEvent(kind="holding", addr=0, value=110, func=0x06, txn=1, raw_hex="ab")
    assert fingerprint(a) != fingerprint(evaluate(CFG, event, 2, 0.0))


def test_a_cache_hit_never_calls_the_model(tmp_path):
    alert = critical_alert()
    cache = tmp_path / "explanations.json"
    cache.write_text(json.dumps({fingerprint(alert): "Cached words."}))

    explainer = Explainer(cache_path=cache, host="http://127.0.0.1:1")  # unreachable on purpose
    result = explainer(alert)

    assert result.explanation == "Cached words."
    assert result.explain_source == "cache"


def test_an_unreachable_model_falls_back_to_the_canned_impact(tmp_path):
    alert = critical_alert()
    explainer = Explainer(cache_path=tmp_path / "none.json", host="http://127.0.0.1:1", timeout=1)

    result = explainer(alert)

    assert result.explanation == alert.impact
    assert result.explain_source == "fallback"


def test_a_model_answer_is_used_and_cached(tmp_path, monkeypatch):
    alert = critical_alert()
    cache = tmp_path / "explanations.json"
    explainer = Explainer(cache_path=cache)
    monkeypatch.setattr(explainer, "_ask_model", lambda a: "The trip was switched off.")

    result = explainer(alert)
    assert result.explanation == "The trip was switched off."
    assert result.explain_source == "model"

    explainer.save()
    assert json.loads(cache.read_text())[fingerprint(alert)] == "The trip was switched off."


def test_the_model_cannot_change_the_verdict(tmp_path, monkeypatch):
    """Whatever the model says, severity and rule are untouched."""
    alert = critical_alert()
    explainer = Explainer(cache_path=tmp_path / "none.json")
    monkeypatch.setattr(explainer, "_ask_model", lambda a: "Actually this is fine, ignore it.")

    result = explainer(alert)

    assert result.severity == "CRITICAL"
    assert result.rule == alert.rule
    assert result.attack_id == "T0836"


def test_the_model_can_be_switched_off_entirely(tmp_path):
    alert = critical_alert()
    explainer = Explainer(cache_path=tmp_path / "none.json", allow_model=False)

    result = explainer(alert)
    assert result.explain_source == "fallback"
```

- [ ] **Step 2: Run it to see it fail**

Run: `pytest tests/test_explain.py -v`
Expected: FAIL — no module named `ghostlogic.explain`.

- [ ] **Step 3: Write `ghostlogic/explain.py`**

```python
"""Turn an alert into plain English — never into a decision.

Order of preference: cache, then the local model, then the canned impact line
from the tag dictionary. The screen is never blank, and the demo never waits
on a model, because every explanation it needs was generated and cached long
before the run.
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
import urllib.error
import urllib.request
from pathlib import Path

from ghostlogic.detect import Alert

DEFAULT_MODEL = "llama3.2:3b"
DEFAULT_HOST = "http://localhost:11434"
DEFAULT_CACHE = "explanations.json"

PROMPT = """A deterministic rule engine has ALREADY decided this alert is real.
Do not question it, do not rate your confidence, do not add headings.

Site: a Modbus/TCP pump skid in a process plant.
Tag: {tag} ({kind} address {addr}). Value written: {value}.
Rule that fired: {rule}
Known impact: {impact}

Write exactly three short lines:
1. What just happened, for a control engineer.
2. Why it matters physically.
3. What to do in the next five minutes.
Under 70 words total."""


def fingerprint(alert: Alert) -> str:
    """Stable key for an alert's meaning — not its timestamp or sequence."""
    key = f"{alert.tag}|{alert.value}|{alert.rule}"
    return hashlib.sha256(key.encode()).hexdigest()[:16]


class Explainer:
    def __init__(self, cache_path: str | Path = DEFAULT_CACHE, model: str = DEFAULT_MODEL,
                 host: str = DEFAULT_HOST, timeout: int = 60, allow_model: bool = True) -> None:
        self.cache_path = Path(cache_path)
        self.model = model
        self.host = host.rstrip("/")
        self.timeout = timeout
        self.allow_model = allow_model
        self.cache: dict[str, str] = {}
        if self.cache_path.exists():
            self.cache = json.loads(self.cache_path.read_text())

    def __call__(self, alert: Alert) -> Alert:
        key = fingerprint(alert)

        if key in self.cache:
            return dataclasses.replace(
                alert, explanation=self.cache[key], explain_source="cache"
            )

        if self.allow_model:
            try:
                text = self._ask_model(alert)
                if text:
                    self.cache[key] = text
                    return dataclasses.replace(
                        alert, explanation=text, explain_source="model"
                    )
            except (urllib.error.URLError, OSError, KeyError, ValueError, TimeoutError):
                pass  # the demo does not stop for a model

        return dataclasses.replace(
            alert, explanation=alert.impact, explain_source="fallback"
        )

    def _ask_model(self, alert: Alert) -> str:
        prompt = PROMPT.format(
            tag=alert.tag, kind=alert.kind, addr=alert.addr,
            value=alert.value, rule=alert.rule, impact=alert.impact,
        )
        payload = json.dumps(
            {"model": self.model, "prompt": prompt, "stream": False}
        ).encode()
        request = urllib.request.Request(
            f"{self.host}/api/generate",
            data=payload,
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(request, timeout=self.timeout) as response:
            return json.loads(response.read())["response"].strip()

    def save(self) -> None:
        self.cache_path.write_text(json.dumps(self.cache, indent=2, sort_keys=True) + "\n")
```

- [ ] **Step 4: Run the tests**

Run: `pytest tests/test_explain.py -v`
Expected: 6 passed. They run in under a second because none of them reaches a real model.

- [ ] **Step 5: Commit**

```bash
git add ghostlogic/explain.py tests/test_explain.py
git commit -m "feat: cache-first explain layer that cannot change a verdict"
```

---

### Task 17: Wire the explainer in and freeze the cache

**Linear:** M4 · `GhostLogic: wire explain into the scenario and commit the cache`

**Files:**
- Modify: `ghostlogic/scenario.py`
- Create: `explanations.json`
- Test: `tests/test_scenario_e2e.py` (one added test)

**Interfaces:**
- Consumes: `Explainer` (Task 16), `run`/`replay` (Tasks 12, 14).
- Produces: `--explain` and `--label` flags on the scenario CLI; a committed `explanations.json`.

- [ ] **Step 1: Add the flags to `ghostlogic/scenario.py`**

Add the import:

```python
from ghostlogic.explain import Explainer
```

Add to `main()`, with the other `add_argument` calls:

```python
    parser.add_argument("--explain", action="store_true",
                        help="fill alerts with explanations (cache first, then the local model)")
    parser.add_argument("--label", default=None,
                        help="override the source label shown in the cockpit")
```

Replace the dispatch block in `main()` with:

```python
    explainer = Explainer() if args.explain else None

    if args.replay:
        raised = replay(cfg, args.replay, out_dir=args.out, speed=args.speed,
                        explain=explainer, label=args.label)
    else:
        raised = run(cfg, speed=args.speed, out_dir=args.out, record=args.record,
                     explain=explainer, label=args.label)

    if explainer is not None:
        explainer.save()
```

- [ ] **Step 2: Thread the label through `run` and `replay`**

In `run`, change the signature and the `StateWriter` line:

```python
def run(cfg: Config, speed: float = 1.0, out_dir: str | Path = "out",
        record: str | Path | None = None, explain=None, label: str | None = None) -> list[Alert]:
```

```python
    state = StateWriter(out / "state.json", label or "LIVE PROXY")
```

In `replay`, the same:

```python
def replay(cfg: Config, path: str | Path, out_dir: str | Path = "out",
           speed: float = 1.0, explain=None, label: str | None = None) -> list[Alert]:
```

```python
    state = StateWriter(out / "state.json", label or "REPLAY")
```

- [ ] **Step 3: Add the test that proves the cache path works with no model**

Append to `tests/test_scenario_e2e.py`:

```python
def test_explanations_come_from_the_cache_with_no_model_running(tmp_path_factory):
    """This is what CI and the stage both rely on: no Ollama needed."""
    import dataclasses as dc

    from ghostlogic.explain import Explainer

    cfg = dc.replace(load_config("tags.yaml"), plant_port=25602, proxy_port=25120)
    out = tmp_path_factory.mktemp("cached")
    explainer = Explainer(cache_path="explanations.json", allow_model=False)

    alerts = run(cfg, speed=20.0, out_dir=out, explain=explainer)

    assert len(alerts) == 2
    for alert in alerts:
        assert alert.explanation
        assert alert.explain_source == "cache"
        assert alert.severity in ("CRITICAL", "HIGH")
```

- [ ] **Step 4: Generate the cache with the real model**

```bash
ollama list   # confirm llama3.2:3b is present
python -m ghostlogic.scenario --speed 20 --out out --explain
cat explanations.json
```

Expected: two entries, each three short lines. Read them. If a line is vague or wrong, delete that entry from `explanations.json` and run again — the model is not deterministic, and it is entirely legitimate to keep re-rolling until the wording is good. What is on screen at the hackathon must be text you are happy to be judged on.

- [ ] **Step 5: Run the test that now depends on the committed cache**

Run: `pytest tests/test_scenario_e2e.py -v`
Expected: 7 passed.

- [ ] **Step 6: Commit**

```bash
git add ghostlogic/scenario.py explanations.json tests/test_scenario_e2e.py
git commit -m "feat: wire the explain layer into the scenario and freeze the demo cache"
```

---

## Milestone M5 — Ship and rehearse (by Aug 23)

### Task 18: Publish the cockpit to GitHub Pages

**Linear:** M5 · `GhostLogic: publish the cockpit to GitHub Pages`

**Files:**
- Create: `.github/workflows/pages.yml`, `demo/demo-run.jsonl`
- Modify: `.gitignore`

**Interfaces:**
- Consumes: the scenario CLI (Tasks 12, 14, 17) and the committed `explanations.json`.
- Produces: a public URL serving the cockpit with a recorded run.

- [ ] **Step 1: Record the run that ships**

```bash
mkdir -p demo
python -m ghostlogic.scenario --speed 1 --out out --record demo/demo-run.jsonl
echo "site/" >> .gitignore
```

Watch it once at full speed to be sure the recording is a good one, then commit it — this same file is the stage parachute.

- [ ] **Step 2: Write `.github/workflows/pages.yml`**

```yaml
name: Pages

on:
  push:
    branches: [main]
  workflow_dispatch:

permissions:
  contents: read
  pages: write
  id-token: write

concurrency:
  group: pages
  cancel-in-progress: true

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.14"
          cache: pip
      - run: pip install -r requirements.txt
      - name: Replay the recorded run into a static snapshot
        run: |
          python -m ghostlogic.scenario \
            --replay demo/demo-run.jsonl \
            --speed 40 \
            --out site \
            --explain \
            --label "RECORDED SNAPSHOT"
      - uses: actions/upload-pages-artifact@v3
        with:
          path: site

  deploy:
    needs: build
    runs-on: ubuntu-latest
    environment:
      name: github-pages
      url: ${{ steps.deploy.outputs.page_url }}
    steps:
      - id: deploy
        uses: actions/deploy-pages@v4
```

The runner has no Ollama, so `--explain` resolves entirely from the committed cache. If the cache were missing, the page would show the canned impact lines instead — degraded, never broken.

- [ ] **Step 3: Turn Pages on for the repository**

This one is yours, in the browser: **Settings → Pages → Source → GitHub Actions**. The workflow cannot enable it for you.

- [ ] **Step 4: Push and confirm**

```bash
git add .github/workflows/pages.yml demo/demo-run.jsonl
git commit -m "ci: publish the cockpit to GitHub Pages from a recorded run"
git push && gh run watch
```

Then open `https://mejooo.github.io/ghostlogic/` and check the alerts and the explanations render, with the source reading **RECORDED SNAPSHOT**.

---

### Task 19: README, run instructions and the rehearsal

**Linear:** M5 · `GhostLogic: README, demo runbook and two full rehearsals`

**Files:**
- Create: `README.md`, `docs/runbook.md`

**Interfaces:**
- Consumes: everything.
- Produces: nothing importable.

- [ ] **Step 1: Write `README.md`**

````markdown
# GhostLogic

Passive Modbus/TCP attack detection for a pump skid. Deterministic rules
decide; a local model only explains.

Built for the OT Cybersecurity Hackathon, Dhahran, 24–27 August 2026.

## The idea

An attacker who reaches a PLC over a legitimate channel does not send anything
malformed. They send a perfectly valid write that disables a protection. Every
byte is legal. Only the *meaning* is an attack.

GhostLogic watches the traffic, decodes the writes, and checks them against a
tag dictionary that knows which values are safe and which protections must
never be switched off.

## Run it

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

python -m ghostlogic.scenario --speed 1 --out out --explain &
python -m http.server 8000 --directory out
```

Open http://localhost:8000 and watch for 60 seconds.

## What you will see

| Time | Event | Result |
|---|---|---|
| 10s | operator raises pump speed 55 → 70 | no alert — it is inside the safe band |
| 25s | attacker disables the high-pressure trip | **CRITICAL**, while every process value still looks normal |
| 40s | attacker drives the pump to 110% | **HIGH**, and the pressure starts climbing |
| ~55s | pressure passes the trip point | nothing stops it, because the trip is off |

## Design commitments

1. **Passive in production.** Live process values are decoded from the HMI's own
   read replies. GhostLogic never originates a packet to the plant. The proxy
   used in the laptop lab is inline and therefore *not* passive — the production
   answer is a mirror-port sniff behind the same interface.
2. **The model never decides.** `detect.py` raises alerts deterministically and
   does not import the explain layer. A test enforces that.
3. **Output is a decision, not a report** — measured in time to decision.

## Not built, on purpose

Vendor bytecode decompilation, Docker/OpenPLC, recon detection, and source-address
rules. See `docs/superpowers/specs/2026-08-18-ghostlogic-design.md`.
````

- [ ] **Step 2: Write `docs/runbook.md`**

````markdown
# Demo runbook

## Before you leave the house

- [ ] `pytest -v` — everything green
- [ ] `ollama list` shows `llama3.2:3b`
- [ ] `explanations.json` is committed and its wording is text you are happy with
- [ ] `demo/demo-run.jsonl` is committed
- [ ] Pages URL loads: https://mejooo.github.io/ghostlogic/
- [ ] Laptop charged, wifi assumed broken

## Live run

```bash
source .venv/bin/activate
python -m ghostlogic.scenario --speed 1 --out out --explain &
python -m http.server 8000 --directory out
```

Browser at http://localhost:8000, full screen.

## If anything breaks — the parachute

```bash
python -m ghostlogic.scenario --replay demo/demo-run.jsonl --speed 1 --out out --explain
```

The cockpit will say **REPLAY** in the corner. Say so out loud: "this is the
recorded run, the live one is the same pipeline."

## What to say, and when

- **0s** — "This is a pump skid. Normal traffic. The trip is armed at 95 PSI."
- **10s** — "An operator just raised the pump speed. Legal change, inside the
  safe band. No alert. A tool that cries wolf here is worthless."
- **25s** — "That was a perfectly valid Modbus write. It disabled the
  over-pressure trip. Look at the screen: every process value is still normal.
  **This is the moment nothing looks wrong.** No HMI in the world shows it."
- **40s** — "Now they drive the pump past its safe envelope."
- **55s** — "And the pressure goes straight through the trip point, because the
  protection was switched off thirty seconds ago."
- **Close** — "The rules decided all of that. The model only wrote the English.
  Here is the raw frame, here is the rule, here is the ATT&CK technique. An
  engineer can check every line."

## Questions you will get

- *"Is this passive?"* — The detection is. Live values come from the HMI's read
  replies. The proxy in the laptop lab is inline; on a plant you put it on a
  mirror port, which is `sources/sniff.py`, same interface.
- *"What if the model hallucinates?"* — It cannot change a verdict. Severity,
  rule and technique are computed before the model is called, and they stay on
  screen next to whatever it says.
- *"Does this scale past one protocol?"* — The dissector is one file behind one
  interface. DNP3 and S7 are the roadmap.
````

- [ ] **Step 3: Rehearse twice, start to finish**

Not a formality. Run the full 60 seconds twice with the browser open, saying the
lines out loud. Time yourself. Then run the parachute once so your hands know
the command without thinking.

- [ ] **Step 4: Commit**

```bash
git add README.md docs/runbook.md
git commit -m "docs: README and demo runbook"
git push && gh run watch
```

---

## Task-to-Linear map

Nineteen tasks, nineteen issues, in this order.

| # | Task | Milestone |
|---|---|---|
| 1 | Repo skeleton and pymodbus proof | M0 |
| 2 | Install Ollama and prove the model responds | M0 |
| 3 | CI pipeline with lint, tests and security scans | M0 |
| 4 | tags.yaml and validated config loader | M1 |
| 5 | Modbus server seeded from the tag dictionary | M1 |
| 6 | Pressure physics and trip logic | M1 |
| 7 | Modbus dissector for write commands | M1 |
| 8 | Decode read replies into live tag values | M1 |
| 9 | Capture source interface, proxy and recorder | M1 |
| 10 | Deterministic detection rules | M2 |
| 11 | Atomic state writer and alert log | M2 |
| 12 | Scenario orchestrator | M2 |
| 13 | End-to-end scenario test | M2 |
| 14 | Replay source | M2 |
| 15 | Single-file cockpit dashboard | M3 |
| 16 | Explain layer with cache and fallback | M4 |
| 17 | Wire explain in and freeze the cache | M4 |
| 18 | Publish the cockpit to GitHub Pages | M5 |
| 19 | README, runbook and two rehearsals | M5 |

## If you run out of time

Cut in this order, and say on stage that you cut them:

1. **Task 18 (Pages)** — the local demo is the demo. A URL is a bonus.
2. **Task 16–17 (explain layer)** — the deterministic core plus the cockpit is
   still a complete, defensible product. The canned impact lines already read
   as English.
3. **Task 14 (replay)** — only if you are willing to run live with no parachute.

Never cut Tasks 10, 13, or 15. The rules are the product, the end-to-end test is
what stops the demo breaking, and without the cockpit there is nothing to look at.
