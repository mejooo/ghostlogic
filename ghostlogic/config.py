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
