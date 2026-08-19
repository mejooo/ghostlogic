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
