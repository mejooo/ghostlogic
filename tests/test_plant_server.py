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
