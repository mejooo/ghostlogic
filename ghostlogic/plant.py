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
