"""The plant: a Modbus/TCP pump skid with its own protective trip.

The trip lives here, inside the device, exactly where a real one would.
That is what makes the demo honest: switching the trip off does not disable
a detection rule, it removes a real protection from a real controller.
"""

from __future__ import annotations

import threading
import time

from pymodbus.datastore import (
    ModbusSequentialDataBlock,
    ModbusServerContext,
    ModbusSlaveContext,
)
from pymodbus.server import StartTcpServer

from ghostlogic.config import COIL, HOLDING, Config, Tag

FC_COIL = 1
FC_HOLDING = 3


def _check_contiguous(kind: str, tags: list[Tag]) -> None:
    """`ModbusSequentialDataBlock(0, values)` binds values[i] to Modbus
    address i. Sorting by addr and taking .init only produces the right
    list if the addresses are exactly 0..N-1 with no gaps or duplicates —
    verify that here so a gap fails loudly instead of silently binding a
    tag to the wrong address.
    """
    for i, tag in enumerate(sorted(tags, key=lambda t: t.addr)):
        if tag.addr != i:
            raise ValueError(
                f"{kind} tags are not contiguous from 0: "
                f"expected addr {i}, found {tag.addr} ({tag.name})"
            )


def build_context(cfg: Config) -> ModbusServerContext:
    """Seed the datastore from the tag dictionary, in address order."""
    holdings = [t for t in cfg.tags.values() if t.kind == HOLDING]
    coils = [t for t in cfg.tags.values() if t.kind == COIL]

    _check_contiguous(HOLDING, holdings)
    _check_contiguous(COIL, coils)

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

    # --- simulation ---------------------------------------------------------
    def tick(self) -> None:
        """Advance the process one step. Pure state, no I/O.

        Two threads touch this datastore: the Modbus server thread (client
        writes) and the physics thread running this method. No lock guards
        that access, and that is deliberate rather than an oversight:
        every _get/_set is a single-element (count=1) datastore operation,
        which is atomic under CPython. The only remaining risk is a tick
        that reads a value the client changed mid-tick — worst case that
        tick uses a 250 ms-stale input, and the next tick self-corrects.
        That is acceptable, and in fact realistic, for a process
        simulation. A lock around individual _get/_set calls would not
        make this multi-step tick atomic anyway, so it would add cost
        without buying real correctness — hence no lock here.
        """
        p = self.cfg.physics

        speed_cmd = self._get(FC_HOLDING, self._a_speed)
        setpoint = self._get(FC_HOLDING, self._a_setpoint)
        running = self._get(FC_COIL, self._a_run)
        trip_armed = self._get(FC_COIL, self._a_trip_en)
        valve_open = self._get(FC_COIL, self._a_valve)

        if running and valve_open:
            target = p.ambient + speed_cmd * p.gain
            flow = speed_cmd * p.flow_factor
        else:
            target = float(p.ambient)
            flow = 0.0

        self.pressure += (target - self.pressure) * p.approach

        if trip_armed and self.pressure >= setpoint:
            self._set(FC_COIL, self._a_run, 0)
            self._set(FC_HOLDING, self._a_speed, 0)
            self.tripped = True
            flow = 0.0  # the pump just stopped; do not publish the pre-trip flow

        self._set(FC_HOLDING, self._a_pressure, round(self.pressure))
        self._set(FC_HOLDING, self._a_flow, round(flow))

    def run_physics(self) -> None:
        interval = (self.cfg.physics.tick_ms / 1000.0) / self.speed
        while not self._stop.is_set():
            self.tick()
            time.sleep(interval)

    # --- lifecycle --------------------------------------------------------
    def start(self) -> None:
        server = threading.Thread(target=self._serve, daemon=True)
        physics = threading.Thread(target=self.run_physics, daemon=True)
        server.start()
        physics.start()
        self._threads.extend([server, physics])

    def _serve(self) -> None:
        StartTcpServer(
            context=self.context,
            address=(self.cfg.plant_host, self.cfg.plant_port),
        )

    def stop(self) -> None:
        """Signal the physics loop to stop.

        This does NOT stop the Modbus server: StartTcpServer blocks forever
        and its listening socket stays bound for the life of the process.
        Only the physics thread actually honors this — the server thread
        keeps running until the process exits.
        """
        self._stop.set()
