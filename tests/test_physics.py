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
    assert plant._get(FC_HOLDING, plant._a_flow) == 0


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
