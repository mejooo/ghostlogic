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
