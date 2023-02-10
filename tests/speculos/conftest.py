import pytest
from pathlib import Path
from ragger.firmware import Firmware
from ragger.backend import SpeculosBackend
from ragger.navigator import NanoNavigator, StaxNavigator
from ragger.utils import app_path_from_app_name

from client import TestClient


# This variable is needed for Speculos only
APPS_DIRECTORY = (Path(__file__).parent.parent / "elfs").resolve()

APP_NAME = "u2f"

BACKENDS = ["speculos"]

DEVICES = ["nanos", "nanox", "nanosp", "stax", "all"]

FIRMWARES = [Firmware('nanos', '2.1'),
             Firmware('nanox', '2.0.2'),
             Firmware('nanosp', '1.0.3'),
             Firmware('stax', '1.0')]


def pytest_addoption(parser):
    parser.addoption("--device", choices=DEVICES, required=True)
    parser.addoption("--backend", choices=BACKENDS, default="speculos")
    parser.addoption("--display", action="store_true", default=False)
    parser.addoption("--golden_run", action="store_true", default=False)
    parser.addoption("--transport", default="U2F")
    parser.addoption("--fast", action="store_true")


@pytest.fixture(scope="session")
def backend_name(pytestconfig):
    return pytestconfig.getoption("backend")


@pytest.fixture(scope="session")
def display(pytestconfig):
    return pytestconfig.getoption("display")


@pytest.fixture(scope="session")
def golden_run(pytestconfig):
    return pytestconfig.getoption("golden_run")


@pytest.fixture(scope="session")
def transport(pytestconfig):
    return pytestconfig.getoption("transport")


@pytest.fixture
def test_name(request):
    # Get the name of current pytest test
    test_name = request.node.name

    # Remove firmware suffix:
    # -  test_xxx_transaction_ok[nanox 2.0.2]
    # => test_xxx_transaction_ok
    return test_name.split("[")[0]


# Glue to call every test that depends on the firmware once for each required firmware
def pytest_generate_tests(metafunc):
    if "firmware" in metafunc.fixturenames:
        fw_list = []
        ids = []

        device = metafunc.config.getoption("device")
        backend_name = metafunc.config.getoption("backend")

        if device == "all":
            if backend_name != "speculos":
                raise ValueError("Invalid device parameter on this backend")

            # Add all supported firmwares
            for fw in FIRMWARES:
                fw_list.append(fw)
                ids.append(fw.device + " " + fw.version)

        else:
            # Enable firmware for demanded device
            for fw in FIRMWARES:
                if device == fw.device:
                    fw_list.append(fw)
                    ids.append(fw.device + " " + fw.version)

        metafunc.parametrize("firmware", fw_list, ids=ids, scope="session")


def prepare_speculos_args(firmware: Firmware, display: bool, transport: str):
    speculos_args = ['--usb', transport]

    if display:
        speculos_args += ["--display", "qt"]

    app_path = app_path_from_app_name(APPS_DIRECTORY, APP_NAME, firmware.device)

    return ([app_path], {"args": speculos_args})


# Depending on the "--backend" option value, a different backend is
# instantiated, and the tests will either run on Speculos or on a physical
# device depending on the backend
def create_backend(backend_name: str, firmware: Firmware, display: bool, transport: str):
    if backend_name.lower() == "speculos":
        args, kwargs = prepare_speculos_args(firmware, display, transport)
        return SpeculosBackend(*args, firmware, **kwargs)
    else:
        raise ValueError(f"Backend '{backend_name}' is unknown. Valid backends are: {BACKENDS}")


@pytest.fixture(scope="session")
def backend(backend_name, firmware, display, transport):
    with create_backend(backend_name, firmware, display, transport) as b:
        yield b


@pytest.fixture(scope="session")
def navigator(backend, firmware, golden_run):
    if firmware.device.startswith("nano"):
        return NanoNavigator(backend, firmware, golden_run)
    elif firmware.device.startswith("stax"):
        return StaxNavigator(backend, firmware, golden_run)
    else:
        raise ValueError(f"Device '{firmware.device}' is unsupported.")


@pytest.fixture(autouse=True)
def use_only_on_backend(request, backend):
    if request.node.get_closest_marker('use_on_backend'):
        current_backend = request.node.get_closest_marker('use_on_backend').args[0]
        if current_backend != backend:
            pytest.skip('skipped on this backend: {}'.format(current_backend))


def pytest_configure(config):
    config.addinivalue_line(
        "markers", "use_only_on_backend(backend): skip test if not on the specified backend",
    )


@pytest.fixture(scope="session")
def client(firmware, backend, navigator, transport: str):
    client = TestClient(firmware, backend, navigator, transport)
    client.start()
    return client
