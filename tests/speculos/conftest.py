import pytest
from pathlib import Path
from ledgered.devices import Device

from ragger.backend import SpeculosBackend
from ragger.navigator import Navigator
from ragger.utils import find_project_root_dir

from client import TestClient

from ragger.conftest import configuration

#######################
# CONFIGURATION START #
#######################

# You can configure optional parameters by overriding the value of
# ragger.configuration.OPTIONAL_CONFIGURATION
# Please refer to ragger/conftest/configuration.py for their descriptions and accepted values

configuration.OPTIONAL.BACKEND_SCOPE = "session"

#####################
# CONFIGURATION END #
#####################

# Pull all features from the base ragger conftest using the overridden configuration
pytest_plugins = ("ragger.conftest.base_conftest", )


##########################
# CONFIGURATION OVERRIDE #
##########################


BACKENDS = ["speculos"]


def pytest_addoption(parser):
    parser.addoption("--transport", default="U2F")
    parser.addoption("--fast", action="store_true")


@pytest.fixture(scope="session")
def transport(pytestconfig):
    return pytestconfig.getoption("transport")


def prepare_speculos_args(root_pytest_dir: Path, device: Device, display: bool, transport: str):
    speculos_args = ["--usb", transport]

    if display:
        speculos_args += ["--display", "qt"]

    device_name = device.name
    if device_name == "nanosp":
        device_name = "nanos2"

    # Find the compiled application for the requested device
    project_root_dir = find_project_root_dir(root_pytest_dir)

    app_path = Path(project_root_dir / "build" / device_name / "bin" / "app.elf").resolve()
    if not app_path.is_file():
        raise ValueError(f"File '{app_path}' missing. Did you compile for this target?")

    return (app_path, {"args": speculos_args})


# Depending on the "--backend" option value, a different backend is
# instantiated, and the tests will either run on Speculos or on a physical
# device depending on the backend
def create_backend(root_pytest_dir: Path, backend_name: str,
                   device: Device, display: bool, transport: str):
    if backend_name.lower() == "speculos":
        app_path, speculos_args = prepare_speculos_args(root_pytest_dir, device,
                                                        display, transport)
        return SpeculosBackend(app_path, device, **speculos_args)
    else:
        raise ValueError(f"Backend '{backend_name}' is unknown. Valid backends are: {BACKENDS}")


@pytest.fixture(scope="session")
def backend(root_pytest_dir: Path, backend_name: str, device: Device, display: bool,
            transport: str):
    with create_backend(root_pytest_dir, backend_name, device, display, transport) as b:
        yield b


@pytest.fixture
def client(backend: SpeculosBackend, navigator: Navigator, transport: str):
    client = TestClient(backend, navigator, transport)
    client.start()
    return client
