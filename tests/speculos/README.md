# How to use the Ragger test framework

This framework allows testing the application on the Speculos emulator.


## Quickly get started with Ragger and Speculos

### Install ragger and dependencies

```
pip install --extra-index-url https://test.pypi.org/simple/ -r requirements.txt
sudo apt-get update && sudo apt-get install qemu-user-static
```

### Compile the application

The application to test must be compiled for all required devices.
You can use for this the container `ghcr.io/ledgerhq/ledger-app-builder/ledger-app-builder-lite`:
```
docker pull ghcr.io/ledgerhq/ledger-app-builder/ledger-app-builder-lite:latest
cd <your app repository>                        # replace <appname> with the name of your app, (eg boilerplate)
docker run --user "$(id -u)":"$(id -g)" --rm -ti -v "$(realpath .):/app" --privileged -v "/dev/bus/usb:/dev/bus/usb" ledger-app-builder-lite:latest
make clean && make BOLOS_SDK=$<device>_SDK      # replace <device> with one of [NANOS, NANOX, NANOSP]
exit
```

### Run a simple test using the Speculos emulator

You can use the following command to get your first experience with Ragger and Speculos
```
pytest -v --tb=short --device nanox --display
```
Or you can refer to the section `Available pytest options` to configure the options you want to use

## Launch the tests

Given the requirements are installed and the app has been built, just run one of the following commands:

```
pytest tests/speculos/ --device nanos
pytest tests/speculos/ --device nanos --transport HID
pytest tests/speculos/ --device nanox
pytest tests/speculos/ --device display
```



## Available pytest options

Standard useful pytest options
```
    -v              formats the test summary in a readable way
    -s              enable logs for successful tests, on Speculos it will enable app logs if compiled with DEBUG=1
    -k <testname>   only run the tests that contain <testname> in their names
    --tb=short      in case of errors, formats the test traceback in a readable way
```

Custom pytest options
```
    --device <device>           run the test on the specified device [nanos,nanox,nanosp,all]. This parameter is mandatory
    --display                 on Speculos, enables the display of the app screen using QT
    --golden_run              on Speculos, screen comparison functions will save the current screen instead of comparing
    --transport <transport>   run the test above the transport [U2F, HID]. U2F is the default
    --fast                    skip some long tests
```
