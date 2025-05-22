import os
import socket
import struct

from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.primitives import serialization

from pathlib import Path

from fido2.attestation import AttestationVerifier
from fido2.ctap import CtapError
from fido2.hid import CtapHidDevice, TYPE_INIT, CAPABILITY, CTAPHID
from fido2.hid.base import CtapHidConnection, HidDescriptor

from ctap1_client import LedgerCtap1

TESTS_SPECULOS_DIR = Path(__file__).absolute().parent
REPO_ROOT_DIR = TESTS_SPECULOS_DIR.parent.parent
APP_ELF_PATH = REPO_ROOT_DIR / "bin" / "app.elf"

CA_PATH = REPO_ROOT_DIR / "attestations" / "data"
TEST_CA_PATH = CA_PATH / "test" / "ca-cert.pem"
PROD_CA_PATH = CA_PATH / "prod" / "ca-cert.pem"


class LedgerAttestationVerifier(AttestationVerifier):
    def __init__(self, device_model):
        super().__init__()

        use_prod_ca = os.environ.get("USE_PROD_CA", False)

        if use_prod_ca:
            self.ca_path = PROD_CA_PATH
        else:
            self.ca_path = TEST_CA_PATH

    def ca_lookup(self, result, auth_data):
        with open(self.ca_path, "rb") as f:
            root_cert = load_pem_x509_certificate(f.read())
        attestation_cert = root_cert.public_bytes(serialization.Encoding.DER)

        return attestation_cert


class LedgerCtapHidConnection(CtapHidConnection):
    """ Overriding fido2.hid.base.CtapHidConnection

    This is mostly a redirection of write_packet() and read_packet()
    to speculos raw socket.
    """
    def __init__(self, transport, debug=False):
        self.sock = socket.create_connection(('127.0.0.1', 5001))
        self.u2f_hid_endpoint = (transport.upper() == "U2F")
        self.debug = debug

        # Set a timeout to allow tests to raise on socket rx failure
        self.sock.settimeout(5)

    def write_packet(self, packet):
        packet = bytes(packet)
        if self.debug:
            print(f"> pkt = {packet.hex()}")
        self.sock.send(struct.pack('>I', len(packet)) + packet)

    def read_packet(self):
        resp_size_bytes = b''
        while len(resp_size_bytes) < 4:
            new_bytes = self.sock.recv(4 - len(resp_size_bytes))
            assert new_bytes, "connection closed"
            resp_size_bytes += new_bytes
        resp_size = (int.from_bytes(resp_size_bytes, 'big') + 2) & 0xffffffff
        if self.u2f_hid_endpoint:
            assert resp_size == 64

        packet = b''
        while len(packet) < resp_size:
            new_bytes = self.sock.recv(resp_size - len(packet))
            assert new_bytes, "connection closed"
            packet += new_bytes
        if self.debug:
            print(f"< pkt = {packet.hex()}")

        return packet

    def close(self):
        self.sock.close()


class LedgerCtapHidDevice(CtapHidDevice):
    """ Overriding fido2.hid.CtapHidDevice

    This is mostly to split call() function in send() and recv() functions.
    This allow Ctap1 and Ctap2 clients to interact with the buttons between
    the sending of a command and the reception of the response.

    This overriding also handle the particularity of sending commands over
    the raw HID endpoint, which means without using the U2F HID encapsulation.
    """
    def __init__(self, descriptor, connection, transport, debug=False):
        self.raw_hid_endpoint = (transport.upper() == "HID")
        self.debug = debug
        super().__init__(descriptor, connection)

    def send(self, cmd, data=b""):

        if self.raw_hid_endpoint:
            # Send raw request without encapsulation
            self._connection.write_packet(data)
            return

        # Send request with U2F encapsulation
        remaining = data
        seq = 0

        header = struct.pack(">IBH", self._channel_id, TYPE_INIT | cmd, len(remaining))

        while remaining or seq == 0:
            size = min(len(remaining), self._packet_size - len(header))
            body, remaining = remaining[:size], remaining[size:]
            packet = header + body
            # Padding packet can be done with anything.
            # Reasonable implementations use 0x00 which might be more intuitive.
            # However using 0xee can help discover APDU Lc field parsing issues.
            # Note: this is what the Fido Conformance tool is using on some tests.
            packet = packet.ljust(self._packet_size, b"\xee")
            self._connection.write_packet(packet)
            header = struct.pack(">IB", self._channel_id, 0x7F & seq)
            seq += 1

    def recv(self, cmd):
        seq = 0
        response = b""

        if self.raw_hid_endpoint:
            return self._connection.read_packet()

        while True:
            recv = self._connection.read_packet()

            r_channel = struct.unpack_from(">I", recv)[0]
            recv = recv[4:]
            if r_channel != self._channel_id:
                raise Exception("Wrong channel")

            if not response:  # Initialization packet
                r_cmd, r_len = struct.unpack_from(">BH", recv)
                recv = recv[3:]
                if r_cmd == TYPE_INIT | cmd:
                    pass  # first data packet
                elif r_cmd == TYPE_INIT | CTAPHID.KEEPALIVE:
                    continue
                elif r_cmd == TYPE_INIT | CTAPHID.ERROR:
                    raise CtapError(struct.unpack_from(">B", recv)[0])
                else:
                    raise CtapError(CtapError.ERR.INVALID_COMMAND)
            else:  # Continuation packet
                r_seq = struct.unpack_from(">B", recv)[0]
                recv = recv[1:]
                if r_seq != seq:
                    raise Exception("Wrong sequence number")
                seq += 1

            response += recv
            if len(response) >= r_len:
                break

        return response[:r_len]

    def exchange(self, cmd, data=b""):
        if self.raw_hid_endpoint and cmd != CTAPHID.MSG:
            # Only CTAPHID.MSG without header are supported over raw HID endpoint
            if cmd == CTAPHID.INIT:
                # Fake CTAPHID.INIT call so that CtapHidDevice().__init__()
                # don't fail. Indeed at init, it makes a call to
                # self.call(CTAPHID.INIT, nonce) which is not really necessary
                # but we don't want to override CtapHidDevice().__init__().
                print("Faking CTAPHID.INIT over HID endpoint")
                response = data  # Nonce
                u2fhid_version = 0x02
                capabilities = CAPABILITY.CBOR
                response += struct.pack(">IBBBBB", self._channel_id,
                                        u2fhid_version, 0, 0, 0, capabilities)
                return response

            raise ValueError("Unexpected cmd over HID endpoint {}".format(hex(cmd)))

        self.send(cmd, data)
        return self.recv(cmd)

    def call(self, cmd, data=b"", event=None, on_keepalive=None):
        if event:
            raise ValueError("event handling is not supported")

        if on_keepalive:
            raise ValueError("on_keepalive handling is not supported")

        return self.exchange(cmd, data)


class TestClient:
    def __init__(self, device, ragger_backend, navigator, transport, debug=False):
        self.model = device.name
        self.ragger_backend = ragger_backend
        self.navigator = navigator
        self.debug = debug

        # USB transport configuration
        self.USB_transport = transport
        self.use_U2F_endpoint = (self.USB_transport.upper() == "U2F")
        self.use_raw_HID_endpoint = (self.USB_transport.upper() == "HID")
        if not self.use_U2F_endpoint and not self.use_raw_HID_endpoint:
            assert ValueError("Invalid endpoint")

    def start(self):
        try:
            hid_dev = LedgerCtapHidConnection(self.USB_transport,
                                              self.debug)
            descriptor = HidDescriptor("sim", 0, 0, 64, 64, "speculos", "0000")
            self.dev = LedgerCtapHidDevice(descriptor, hid_dev,
                                           self.USB_transport, self.debug)

            self.ctap1 = LedgerCtap1(self.dev, self.model, self.navigator,
                                     self.debug)

        except Exception as e:
            raise e

    def simulate_reboot(self):
        # Warning, data saved in NVM won't be restored.
        # So this is not a perfect reboot simulation.
        self.ragger_backend._client.stop()
        self.ragger_backend._client.start()
        self.start()
