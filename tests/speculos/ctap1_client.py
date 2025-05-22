import struct

from enum import IntEnum

from ledgered.devices import Device, DeviceType

from ragger.navigator import Navigator, NavInsID

from fido2.ctap1 import Ctap1, ApduError, RegistrationData, SignatureData
from fido2.hid import CTAPHID
from fido2.ctap import CtapDevice

from utils import prepare_apdu


class APDU(IntEnum):
    """APDU status codes.

    Overriding fido2.ctap1.APDU to add many missing error codes."""

    # ISO7816 standard status codes
    SW_NO_ERROR = 0x9000,
    SW_WRONG_LENGTH = 0x6700,
    SW_CONDITIONS_NOT_SATISFIED = 0x6985,
    SW_WRONG_DATA = 0x6A80,
    SW_INCORRECT_P1P2 = 0x6A86,
    SW_INS_NOT_SUPPORTED = 0x6D00,
    SW_CLA_NOT_SUPPORTED = 0x6E00,

    # Vendor specific status codes
    SW_INTERNAL_EXCEPTION = 0X6F00,
    SW_PROPRIETARY_INTERNAL = 0x6FFF,


class U2F_P1(IntEnum):
    CHECK_IS_REGISTERED = 0x07
    REQUEST_USER_PRESENCE = 0x03
    OPTIONAL_USER_PRESENCE = 0x08


class LedgerCtap1(Ctap1):
    """ Overriding fido2.ctap1.Ctap1

    This is mostly to allow to interact with the screen and the buttons
    during APDU exchange.
    To do so, send_apdu_nowait as been introduced.
    Then, register() and authenticate() Ctap1 functions are overridden
    to add interactions with the screen and the buttons.
    """
    def __init__(self, ctap_device: CtapDevice, device: Device, navigator: Navigator,
                 debug: bool = False):
        super().__init__(ctap_device)
        self.ledger_device = device
        self.navigator = navigator
        self.debug = debug

    def confirm(self):
        if self.ledger_device.type == DeviceType.STAX:
            instructions = [NavInsID.USE_CASE_CHOICE_CONFIRM]
        else:
            instructions = [NavInsID.BOTH_CLICK]
        self.navigator.navigate(instructions,
                                screen_change_after_last_instruction=False)

    def wait_for_return_on_dashboard(self, dismiss: bool = False):
        if dismiss and self.ledger_device.type == DeviceType.STAX:
            # On Stax tap on the center to dismiss the status message faster
            self.navigator.navigate([NavInsID.USE_CASE_STATUS_DISMISS],
                                    screen_change_before_first_instruction=True)

        self.navigator._backend.wait_for_home_screen()

    def parse_response(self, response: bytes):
        status = struct.unpack(">H", response[-2:])[0]
        try:
            status = APDU(status)
        except ValueError:
            pass

        data = response[:-2]
        if status != APDU.SW_NO_ERROR:
            raise ApduError(status, data)
        return data

    def send_raw_apdu(self, apdu):
        response = self.device.exchange(CTAPHID.MSG, apdu)
        return self.parse_response(response)

    def send_apdu(self, cla=0, ins=0, p1=0, p2=0, data=b""):
        apdu = prepare_apdu(cla=cla, ins=ins, p1=p1, p2=p2, data=data)
        return self.send_raw_apdu(apdu)

    def send_apdu_nowait(self, cla=0, ins=0, p1=0, p2=0, data=b""):
        apdu = prepare_apdu(cla=cla, ins=ins, p1=p1, p2=p2, data=data)
        self.device.send(CTAPHID.MSG, apdu)

    def register(self, client_param: bytes, app_param: bytes, user_accept: bool = True,
                 check_screens=None, compare_args=None):
        # Refresh navigator screen content reference
        self.navigator._backend.get_current_screen_content()

        data = client_param + app_param
        self.send_apdu_nowait(ins=Ctap1.INS.REGISTER, data=data)

        instructions = []

        if self.ledger_device.type == DeviceType.STAX:
            if user_accept:
                instructions.append(NavInsID.USE_CASE_CHOICE_CONFIRM)
            elif user_accept is not None:
                instructions.append(NavInsID.USE_CASE_CHOICE_REJECT)
        elif user_accept and check_screens is None:
            # Validate blindly
            instructions.append(NavInsID.BOTH_CLICK)
        elif user_accept is not None:
            # check_screens == None only supported when user accept
            assert check_screens in ["full", "fast"]

            # Screen 0 -> 1
            instructions.append(NavInsID.RIGHT_CLICK)

            # Screen 1 -> 2
            if self.ledger_device.type == DeviceType.NANOS:
                instructions += [NavInsID.RIGHT_CLICK] * 4
            else:
                instructions += [NavInsID.RIGHT_CLICK] * 2

            if check_screens == "full":
                # Screen 2 -> 0
                instructions.append(NavInsID.RIGHT_CLICK)

                # Screen 0 -> 2
                instructions.append(NavInsID.LEFT_CLICK)

            if user_accept:
                # Screen 2 -> 0
                instructions.append(NavInsID.RIGHT_CLICK)

            # Validate
            instructions.append(NavInsID.BOTH_CLICK)

        if check_screens:
            assert compare_args
            root, test_name = compare_args
            # Over U2F endpoint (but not over HID) the device needs the
            # response to be retrieved before continuing the UX flow.
            self.navigator.navigate_and_compare(root, test_name, instructions,
                                                screen_change_after_last_instruction=False)
        elif instructions:
            self.navigator.navigate(instructions,
                                    screen_change_after_last_instruction=False)

        response = self.device.recv(CTAPHID.MSG)
        try:
            response = self.parse_response(response)
        except ApduError as e:
            if e.code == APDU.SW_CONDITIONS_NOT_SATISFIED:
                # This status code is return over U2F endpoint to avoid
                # timeout until the user accept the request.
                # Now that we have validate or abort the request with button
                # press, we can resend the request and receive the "true"
                # request response.
                self.send_apdu_nowait(ins=Ctap1.INS.REGISTER, data=data)
                response = self.device.recv(CTAPHID.MSG)
                response = self.parse_response(response)
            else:
                if user_accept is not None:
                    self.wait_for_return_on_dashboard(dismiss=True)
                raise e

        if user_accept is not None:
            self.wait_for_return_on_dashboard(dismiss=True)

        return RegistrationData(response)

    def authenticate(self, client_param: bytes, app_param: bytes, key_handle: bytes,
                     check_only: bool = False, user_accept: bool = True,
                     check_screens=None, compare_args=None):
        # Refresh navigator screen content reference
        self.navigator._backend.get_current_screen_content()

        key_handle_len = struct.pack(">B", len(key_handle))
        data = client_param + app_param + key_handle_len + key_handle
        p1 = U2F_P1.CHECK_IS_REGISTERED if check_only else U2F_P1.REQUEST_USER_PRESENCE
        self.send_apdu_nowait(ins=Ctap1.INS.AUTHENTICATE, p1=p1, data=data)

        instructions = []
        if self.ledger_device.type == DeviceType.STAX:
            if user_accept:
                instructions.append(NavInsID.USE_CASE_CHOICE_CONFIRM)
            elif user_accept is not None:
                instructions.append(NavInsID.USE_CASE_CHOICE_REJECT)
        elif user_accept and check_screens is None:
            # Validate blindly
            instructions.append(NavInsID.BOTH_CLICK)
        elif user_accept is not None:
            # check_screens == None only supported when user accept
            assert check_screens in ["full", "fast"]

            # Screen 0 -> 1
            instructions.append(NavInsID.RIGHT_CLICK)

            # Screen 1 -> 2
            if self.ledger_device.type == DeviceType.NANOS:
                instructions += [NavInsID.RIGHT_CLICK] * 4
            else:
                instructions += [NavInsID.RIGHT_CLICK] * 2

            if check_screens == "full":
                # Screen 2 -> 0
                instructions.append(NavInsID.RIGHT_CLICK)

                # Screen 0 -> 2
                instructions.append(NavInsID.LEFT_CLICK)

            if user_accept:
                # Screen 2 -> 0
                instructions.append(NavInsID.RIGHT_CLICK)

            # Validate
            instructions.append(NavInsID.BOTH_CLICK)

        if check_screens:
            assert compare_args
            root, test_name = compare_args
            # Over U2F endpoint (but not over HID) the device needs the
            # response to be retrieved before continuing the UX flow.
            self.navigator.navigate_and_compare(root, test_name, instructions,
                                                screen_change_after_last_instruction=False)
        elif instructions:
            self.navigator.navigate(instructions,
                                    screen_change_after_last_instruction=False)

        response = self.device.recv(CTAPHID.MSG)
        try:
            response = self.parse_response(response)
        except ApduError as e:
            if check_only is False and e.code == APDU.SW_CONDITIONS_NOT_SATISFIED:
                # This status code is return over U2F endpoint to avoid
                # timeout until the user accept the request.
                # Now that we have validate or abort the request with button
                # press, we can resend the request and receive the "true"
                # request response.
                self.send_apdu_nowait(ins=Ctap1.INS.AUTHENTICATE,
                                      p1=p1, data=data)
                response = self.device.recv(CTAPHID.MSG)
                response = self.parse_response(response)
            else:
                if user_accept is not None:
                    self.wait_for_return_on_dashboard(dismiss=True)
                raise e

        if user_accept is not None:
            self.wait_for_return_on_dashboard(dismiss=True)

        return SignatureData(response)
