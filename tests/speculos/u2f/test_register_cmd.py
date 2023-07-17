import pytest
import socket

from cryptography.x509 import load_der_x509_certificate

from ragger.navigator import NavInsID, NavIns

import fido2

from fido2.ctap1 import ApduError, Ctap1, RegistrationData
from fido2.hid import CTAPHID
from fido2.webauthn import AttestationObject

from client import TESTS_SPECULOS_DIR, LedgerAttestationVerifier
from ctap1_client import APDU, U2F_P1
from utils import FIDO_RP_ID_HASH_1, generate_random_bytes


def test_register_ok(client, test_name):
    challenge = generate_random_bytes(32)
    app_param = FIDO_RP_ID_HASH_1

    compare_args = (TESTS_SPECULOS_DIR, test_name)

    registration_data = client.ctap1.register(challenge, app_param,
                                              check_screens="full",
                                              compare_args=compare_args)
    registration_data.verify(app_param, challenge)


def test_register_certificate(client):
    challenge = generate_random_bytes(32)
    app_param = generate_random_bytes(32)

    registration_data = client.ctap1.register(challenge, app_param)
    registration_data.verify(app_param, challenge)

    verifier = LedgerAttestationVerifier(client.model)
    attestation = AttestationObject.from_ctap1(app_param, registration_data)
    verifier.verify_attestation(attestation, challenge)

    # Check certificate extension as it is not done by FidoU2FAttestation().verify()
    cert = load_der_x509_certificate(registration_data.certificate)
    assert len(cert.extensions) == 1

    # Check that OID correspond to id-fido-u2f-ce-transports
    assert cert.extensions[0].oid.dotted_string == "1.3.6.1.4.1.45724.2.1.1"
    assert cert.extensions[0].critical is False

    # Check that value correspond to exposed transports
    assert cert.extensions[0].value.value == bytes.fromhex("03020520")


def test_register_user_refused(client, test_name):
    challenge = generate_random_bytes(32)
    app_param = FIDO_RP_ID_HASH_1

    compare_args = (TESTS_SPECULOS_DIR, test_name)

    with pytest.raises(ApduError) as e:
        client.ctap1.register(challenge, app_param, user_accept=False,
                              check_screens="full",
                              compare_args=compare_args)

    assert e.value.code == APDU.SW_PROPRIETARY_INTERNAL


def test_register_duplicate(client):
    challenge = generate_random_bytes(32)
    app_param = generate_random_bytes(32)

    registration_data = client.ctap1.register(challenge, app_param)
    registration_data.verify(app_param, challenge)

    # Nothing is saved on the authenticator side, therefore we should
    # be able to register again with the exact same parameter.
    registration_data = client.ctap1.register(challenge, app_param)
    registration_data.verify(app_param, challenge)

    # Also check with just a challenge change
    challenge = generate_random_bytes(32)
    registration_data = client.ctap1.register(challenge, app_param)
    registration_data.verify(app_param, challenge)


def test_register_multiple_ok(client):
    for _ in range(5):
        challenge = generate_random_bytes(32)
        app_param = generate_random_bytes(32)

        registration_data = client.ctap1.register(challenge, app_param)
        registration_data.verify(app_param, challenge)


def test_register_wrong_app_param(client):
    challenge = generate_random_bytes(32)
    app_param = generate_random_bytes(32)

    registration_data = client.ctap1.register(challenge, app_param)

    # Change app_param first bit
    app_param = bytearray(app_param)
    app_param[0] ^= 0x80

    with pytest.raises(fido2.attestation.base.InvalidSignature):
        registration_data.verify(app_param, challenge)


def test_register_wrong_challenge(client):
    challenge = bytearray(generate_random_bytes(32))
    app_param = generate_random_bytes(32)

    registration_data = client.ctap1.register(challenge, app_param)

    # Change challenge first bit
    challenge[0] ^= 0x40

    with pytest.raises(fido2.attestation.base.InvalidSignature):
        registration_data.verify(app_param, challenge)


def test_register_length_too_short(client):
    challenge = generate_random_bytes(32)

    # Create app_param one byte too short
    app_param = generate_random_bytes(31)

    with pytest.raises(ApduError) as e:
        client.ctap1.register(challenge, app_param, user_accept=None)
    assert e.value.code == APDU.SW_WRONG_LENGTH


def test_register_length_too_long(client):
    challenge = generate_random_bytes(32)

    # Create app_param one byte too long
    app_param = generate_random_bytes(33)

    with pytest.raises(ApduError) as e:
        client.ctap1.register(challenge, app_param, user_accept=None)
    assert e.value.code == APDU.SW_WRONG_LENGTH


def test_register_raw(client):
    if client.use_raw_HID_endpoint:
        pytest.skip("Does not work with this transport")

    challenge = generate_random_bytes(32)
    app_param = generate_random_bytes(32)
    data = challenge + app_param

    # On U2F endpoint, the device should return APDU.SW_CONDITIONS_NOT_SATISFIED
    # until user validate.
    for i in range(5):
        client.ctap1.send_apdu_nowait(cla=0x00,
                                      ins=Ctap1.INS.REGISTER,
                                      p1=0x00,
                                      p2=0x00,
                                      data=data)

        response = client.ctap1.device.recv(CTAPHID.MSG)

        with pytest.raises(ApduError) as e:
            response = client.ctap1.parse_response(response)

        assert e.value.code == APDU.SW_CONDITIONS_NOT_SATISFIED

    # Confirm request
    client.ctap1.confirm()

    client.ctap1.send_apdu_nowait(cla=0x00,
                                  ins=Ctap1.INS.REGISTER,
                                  p1=0x00,
                                  p2=0x00,
                                  data=data)

    response = client.ctap1.device.recv(CTAPHID.MSG)
    client.ctap1.wait_for_return_on_dashboard()
    response = client.ctap1.parse_response(response)

    registration_data = RegistrationData(response)

    registration_data.verify(app_param, challenge)


def test_register_raw_u2f_fake_channel_security_crc(client):
    if client.use_raw_HID_endpoint:
        pytest.skip("Does not work with this transport")

    # Only spec valid P1 is 0x00, however some platforms wrongly uses
    # 0x03 as P1 for enroll:
    # https://searchfox.org/mozilla-central/source/third_party/rust/authenticator/src/consts.rs#55
    # https://github.com/Yubico/python-u2flib-host/issues/34
    # We choose to allow it.
    valid_p1 = [
        0x00,
        U2F_P1.REQUEST_USER_PRESENCE,
    ]
    for p1 in valid_p1:
        challenge = bytearray(generate_random_bytes(32))
        app_param = generate_random_bytes(32)
        data = challenge + app_param

        # On U2F endpoint, the device should return APDU.SW_CONDITIONS_NOT_SATISFIED
        # until user validate, except if the request change!
        client.ctap1.send_apdu_nowait(cla=0x00,
                                      ins=Ctap1.INS.REGISTER,
                                      p1=p1,
                                      p2=0x00,
                                      data=data)

        response = client.ctap1.device.recv(CTAPHID.MSG)

        with pytest.raises(ApduError) as e:
            response = client.ctap1.parse_response(response)

        assert e.value.code == APDU.SW_CONDITIONS_NOT_SATISFIED

        # Confirm request
        client.ctap1.confirm()

        # Change challenge first bit
        challenge[0] ^= 0x40
        data = challenge + app_param

        client.ctap1.send_apdu_nowait(cla=0x00,
                                      ins=Ctap1.INS.REGISTER,
                                      p1=p1,
                                      p2=0x00,
                                      data=data)

        with pytest.raises(socket.timeout) as e:
            response = client.ctap1.device.recv(CTAPHID.MSG)

        if client.model == "stax":
            # Patch issue with click ignored on Speculos after a EXCEPTION_IO_RESET
            client.navigator.navigate([NavIns(NavInsID.TAPPABLE_CENTER_TAP)],
                                      screen_change_after_last_instruction=False)

        # App should then recover and allow new requests
        client.ctap1.wait_for_return_on_dashboard()

        challenge = bytearray(generate_random_bytes(32))
        app_param = generate_random_bytes(32)
        registration_data = client.ctap1.register(challenge, app_param)
        registration_data.verify(app_param, challenge)


def test_register_raw_u2f_fake_channel_security_length(client):
    challenge = generate_random_bytes(32)
    app_param = generate_random_bytes(32)
    data = challenge + app_param

    # This test is specific for U2F endpoint
    if not client.use_U2F_endpoint:
        pytest.skip("Does not work with this transport")

    # On U2F endpoint, the device should return APDU.SW_CONDITIONS_NOT_SATISFIED
    # until user validate, except if the request change!
    client.ctap1.send_apdu_nowait(cla=0x00,
                                  ins=Ctap1.INS.REGISTER,
                                  p1=0x00,
                                  p2=0x00,
                                  data=data)

    response = client.ctap1.device.recv(CTAPHID.MSG)

    with pytest.raises(ApduError) as e:
        response = client.ctap1.parse_response(response)

    assert e.value.code == APDU.SW_CONDITIONS_NOT_SATISFIED

    # Confirm request
    client.ctap1.confirm()

    # Change challenge length
    challenge2 = challenge[:-1]
    data = challenge2 + app_param

    client.ctap1.send_apdu_nowait(cla=0x00,
                                  ins=Ctap1.INS.REGISTER,
                                  p1=0x00,
                                  p2=0x00,
                                  data=data)

    with pytest.raises(socket.timeout) as e:
        response = client.ctap1.device.recv(CTAPHID.MSG)

    if client.model == "stax":
        # Patch issue with click ignored on Speculos after a EXCEPTION_IO_RESET
        client.navigator.navigate([NavIns(NavInsID.TAPPABLE_CENTER_TAP)],
                                  screen_change_after_last_instruction=False)

    # App should then recover and allow new requests
    client.ctap1.wait_for_return_on_dashboard()

    challenge = generate_random_bytes(32)
    app_param = generate_random_bytes(32)
    registration_data = client.ctap1.register(challenge, app_param)
    registration_data.verify(app_param, challenge)


def test_register_wrong_p1p2(client):
    challenge = generate_random_bytes(32)
    app_param = generate_random_bytes(32)
    data = challenge + app_param

    # Only spec valid P1 is 0x00, however some platforms wrongly uses
    # 0x03 as P1 for enroll:
    # https://searchfox.org/mozilla-central/source/third_party/rust/authenticator/src/consts.rs#55
    # https://github.com/Yubico/python-u2flib-host/issues/34
    # We choose to allow it.
    valid_p1 = [
        0x00,
        U2F_P1.REQUEST_USER_PRESENCE,
    ]
    for p1 in range(0xff + 1):
        if p1 in valid_p1:
            continue
        with pytest.raises(ApduError) as e:
            client.ctap1.send_apdu(cla=0x00,
                                   ins=Ctap1.INS.REGISTER,
                                   p1=p1,
                                   p2=0x00,
                                   data=data)
        assert e.value.code == APDU.SW_INCORRECT_P1P2

    # Only supported P2 is 0x00
    for p2 in range(1, 0xff + 1):
        with pytest.raises(ApduError) as e:
            client.ctap1.send_apdu(cla=0x00,
                                   ins=Ctap1.INS.REGISTER,
                                   p1=0x00,
                                   p2=p2,
                                   data=data)
        assert e.value.code == APDU.SW_INCORRECT_P1P2
