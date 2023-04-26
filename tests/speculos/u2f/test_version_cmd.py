import pytest

from fido2.ctap1 import Ctap1, ApduError

from ctap1_client import APDU


def test_get_version_raw(client):
    version = client.ctap1.send_apdu(cla=0x00,
                                     ins=Ctap1.INS.VERSION,
                                     p1=0x00,
                                     p2=0x00,
                                     data=b"").decode()

    assert version == "U2F_V2"


def test_get_version(client):
    version = client.ctap1.get_version()

    assert version == "U2F_V2"


def test_get_version_bad_length(client):
    with pytest.raises(ApduError) as e:
        client.ctap1.send_apdu(cla=0x00,
                               ins=Ctap1.INS.VERSION,
                               p1=0x00,
                               p2=0x00,
                               data=b"a").decode()
    assert e.value.code == APDU.SW_WRONG_LENGTH


def test_get_version_wrong_p1p2(client):
    # Only supported P1 is 0x00
    for p1 in range(1, 0xff + 1):
        with pytest.raises(ApduError) as e:
            client.ctap1.send_apdu(cla=0x00,
                                   ins=Ctap1.INS.VERSION,
                                   p1=p1,
                                   p2=0x00,
                                   data=b"")
        assert e.value.code == APDU.SW_INCORRECT_P1P2

    # Only supported P2 is 0x00
    for p2 in range(1, 0xff + 1):
        with pytest.raises(ApduError) as e:
            client.ctap1.send_apdu(cla=0x00,
                                   ins=Ctap1.INS.VERSION,
                                   p1=0x00,
                                   p2=p2,
                                   data=b"")
        assert e.value.code == APDU.SW_INCORRECT_P1P2
