import pytest
import sys
import time

from ragger.navigator import NavInsID, NavIns

from client import TESTS_SPECULOS_DIR
from utils import generate_random_bytes, fido_known_appid


def test_u2f_screens_idle(client, test_name, device):
    # Refresh navigator screen content reference
    time.sleep(0.1)
    client.navigator._backend.get_current_screen_content()

    if device.is_nano:
        instructions = []
        # Screen 0 -> 1
        instructions.append(NavIns(NavInsID.RIGHT_CLICK))
        # Screen 1 -> 2
        instructions.append(NavIns(NavInsID.RIGHT_CLICK))
    else:
        instructions = [
            NavIns(NavInsID.USE_CASE_HOME_INFO),
            NavIns(NavInsID.USE_CASE_SETTINGS_SINGLE_PAGE_EXIT)
        ]

    client.navigator.navigate_and_compare(TESTS_SPECULOS_DIR, test_name, instructions,
                                          screen_change_before_first_instruction=False)


@pytest.mark.skipif(
    "--fast" in sys.argv,
    reason="running in fast mode",
)
def test_u2f_screens_fido_known_list(client, test_name):
    # test on all fido_known_appid
    for idx, app_param in enumerate(fido_known_appid.keys()):
        # Test registration
        app_name = str(idx) + "_" + fido_known_appid[app_param]
        print("Registering:", app_name)
        challenge = generate_random_bytes(32)
        test_part_name = test_name + "/reg/" + app_name
        compare_args = (TESTS_SPECULOS_DIR, test_part_name)
        registration_data = client.ctap1.register(challenge, app_param,
                                                  check_screens="fast",
                                                  compare_args=compare_args)
        registration_data.verify(app_param, challenge)

        # Test authentication
        print("Logging:", app_name)
        challenge = generate_random_bytes(32)
        test_part_name = test_name + "/log/" + app_name
        compare_args = (TESTS_SPECULOS_DIR, test_part_name)
        authentication_data = client.ctap1.authenticate(challenge,
                                                        app_param,
                                                        registration_data.key_handle,
                                                        check_screens="fast",
                                                        compare_args=compare_args)

        authentication_data.verify(app_param, challenge,
                                   registration_data.public_key)
