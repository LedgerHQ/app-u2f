from utils import generate_random_bytes


def test_authenticate_ok(client):
    # Make sure that app update will still works with previously generated
    # key handles and public key already shared with some Relying Party
    app_param_hex = "f430952043cccefab769aa034f8f38d6"
    app_param_hex += "9c21d3d685ed7044a3602c4f8901ec73"
    app_param = bytearray.fromhex(app_param_hex)

    key_handle_hex = "2a3d03e1045aab9fc7415b5a62a7373c"
    key_handle_hex += "3282d0e16e3b95e7727139951a993144"
    key_handle_hex += "2d6d41e817c0cfc1082b37909feca72b"
    key_handle_hex += "043ddac0c18301f0536bd6df821282eb"
    key_handle = bytearray.fromhex(key_handle_hex)

    public_key_hex = "0411410f5ca231c9935585190628ad66"
    public_key_hex += "ea3577b690c88f7e7ada2d0531b1845d"
    public_key_hex += "350c8325f960de51a6938ca45da1d40d"
    public_key_hex += "84360c8d50df3633c80920645ccd604f61"
    public_key = bytearray.fromhex(public_key_hex)

    challenge = generate_random_bytes(32)

    authentication_data = client.ctap1.authenticate(challenge,
                                                    app_param,
                                                    key_handle)

    authentication_data.verify(app_param, challenge, public_key)
