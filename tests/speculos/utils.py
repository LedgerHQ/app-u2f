import secrets
import struct

from fido2.utils import sha256


FIDO_RP_ID_HASH_1 = bytes.fromhex("000102030405060708090a0b0c0d0e0f"
                                  "101112131415161718191a1b1c1d1e1f")


def prepare_apdu(cla=0, ins=0, p1=0, p2=0, data=b""):
    size = len(data)
    size_h = size >> 16 & 0xFF
    size_l = size & 0xFFFF
    apdu = struct.pack(">BBBBBH", cla, ins, p1, p2, size_h, size_l) + data + b"\0\0"

    return apdu


def generate_random_bytes(length):
    return secrets.token_bytes(length)


def get_rp_id_hash(rp_id):
    return sha256(rp_id.encode("utf8"))


# Extracted from src/fido_known_app.c
fido_known_app = {
    "www.binance.com": "Binance",
    "https://bitbucket.org": "Bitbucket",
    "https://www.bitfinex.com": "Bitfinex",
    "https://vault.bitwarden.com/app-id.json": "Bitwarden",
    "coinbase.com": "Coinbase",
    "https://www.dashlane.com": "Dashlane",
    "https://www.dropbox.com/u2f-app-id.json": "Dropbox",
    "www.dropbox.com": "Dropbox",
    "https://api-9dcf9b83.duosecurity.com": "Duo",
    "https://www.fastmail.com": "FastMail",
    "https://id.fedoraproject.org/u2f-origins.json": "Fedora",
    "https://account.gandi.net/api/u2f/trusted_facets.json": "Gandi",
    "https://github.com/u2f/trusted_facets": "GitHub",
    "https://gitlab.com": "GitLab",
    "https://www.gstatic.com/securitykey/origins.json": "Google",
    "https://keepersecurity.com": "Keeper",
    "https://lastpass.com": "LastPass",
    "https://slushpool.com/static/security/u2f.json": "Slush Pool",
    "https://dashboard.stripe.com": "Stripe",
    "https://u2f.bin.coffee": "u2f.bin.coffee",
    "webauthn.bin.coffee": "webauthn.bin.coffee",
    "webauthn.io": "WebAuthn.io",
    "webauthn.me": "WebAuthn.me",
    "demo.yubico.com": "demo.yubico.com",
}
fido_known_appid = {get_rp_id_hash(x): y for x, y in fido_known_app.items()}


def parse_identifier_screen(app_param, speculos_client):
    identifier_text = speculos_client.parse_bnnn_paging_screen("Identifier")

    expected = app_param.hex().upper()
    if identifier_text != expected:
        raise ValueError("Expecting {} instead of {}".format(
                         repr(expected), repr(identifier_text)))
