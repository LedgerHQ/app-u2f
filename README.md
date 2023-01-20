# Ledger App FIDO U2F

Ledger App FIDO U2F for Ledger devices.

This application implements an U2F Authenticator for Ledger devices. 

A great introduction to WebAuthn can be found [here](https://webauthn.me/introduction).
Note that U2F is only a subpart of WebAuthn.
You can also use [this demo](https://webauthn.me/) to test this app, or use [its debugger](https://webauthn.me/debugger) to do some advance testing.


## Specifications

* FIDO U2F (CTAP 1) specification can be found [here](https://fidoalliance.org/specs/fido-u2f-v1.2-ps-20170411/fido-u2f-raw-message-formats-v1.2-ps-20170411.html).


## Building

On a development environment:

* Set `BOLOS_SDK` to a place where the Nano S SDK has been cloned (<https://github.com/LedgerHQ/nanos-secure-sdk>)
* Install `arm-none-eabi-gcc` and `clang`
* Run `make`


## Acronyms

Acronyms not specific to the project:

* U2F: Universal 2nd Factor (open authentication standard, precedes FIDO2)
* WebAuthn: Web Authentication (component of FIDO2 specifications, described on [FIDO Alliance's website](https://fidoalliance.org/fido2/fido2-web-authentication-webauthn/))


## Testing the app

See dedicated `README.md` in tests `directory`.
