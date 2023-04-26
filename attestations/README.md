# Generating U2F attestations for a device


## CA generation

CA files can be generated using `createCA.sh <env>` script.
It takes one parameter:
- `<env>`: an env (`test`, `prod`, ...) that is used when generating the outputs.

They will be generated as:
- `ca_key_file="data/<env>/ca-priv-key.pem"`
- `ca_cert_file="data/<env>/ca-cert.pem"`

CA files for env `prod` have already been generated.
Only the `ca-cert.pem` is committed. If you need the private key (to generate a certificate for a new device), then ask the right person!

CA files for env `test` have already been generated and are committed.
They can be accessed from the public repository and should therefore never be used in production.


## Configuration generation

You should create an `cnf/<version>/openssl_cert_<model>.cnf` file.
You can start from a copy of an other model and should update:
- The `req_distinguished_name` CN field.
- For U2F:
	- An extension should be added to the certificate using `v3_req` `id-fido-u2f-ce-transports` OID (`1.3.6.1.4.1.45724.2.1.1`) with set value depending on supported transports. See https://fidoalliance.org/specs/fido-u2f-v1.2-ps-20170411/fido-u2f-authenticator-transports-extension-v1.2-ps-20170411.html#fido-u2f-extensions


## Device private key and certificate generation

Then you can run `./createKeyAndCert.sh <env> <version> <model>` to generate the device key and certificate.
It takes three parameters:
- `<env>`: an env (`test`, `prod`, ...) that is used when retrieving the CA inputs and generating the outputs.
- `<version>`: either `U2F`
- `<model>`: device model (`nanos`, `nanosp`, `nanox`, ...)

They will be generated as:
- `key_file="data/<env>/<version>/<model>-priv-key.pem"`
- `cert_file="data/<env>/<version>/<model>-cert.der"`

Keys and certificates have already been generated for env `prod`.
Only the `<model>-cert.pem` are committed. If you need the private keys, then ask the right person!

Keys and certificates have already been generated for env `test` and they are committed.
They can be accessed from the public repository and should therefore never be used in production.


## Generate hex key and certificate

You can then retrieve the attestation data and key in a form that should be put in `src/crypto_data.h`.
To do so, just run `./generateCryptoData.py <env> <version> <model>` and the data should be output in the terminal.

This repository contains a `src/crypto_data.h` file that is committed and contains data from `test` env and public data from `prod` env.
Never use `test` data in production.
