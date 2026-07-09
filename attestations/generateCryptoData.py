#!/bin/python3
import argparse
import os
import subprocess

attestation_key_prefix = "static const uint8_t {}_{}_{}_ATTESTATION_KEY[] ="
attestation_cert_prefix = "static const uint8_t {}_{}_{}_ATTESTATION_CERT[] ="


parser = argparse.ArgumentParser()
parser.add_argument("env", type=str, help="CA, key and cert env")
parser.add_argument("version", type=str, help="target protocol version", choices=["U2F"])
parser.add_argument("model", type=str, help="device model")

args = parser.parse_args()

files_path = f"data/{args.env}/{args.version}/{args.model}-"
key_file = files_path + "priv-key.pem"
cert_file = files_path + "cert.der"

env = args.env.upper()
version = args.version.upper()
model = args.model.upper()

if not os.path.isfile(key_file):
    print(f"error: {key_file} does not exist")
    exit(1)

if not os.path.isfile(cert_file):
    print(f"error: {cert_file} does not exist")
    exit(1)

# Generate ATTESTATION_KEY
cmd = f"openssl ec -in {key_file} -text -noout"
result = subprocess.run(cmd.split(), capture_output=True)
if result.returncode != 0:
    print("Extraction of key failed")
    print("cmd: ", cmd)
    print("stderr: ", result.stderr.decode())
    exit(1)
stdout = result.stdout.decode()
key_bytes = "".join(stdout.split("\n")[2:5]).replace(" ", "").split(":")

key_line_1 = "    " + ", ".join([f"0x{x}" for x in key_bytes[:16]])
key_line_2 = "    " + ", ".join([f"0x{x}" for x in key_bytes[16:]])
key_data = ",\n".join([key_line_1, key_line_2])

key = attestation_key_prefix.format(env, version, model) + " {\n" + key_data + "};"
print(key)

# Generate ATTESTATION_CERT
with open(cert_file, "rb") as f:
    cert_bytes = f.read()

cert_lines = []
line_bytes = []
for x in cert_bytes:
    line_bytes.append(f"0x{x:02x}")
    if len(line_bytes) == 16:
        cert_lines.append("    " + ", ".join(line_bytes))
        line_bytes = []
cert_lines.append("    " + ", ".join(line_bytes))

cert_data = ",\n".join(cert_lines)

cert = attestation_cert_prefix.format(env, version, model) + " {\n" + cert_data + "};"
print(cert)
