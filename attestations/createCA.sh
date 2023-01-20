#!/bin/bash

if [ -z "$1" ]
  then
    echo "Env (test|prod|...) should be supplied as argument"
    exit
fi
env="$1"

cnf_file="cnf/openssl_CA.cnf"
dir_ca_path="data/$env"
ca_key_file="$dir_ca_path/ca-priv-key.pem"
ca_cert_file="$dir_ca_path/ca-cert.pem"

if [ ! -f $cnf_file ]
  then
    echo "File <$cnf_file> not found!"
    exit
fi

if [ -f $ca_key_file ]
  then
    echo "File <$ca_key_file> already exist!"
    exit
fi

if [ -f $ca_cert_file ]
  then
    echo "File <$ca_cert_file> already exist!"
    exit
fi

# Create dir if not present
mkdir -p $dir_ca_path

# Generate private key
openssl ecparam -out $ca_key_file -name prime256v1 -genkey

# Generate random file if missing
openssl rand -writerand .rnd

# Generate associated certificate
openssl req -x509 -new -config $cnf_file -days 3650 -out $ca_cert_file -key $ca_key_file

# Delete random file
rm .rnd
