#!/bin/bash

if [ -z "$1" ]
  then
    echo "Env (test|prod|...) should be supplied as argument"
    exit
fi
env="$1"

if [ -z "$2" ]
  then
    echo "U2F should be supplied as argument"
    exit
fi
version=$2

if [ -z "$3" ]
  then
    echo "Device model should be supplied as argument"
    exit
fi
model=$3

cnf_file="cnf/$version/openssl_cert_$model.cnf"
dir_ca_path="data/$env"
ca_key_file="$dir_ca_path/ca-priv-key.pem"
ca_cert_file="$dir_ca_path/ca-cert.pem"
dir_path="data/$env/$version"
key_file="$dir_path/$model-priv-key.pem"
cert_file="$dir_path/$model-cert.der"

if [ ! -f $cnf_file ]
  then
    echo "File <$cnf_file> not found!"
    exit
fi

if [ -f $key_file ]
  then
    echo "File <$key_file> already exist!"
    exit
fi

if [ -f $cert_file ]
  then
    echo "File <$cert_file> already exist!"
    exit
fi

# Create dir if not present
mkdir -p $dir_path

# Generate private key
openssl ecparam -out $key_file -name prime256v1 -genkey

# Generate associated certificate
openssl req -new -key $key_file -config $cnf_file |
openssl x509 -req -CA $ca_cert_file -CAkey $ca_key_file -CAcreateserial \
        -out $cert_file --outform DER -days 3650 \
        -extfile $cnf_file -extensions v3_req
