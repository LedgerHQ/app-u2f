# blue-app-u2f
FIDO U2F Application for Ledger Blue 

This application implements a U2F Authenticator for Ledger Blue - missing an integration guide and a few power management cleanups. 

To compile, generate src/u2f_crypto_data.h with 

```
static const uint8_t ATTESTATION_KEY[] = {
	// 32 bytes secp256k1 attestation private key
};

static const uint8_t ATTESTATION_CERT[] = {
	// Attestation certificate
};
```

