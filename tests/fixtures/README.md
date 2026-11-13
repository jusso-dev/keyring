# Test fixtures

Throwaway files for the test suite only. They were generated locally with
`openssl` for the subject `CN=keyring.test`, are self-signed, and are not
trusted or used anywhere else.

| File | What it is |
| --- | --- |
| `test-cert.pem` | Public certificate only |
| `test-plain.pfx` | PFX with the certificate stored unencrypted. Password `test-password` |
| `test-encrypted.pfx` | PFX with everything encrypted. Password `test-password` |
| `test-bundle.pem` | Certificate and its private key in one PEM |
| `test-chain.pem` | Public certificates only, CA first: `CN=Keyring Test CA`, then `CN=leaf.keyring.test` signed by it with the key from `test-bundle.pem`. The CA's key was deleted |

The private keys in these files protect nothing. Don't reuse them.
| `test-rsa-pub.pem`, `test-rsa-n.txt` | Public half of a throwaway RSA 2048 key, as PEM and as the JWK `n` value. The private key was deleted |
| `test-ec-pub.pem`, `test-ec-x.txt`, `test-ec-y.txt` | Public half of a throwaway EC P-256 key, as PEM and as JWK `x` and `y`. The private key was deleted |
| `demo-cert.pem`, `demo-cert-soon.pem` | Public certificates only, self-signed, for the screenshot demo in `tests/screenshots.rs`: `CN=payments-api.demo.example` and `CN=internal-gateway.demo.example` (ends 25-11-2026). The private keys were deleted |
