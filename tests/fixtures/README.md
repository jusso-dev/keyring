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

The private keys in these files protect nothing. Don't reuse them.
