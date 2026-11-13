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
| `test-ber.pfx` | A PFX in BER, with indefinite lengths, as older Windows tools write it. Its own throwaway key and certificate, `CN=keyring-ber.test`. Password `test-password`. See "The BER PFX" below |

The private keys in these files protect nothing. Don't reuse them.
| `test-rsa-pub.pem`, `test-rsa-n.txt` | Public half of a throwaway RSA 2048 key, as PEM and as the JWK `n` value. The private key was deleted |
| `test-ec-pub.pem`, `test-ec-x.txt`, `test-ec-y.txt` | Public half of a throwaway EC P-256 key, as PEM and as JWK `x` and `y`. The private key was deleted |

## The BER PFX

`test-ber.pfx` was made with a fresh key that was deleted straight after, then re-encoded by `make_ber_pfx.py` (standard library only):

```sh
W=$(mktemp -d) && cd "$W"
openssl req -x509 -newkey rsa:2048 -nodes -keyout key.pem -out cert.pem \
  -subj "/CN=keyring-ber.test" -days 3650
openssl pkcs12 -export -inkey key.pem -in cert.pem -certpbe NONE \
  -passout pass:test-password -out der.pfx
rm key.pem
python3 -I <repo>/tests/fixtures/make_ber_pfx.py der.pfx <repo>/tests/fixtures/test-ber.pfx
cd - && rm -rf "$W"
```

The script gives the outer structures indefinite lengths (`0x80`, ended by `00 00`): the PFX itself, the authSafe ContentInfo and its `[0]`, and the MAC data. It turns the authSafe's OCTET STRING into a constructed one in 1024-byte pieces. The bytes inside are unchanged, so the MAC still checks, and the bags inside stay DER. Check it with:

```sh
openssl asn1parse -inform DER -in test-ber.pfx -i    # l=inf on the outer parts
openssl pkcs12 -in test-ber.pfx -passin pass:test-password -info -noout
```

Running the commands again makes a different key and file, which is fine: nothing depends on its bytes.
