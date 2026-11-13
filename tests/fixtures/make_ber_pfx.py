#!/usr/bin/env python3
"""Re-encode a DER PKCS #12 file as BER, the way older Windows tools write it.

    python3 -I make_ber_pfx.py in.pfx out.pfx

The outer constructed elements (the PFX, the authSafe ContentInfo and macData)
get indefinite lengths (0x80 ... 00 00), and the authSafe OCTET STRING becomes
a constructed, indefinite-length OCTET STRING in 1024-byte chunks. The octets
inside are unchanged, so the MAC still verifies. The bags inside the authSafe
stay DER: the MAC covers their exact bytes.

Only the standard library is used. Check the output with
`openssl asn1parse -inform DER -i` (it shows `l=inf`) and
`openssl pkcs12 -info -noout` (the MAC still verifies).
"""

import sys

SEQUENCE = 0x30
OCTET_STRING = 0x04
OCTET_STRING_CONSTRUCTED = 0x24
CONTEXT_0 = 0xA0
CHUNK = 1024


def read_tlv(data, i):
    """One definite-length DER TLV at data[i]: (tag, value, next index)."""
    tag = data[i]
    first = data[i + 1]
    j = i + 2
    if first < 0x80:
        length = first
    else:
        n = first & 0x7F
        if n == 0 or n > 4:
            raise ValueError(f"unexpected length form at {i}")
        length = int.from_bytes(data[j : j + n], "big")
        j += n
    return tag, data[j : j + length], j + length


def children(value):
    out, i = [], 0
    while i < len(value):
        tag, v, i = read_tlv(value, i)
        out.append((tag, v))
    return out


def der_len(n):
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b


def indefinite(tag, parts):
    return bytes([tag, 0x80]) + b"".join(parts) + b"\x00\x00"


def chunked_octets(value):
    chunks = [
        bytes([OCTET_STRING]) + der_len(len(value[k : k + CHUNK])) + value[k : k + CHUNK]
        for k in range(0, len(value), CHUNK)
    ]
    return indefinite(OCTET_STRING_CONSTRUCTED, chunks)


def reencode(tag, value, depth, parent):
    """Indefinite lengths for SEQUENCEs and [0]s down to depth 3: the PFX,
    the authSafe ContentInfo and its [0], and macData with its DigestInfo and
    AlgorithmIdentifier. The OCTET STRING inside the authSafe's [0] is
    chunked. Everything else is copied as it was."""
    if tag == OCTET_STRING and parent == CONTEXT_0:
        return chunked_octets(value)
    if tag in (SEQUENCE, CONTEXT_0) and depth <= 3:
        return indefinite(
            tag, [reencode(t, v, depth + 1, tag) for t, v in children(value)]
        )
    return bytes([tag]) + der_len(len(value)) + value


def main():
    src, dst = sys.argv[1], sys.argv[2]
    der = open(src, "rb").read()
    tag, value, end = read_tlv(der, 0)
    if tag != SEQUENCE or end != len(der) or not value.startswith(b"\x02\x01\x03"):
        sys.exit("not a DER PKCS #12 file")
    ber = reencode(tag, value, 0, None)
    if ber == der or ber[1] != 0x80:
        sys.exit("re-encoding changed nothing")
    open(dst, "wb").write(ber)
    print(f"{len(der)} bytes DER -> {len(ber)} bytes BER")


if __name__ == "__main__":
    main()
