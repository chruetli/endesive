#!/usr/bin/env python3
# *-* coding: utf-8 *-*
"""
Test: sign a PDF that was encrypted by qpdf with an empty password and
256-bit AES (qpdf --encrypt "" "" 256 -- in.pdf out.pdf).

This is the same flow as pdf-sign-cms.py, just pointed at the AES-256
encrypted fixture and using the correct (empty) PDF password.
"""
import sys
import datetime
from cryptography.hazmat import backends
from cryptography.hazmat.primitives.serialization import pkcs12

from endesive.pdf import cms


def main():
    date = datetime.datetime.now(datetime.UTC)
    date = date.strftime("D:%Y%m%d%H%M%S+00'00'")
    dct = {
        "aligned": 8192,
        "sigflags": 3,
        "sigflagsft": 132,
        "sigpage": 0,
        "signature": "Dokument podpisany cyfrowo",
        "contact": "contact:mak@trisoft.com.pl",
        "location": "Szczecin",
        "signingdate": date,
        "reason": "Dokument podpisany cyfrowo",
        # the PDF itself was encrypted by qpdf with an EMPTY password
        "password": "",
    }
    with open("ca/demo2_user1.p12", "rb") as fp:
        p12 = pkcs12.load_key_and_certificates(
            fp.read(), b"1234", backends.default_backend()
        )
    fname = "pdf-aes256.pdf"
    if len(sys.argv) > 1:
        fname = sys.argv[1]
    datau = open(fname, "rb").read()
    datas = cms.sign(datau, dct, p12[0], p12[1], p12[2], "sha256")
    fname = fname.replace(".pdf", "-signed-cms.pdf")
    with open(fname, "wb") as fp:
        fp.write(datau)
        fp.write(datas)
    print("wrote", fname)


main()
