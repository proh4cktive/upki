# -*- coding:utf-8 -*-

import json

class Options(object):
    def __init__(self):
        self.KeyLen = [
                    1024,
                    2048,
                    4096
                ]
        self.CertTypes = [
                    "user",
                    "server",
                    "email",
                    "sslCA"
                ]
        self.Digest = [
                    "md5",
                    "sha1",
                    "sha256",
                    "sha512"
                ]
        self.ExtendedUsages = [
                    "serverAuth",
                    "clientAuth",
                    "codeSigning",
                    "emailProtection",
                    "timeStamping",
                    "OCSPSigning",
                    # "ipsecIKE",
                    # "msCodeInd",
                    # "msCodeCom",
                    # "msCTLSign",
                    # "msEFS"
                ]
        self.Fields = [
                    "C",
                    "ST",
                    "L",
                    "O",
                    "OU",
                    "CN",
                    "emailAddress"
                ]
        self.KeyTypes = [
                    "rsa",
                    "dsa"
                ]
        self.Types = [
                    "server",
                    "client",
                    "email",
                    "objsign",
                    "sslCA",
                    "emailCA"
                ]
        self.Usages = [
                    "digitalSignature",
                    "nonRepudiation",
                    "keyEncipherment",
                    "dataEncipherment",
                    "keyAgreement",
                    "keyCertSign",
                    "cRLSign",
                    "encipherOnly",
                    "decipherOnly"
                ]

    def __str__(self):
        return json.dumps(vars(self), sort_keys=True, indent=indent)
    

    def json(self, minimize=False):
        indent = 0 if minimize else 4
        return json.dumps(vars(self), sort_keys=True, indent=indent)

    def clean(self, data, field):
        if data is None:
            raise Exception('Null data')
        if field is None:
            raise Exception('Null field')

        if field not in vars(self).keys():
            raise NotImplementedError('Unsupported field')

        allowed = getattr(self, field)
        if data not in allowed:
            raise Exception('Invalid value')

        return data