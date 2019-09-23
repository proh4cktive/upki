# -*- coding:utf-8 -*-

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import dsa

import upkica

class PrivateKey(upkica.core.Common):
    def __init__(self, config):
        try:
            super(PrivateKey, self).__init__(config._logger)
        except Exception as err:
            raise Exception('Unable to initialize privateKey: {e}'.format(e=err))

        self._config   = config

        # Private var
        self.__backend = default_backend()

    def generate(self, profile, keyType=None, keyLen=None):
        """Generate Private key based on:
            - profile object (profile)
        """
        if keyLen is None:
            keyLen = profile['keyLen']
        if keyType is None:
            keyType = profile['keyType']

        if keyType == 'rsa':
            try:
                pkey = rsa.generate_private_key(
                        public_exponent = 65537,
                        key_size = int(keyLen),
                        backend = self.__backend)
            except Exception as err:
                raise Exception(err)
        elif keyType == 'dsa':
            try:
                pkey = dsa.generate_private_key(
                        key_size = int(keyLen),
                        backend = self.__backend)
            except Exception as err:
                raise Exception(err)
        else:
            raise NotImplementedError('Private key generation only support {t} key type'.format(t=self._config._allowed.KeyTypes))

        return pkey

    def load(self, raw, password=None, encoding='PEM'):
        """Load a Private Key and return a cryptography CSR object
        """
        pkey = None

        try:
            if encoding == 'PEM':
                pkey = serialization.load_pem_private_key(raw, password=password, backend=self.__backend)
            elif encoding in ['DER','PFX','P12']:
                pkey = serialization.load_der_private_key(raw, password=password, backend=self.__backend)
            else:
                raise NotImplementedError('Unsupported Private Key encoding')
        except Exception as err:
            raise Exception(err)
        
        return pkey

    def dump(self, pkey, password=None, encoding='PEM'):
        """Export Private key (pkey) using args:
            - encoding in PEM (default) or PFX/P12/DER mode
            - password will protect file with password if needed
        """
        data = None

        if encoding == 'PEM':
            enc = serialization.Encoding.PEM
        elif encoding in ['DER','PFX','P12']:
            enc = serialization.Encoding.DER
        else:
            raise NotImplementedError('Unsupported private key encoding')

        encryption = serialization.NoEncryption() if password is None else serialization.BestAvailableEncryption(bits(password))
        try:
            data = pkey.private_bytes(
                encoding=enc,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=encryption)
        except Exception as err:
            raise Exception(err)

        return data

    def parse(self, raw, password=None, encoding='PEM'):

        data = dict({})
        
        try:
            if encoding == 'PEM':
                pkey = serialization.load_pem_private_key(raw, password=password, backend=self.__backend)
            elif encoding in ['DER','PFX','P12']:
                pkey = serialization.load_der_private_key(raw, password=password, backend=self.__backend)
            else:
                raise NotImplementedError('Unsupported Private Key encoding')
        except Exception as err:
            raise Exception(err)
        
        data['bits'] = pkey.key_size
        data['keyType'] = 'rsa'

        return data