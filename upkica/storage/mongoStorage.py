# -*- coding:utf-8 -*-

from pymongo import MongoClient

import upkica

from .abstractStorage import AbstractStorage

class MongoStorage(AbstractStorage):
    def __init__(self, logger, options):
        try:
            super(MongoStorage, self).__init__(logger)
        except Exception as err:
            raise Exception(err)

        # Define values
        self._serial_db = 'serials'
        self._nodes_db  = 'nodes'

        # Setup handles
        self.db         = None

        try:
            options['host']
            options['port']
            options['db']
        except KeyError:
            raise Exception('Missing mandatory DB options')

        # Setup optional options
        try:
            options['auth_db']
        except KeyError:
            options['auth_db'] = None
        try:
            options['auth_mechanism']
            if options['auth_mechanism'] not in ['MONGODB-CR', 'SCRAM-MD5', 'SCRAM-SHA-1', 'SCRAM-SHA-256', 'SCRAM-SHA-512']:
                raise NotImplementedError('Unsupported MongoDB authentication method')
        except KeyError:
            options['auth_mechanism'] = None

        try:
            options['user']
            options['pass']
        except KeyError:
            options['user'] = None
            options['pass'] = None

        # Store infos
        self._options = options
        self._connected   = False
        self._initialized = self._is_initialized()

    def _is_initialized(self):
        # Check config file, public and private exists
        return False

    def initialize(self):
        pass
    
    def connect(self):
        """Connect to MongoDB server using options
        """
        try:
            connection = MongoClient(host=self._options['host'],
                    port=self._options['port'],
                    username=self._options['user'],
                    password=self._options['pass'],
                    authSource=self._options['auth_db'],
                    authMechanism=self._options['auth_mechanism'])
            self.db = getattr(connection, self._options['db'])
            self.output('MongoDB connected to mongodb://{s}:{p}/{d}'.format(s=self._options['host'],p=self._options['port'],d=self._options['db']))
        except Exception as err:
            raise Exception(err)
        
    def serial_exists(self, serial):
        pass
    def store_key(self, pkey, nodename, ca=False, encoding='PEM'):
        pass
    def store_request(self, req, nodename, ca=False, encoding='PEM'):
        pass
    def delete_request(self, nodename, ca=False, encoding='PEM'):
        pass
    def store_public(self, crt, nodename, ca=False, encoding='PEM'):
        pass
    def download_public(self, dn, encoding='PEM'):
        pass
    def delete_public(self, nodename, ca=False, encoding='PEM'):
        pass
    def store_crl(self, crl, next_crl_days=30):
        pass
    def terminate(self):
        pass
    def exists(self, name, profile=None, uid=None):
        pass
    def get_ca(self):
        pass
    def get_crl(self):
        pass
    def store_crl(self, crl_pem):
        pass
    def register_node(self, dn, profile_name, profile_data, sans=[], keyType=None, bits=None, digest=None, duration=None, local=False):
        pass
    def get_node(self, name, profile=None, uid=None):
        pass
    def get_nodes(self):
        pass
    def get_revoked(self):
        pass
    def activate_node(self, dn):
        pass
    def certify_node(self, cert, internal=False):
        pass
    def expire_node(self, dn):
        pass
    def renew_node(self, serial, dn, cert):
        pass
    def revoke_node(self, dn, reason='unspecified'):
        pass
    def unrevoke_node(self, dn):
        pass
    def delete_node(self, dn, serial):
        pass
