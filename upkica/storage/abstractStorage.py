# -*- coding:utf-8 -*-

from abc import abstractmethod

import upkica

class AbstractStorage(upkica.core.Common):
    def __init__(self, logger):
        try:
            super(AbstractStorage, self).__init__(logger)
        except Exception as err:
            raise Exception(err)
        
    @abstractmethod
    def _is_initialized(self):
        raise NotImplementedError()

    @abstractmethod
    def initialize(self):
        raise NotImplementedError()
        
    @abstractmethod
    def connect(self):
        raise NotImplementedError()
        
    @abstractmethod
    def serial_exists(self, serial):
        raise NotImplementedError()
        
    @abstractmethod
    def store_key(self, pkey, nodename, ca=False, encoding='PEM'):
        raise NotImplementedError()
        
    @abstractmethod
    def store_request(self, req, nodename, ca=False, encoding='PEM'):
        raise NotImplementedError()
        
    @abstractmethod
    def delete_request(self, nodename, ca=False, encoding='PEM'):
        raise NotImplementedError()
        
    @abstractmethod
    def store_public(self, crt, nodename, ca=False, encoding='PEM'):
        raise NotImplementedError()
        
    @abstractmethod
    def download_public(self, dn, encoding='PEM'):
        raise NotImplementedError()
        
    @abstractmethod
    def delete_public(self, nodename, ca=False, encoding='PEM'):
        raise NotImplementedError()
        
    @abstractmethod
    def store_crl(self, crl, next_crl_days=30):
        raise NotImplementedError()
        
    @abstractmethod
    def terminate(self):
        raise NotImplementedError()
        
    @abstractmethod
    def exists(self, name, profile=None, uid=None):
        raise NotImplementedError()
        
    @abstractmethod
    def get_ca(self):
        raise NotImplementedError()
        
    @abstractmethod
    def get_crl(self):
        raise NotImplementedError()
        
    @abstractmethod
    def store_crl(self, crl_pem):
        raise NotImplementedError()
        
    @abstractmethod
    def register_node(self, dn, profile_name, profile_data, sans=[], keyType=None, bits=None, digest=None, duration=None, local=False):
        raise NotImplementedError()
        
    @abstractmethod
    def get_node(self, name, profile=None, uid=None):
        raise NotImplementedError()
        
    @abstractmethod
    def list_nodes(self):
        raise NotImplementedError()
        
    @abstractmethod
    def get_revoked(self):
        raise NotImplementedError()
        
    @abstractmethod
    def activate_node(self, dn):
        raise NotImplementedError()
        
    @abstractmethod
    def certify_node(self, cert, internal=False):
        raise NotImplementedError()
        
    @abstractmethod
    def expire_node(self, dn):
        raise NotImplementedError()
        
    @abstractmethod
    def renew_node(self, serial, dn, cert):
        raise NotImplementedError()
        
    @abstractmethod
    def revoke_node(self, dn, reason='unspecified'):
        raise NotImplementedError()
        
    @abstractmethod
    def unrevoke_node(self, dn):
        raise NotImplementedError()
        
    @abstractmethod
    def delete_node(self, dn, serial):
        raise NotImplementedError()
