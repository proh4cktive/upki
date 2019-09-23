# -*- coding:utf-8 -*-

import os
import re
import yaml

import upkica

class Config(upkica.core.Common):
    def __init__(self, logger, configpath, host, port):
        try:
            super(Config, self).__init__(logger)
        except Exception as err:
            raise Exception(err)

        self.storage  = None
        self.password = None
        self._seed    = None
        self._host    = host
        self._port    = port
        
        try:
            # Extract directory, before append config file
            self._dpath = os.path.dirname(configpath)
            self._path  = os.path.join(self._dpath, "ca.config.yml")
        except Exception as err:
            raise Exception(err)

    def initialize(self):
        """Generate the config directories if does not exists
        Ask user the configuration values
        Create the config file
        Create default profiles files"""
        
        try:
            self.output("Create core structure (logs/config) on {p}".format(p=self._dpath), level="DEBUG")
            self._mkdir_p(os.path.join(self._dpath, 'logs'))
        except Exception as err:
            raise Exception('Unable to create directories: {e}'.format(e=err))

        conf = dict()
        conf['name']     = self._ask('Enter your company name', default='Kitchen Inc.')
        conf['domain']   = self._ask('Enter your domain name', default='kitchen.io')
        conf['clients']  = self._ask('Which kind of user can post requests (all | register | manual)', default='register', regex="^(all|register|manual)")
        conf['password'] = self._ask('Password used for private key protection (default: None)', mandatory=False)
        
        # We will check storage and loop if this one failed
        while True:
            storage = self._ask('How to store profiles and certificates', default='file', regex='^(file|mongodb)$')
            # MongoDB support is not YET ready
            storage = 'file'

            conf['storage'] = dict({'type': storage})

            if storage == 'file':
                conf['storage']['path'] = self._ask('Enter storage directory path', default=self._dpath)
                # Setup storage
                self.storage = upkica.storage.FileStorage(self._logger, conf['storage'])
            
            elif storage == 'mongodb':
                conf['storage']['host']           = self._ask('Enter MongoDB server IP', default='127.0.0.1', regex='ipv4')
                conf['storage']['port']           = self._ask('Enter MongoDB server port', default=27017, regex='port')
                conf['storage']['db']             = self._ask('Enter MongoDB database name', default='upki')
                authentication = self._ask('Do you need authentication', default='no', mandatory=False)
                if authentication in ['y','yes']:
                    conf['storage']['auth_db']        = self._ask('Enter MongoDB authentication database', default='admin')
                    conf['storage']['auth_mechanism'] = self._ask('Enter MongoDB authentication method', default='SCRAM-SHA-256', regex='^(MONGODB-CR|SCRAM-MD5|SCRAM-SHA-1|SCRAM-SHA-256|SCRAM-SHA-512)$')
                    conf['storage']['user']           = self._ask('Enter MongoDB user')
                    conf['storage']['pass']           = self._ask('Enter MongoDB password')
                # Setup storage
                self.storage = upkica.storage.MongoStorage(self._logger, conf['storage'])
            
            else:
                self.output('Storage only supports File or MongoDB for now...')

            try:
                # Try initialization
                self.storage.initialize()
                # If all is good, exit the loop
                break
            except Exception as err:
                self.output('Unable to setup storage: {e}'.format(e=err))
        
        try:
            # Store config
            self._storeYAML(self._path, conf)
            self.output('Configuration saved at {p}.'.format(p=self._path))
        except Exception as err:
            raise Exception(err)

        # Copy default profiles
        for name in ['admin', 'ca', 'ra', 'server', 'user']:
            try:
                data = self._parseYAML(os.path.join('./upkica','data','{n}.yml'.format(n=name)))
            except Exception as err:
                raise Exception('Unable to load sample {n} profile: {e}'.format(n=name, e=err))
            try:
                # Update domain with user value
                data['domain'] = conf['domain']
            except KeyError:
                pass
            # Update company in subject
            for i, entry in enumerate(data['subject']):
                try:
                    entry['O']
                    data['subject'][i] = {'O': conf['name']}
                except KeyError:
                    pass
            try:
                self._storeYAML(os.path.join(self._dpath, 'profiles', '{n}.yml'.format(n=name)), data)
            except Exception as err:
                raise Exception('Unable to store {n} profile: {e}'.format(n=name, e=err))
        
        self.output('Profiles saved in {p}.'.format(p=os.path.join(self._dpath, 'profiles')))

        return True

    def load(self):
        """Read config values
        load connectors"""

        try:
            data = self._parseYAML(self._path)
            self.output('Configuration loaded using file at {p}'.format(p=self._path), level="DEBUG")
        except Exception as err:
            raise Exception(err)

        try:
            self.name     = data['name']
            self.domain   = data['domain']
            self.clients  = data['clients']
            self.password = data['password']
            data['storage']['type']
        except KeyError:
            raise Exception('Missing mandatory options')

        # Setup storage
        if data['storage']['type'].lower() == 'file':
            self.storage = upkica.storage.FileStorage(self._logger, data['storage'])
        elif data['storage']['type'].lower() == 'mongodb':
            self.storage = upkica.storage.MongoStorage(self._logger, data['storage'])
        else:
            raise NotImplementedError('Storage only supports File or MongoDB')
