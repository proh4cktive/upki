# -*- coding:utf-8 -*-

import os
import sys
import time
import random
import hashlib
import threading
import validators

from cryptography import x509

import upkica

class Authority(upkica.core.Common):
    def __init__(self, config):
        try:
            super(Authority, self).__init__(config._logger)
        except Exception as err:
            raise upkica.core.UPKIError(1, err)

        # Initialize handles
        self._config   = config
        self._profiles = None
        self._private  = None
        self._request  = None
        self._public   = None

    def _load_profile(self, name):
        try:
            data = self._profiles.load(name)
        except Exception as err:
            raise upkica.core.UPKIError(2, 'Unable to load {n} profile: {e}'.format(n=name, e=err))

        return data

    def initialize(self, keychain=None):
        """Initialize the PKI config file, and store it on disk.
        Initialize storage if needed
        Generate Private and Public keys for CA
        Generate Private and Public keys used for 0MQ TLS socket
        Called on initialization only.
        """

        if keychain is not None:
            # No need to initialize anything if CA required files does not exists
            for f in ['ca.key','ca.crt']:
                if not os.path.isfile(os.path.join(keychain,f)):
                    raise upkica.core.UPKIError(3, 'Missing required CA file for import.')

        try:
            self._config.initialize()
        except upkica.core.UPKIError as err:
            raise upkica.core(err.code, err.reason)
        except Exception as err:
            raise upkica.core.UPKIError(4, 'Unable to setup config: {e}'.format(e=err))

        try:
            # Load CA like usual
            self.load()
        except upkica.core.UPKIError as err:
            raise upkica.core(err.code, err.reason)
        except Exception as err:
            raise upkica.core.UPKIError(5, err)

        try:
            # Load CA specific profile
            ca_profile = self._load_profile("ca")
        except Exception as err:
            raise upkica.core.UPKIError(6, err)

        try:
            # Setup private handle
            self._private = upkica.ca.PrivateKey(self._config)
        except Exception as err:
            raise upkica.core.UPKIError(7, 'Unable to initialize CA Private Key: {e}'.format(e=err))

        try:
            # Setup request handle
            self._request = upkica.ca.CertRequest(self._config)
        except Exception as err:
            raise upkica.core.UPKIError(8, 'Unable to initialize CA Certificate Request: {e}'.format(e=err))

        try:
            # Setup public handle
            self._public = upkica.ca.PublicCert(self._config)
        except Exception as err:
            raise upkica.core.UPKIError(9, 'Unable to initialize CA Public Certificate: {e}'.format(e=err))
        
        if keychain:
            try:
                (pub_cert, priv_key) = self.__import_keychain(ca_profile, keychain)
            except upkica.core.UPKIError as err:
                raise upkica.core.UPKIError(err.code, err.reason)
            except Exception as err:
                raise upkica.core.UPKIError(10, err)
        else:
            try:
                (pub_cert, priv_key) = self.__create_keychain(ca_profile)
            except upkica.core.UPKIError as err:
                raise upkica.core.UPKIError(err.code, err.reason)
            except Exception as err:
                raise upkica.core.UPKIError(11, err)

        try:
            dn = self._get_dn(pub_cert.subject)
        except Exception as err:
            raise Exception('Unable to get DN from CA certificate: {e}'.foramt(e=err))
        
        try:
            self._storage.certify_node(dn, pub_cert, internal=True)
        except Exception as err:
            raise upkica.core.UPKIError(12, 'Unable to activate CA: {e}'.format(e=err))

        try:
            (server_pub, server_priv) = self.__create_listener('server', pub_cert, priv_key)
        except upkica.core.UPKIError as err:
            raise upkica.core(err.code, err.reason)
        except Exception as err:
            raise upkica.core.UPKIError(13, err)

        try:
            dn = self._get_dn(server_pub.subject)
        except Exception as err:
            raise Exception('Unable to get DN from server certificate: {e}'.foramt(e=err))
        
        try:
            self._storage.certify_node(dn, server_pub, internal=True)
        except Exception as err:
            raise upkica.core.UPKIError(14, 'Unable to activate server: {e}'.format(e=err))

        return True

    def __import_keychain(self, profile, ca_path):
        ###########################################################
        ############ AUTHORITY KEYCHAIN IMPORT ####################
        ###########################################################
        if not os.path.isdir(ca_path):
            raise upkica.core.UPKIError(15, 'Directory does not exists')

        # Load private key data
        with open(os.path.join(ca_path,'ca.key'), 'rb') as key_path:
            self.output("1. CA private key loaded", color="green")
            key_pem = key_path.read()

        try:
            # Load certificate request data
            with open(os.path.join(ca_path,'ca.csr'), 'rb') as csr_path:
                self.output("2. CA certificate request loaded", color="green")
                csr_pem = csr_path.read()
        except Exception:
            # If Certificate Request does not exist, create one
            csr_pem = None

        try:
            # Load private key object
            priv_key = self._private.load(key_pem)
            self._storage.store_key(self._private.dump(priv_key, password=self._config.password), nodename="ca")
        except Exception as err:
            raise upkica.core.UPKIError(16, err)

        # If CSR is invalid or does not exists, just create one
        if csr_pem is None:
            try:
                csr = self._request.generate(priv_key, "CA", profile)
                csr_pem = self._request.dump(csr)
                self.output("2. CA certificate request generated", color="green")
            except Exception as err:
                raise upkica.core.UPKIError(17, err)
        
        try:
            # Load certificate request object
            csr = self._request.load(csr_pem)
            self._storage.store_request(self._request.dump(csr), nodename="ca")
        except Exception as err:
            raise upkica.core.UPKIError(18, err)

        # Load public certificate data
        with open(os.path.join(ca_path,'ca.crt'), 'rb') as pub_path:
            self.output("3. CA certificate loaded", color="green")
            pub_pem = pub_path.read()

        try:
            # Load public certificate object
            pub_cert = self._public.load(pub_pem)
            self._storage.store_public(self._public.dump(pub_cert), nodename="ca")
        except Exception as err:
            raise upkica.core.UPKIError(19, err)

        return (pub_cert, priv_key)

    def __create_keychain(self, profile):

        ###########################################################
        ############ AUTHORITY KEYCHAIN GENERATION ################
        ###########################################################
        try:
            priv_key = self._private.generate(profile)
        except Exception as err:
            raise upkica.core.UPKIError(20, 'Unable to generate CA Private Key: {e}'.format(e=err))

        try:
            self.output("1. CA private key generated", color="green")
            self.output(self._private.dump(priv_key), level="DEBUG")
            self._storage.store_key(self._private.dump(priv_key, password=self._config.password), nodename="ca")
        except Exception as err:
            raise upkica.core.UPKIError(21, 'Unable to store CA Private key: {e}'.format(e=err))

        try:
            cert_req = self._request.generate(priv_key, "CA", profile)
        except Exception as err:
            raise upkica.core.UPKIError(22, 'Unable to generate CA Certificate Request: {e}'.format(e=err))

        try:
            self.output("2. CA certificate request generated", color="green")
            self.output(self._request.dump(cert_req), level="DEBUG")
            self._storage.store_request(self._request.dump(cert_req), nodename="ca")
        except Exception as err:
            raise upkica.core.UPKIError(23, 'Unable to store CA Certificate Request: {e}'.format(e=err))

        try:
            pub_cert = self._public.generate(cert_req, None, priv_key, profile, ca=True, selfSigned=True)
        except Exception as err:
            raise upkica.core.UPKIError(24, 'Unable to generate CA Public Certificate: {e}'.format(e=err))

        try:
            self.output("3. CA public certificate generated", color="green")
            self.output(self._public.dump(pub_cert), level="DEBUG")
            self._storage.store_public(self._public.dump(pub_cert), nodename="ca")
        except Exception as err:
            raise upkica.core.UPKIError(25, 'Unable to store CA Public Certificate: {e}'.format(e=err))

        return (pub_cert, priv_key)

    def __create_listener(self, profile, pub_cert, priv_key):
        ###########################################################
        ############ LISTENER KEYCHAIN GENERATION #################
        ###########################################################

        try:
            # Load Server specific profile
            server_profile = self._load_profile(profile)
        except Exception as err:
            raise upkica.core.UPKIError(26, err)

        try:
            server_priv_key = self._private.generate(server_profile)
        except Exception as err:
            raise upkica.core.UPKIError(27, 'Unable to generate Server Private Key: {e}'.format(e=err))

        try:
            self.output("4. Server private key generated", color="green")
            self.output(self._private.dump(server_priv_key), level="DEBUG")
            self._storage.store_key(self._private.dump(server_priv_key), nodename="zmq")
        except Exception as err:
            raise upkica.core.UPKIError(28, 'Unable to store Server Private key: {e}'.format(e=err))

        try:
            server_cert_req = self._request.generate(server_priv_key, "ca", server_profile)
        except Exception as err:
            raise upkica.core.UPKIError(29, 'Unable to generate Server Certificate Request: {e}'.format(e=err))

        try:
            self.output("5. Server certificate request generated", color="green")
            self.output(self._request.dump(server_cert_req), level="DEBUG")
            self._storage.store_request(self._request.dump(server_cert_req), nodename="zmq")
        except Exception as err:
            raise upkica.core.UPKIError(30, 'Unable to store Server Certificate Request: {e}'.format(e=err))

        try:
            server_pub_cert = self._public.generate(server_cert_req, pub_cert, priv_key, server_profile)
        except Exception as err:
            raise upkica.core.UPKIError(31, 'Unable to generate Server Public Certificate: {e}'.format(e=err))

        try:
            self.output("6. Server public certificate generated", color="green")
            self.output(self._public.dump(server_pub_cert), level="DEBUG")
            self._storage.store_public(self._public.dump(server_pub_cert), nodename="zmq")
        except Exception as err:
            raise upkica.core.UPKIError(32, 'Unable to store Server Public Certificate: {e}'.format(e=err))

        return (server_pub_cert, server_priv_key)
    
    def load(self):
        """Load config file
        connect to configured storage"""
        if not os.path.isfile(self._config._path):
            raise upkica.core.UPKIError(33, "uPKI is not yet initialized. PLEASE RUN: '{p} init'".format(p=sys.argv[0]))
        
        try:
            self.output('Loading config...', level="DEBUG")
            self._config.load()
        except Exception as err:
            raise upkica.core.UPKIError(34, 'Unable to load configuration: {e}'.format(e=err))

        # Setup connectors
        self._storage  = self._config.storage
        self._profiles = upkica.utils.Profiles(self._logger, self._storage)

        try:
            self.output('Connecting storage...', level="DEBUG")
            self._storage.connect()
        except Exception as err:
            raise upkica.core.UPKIError(35, 'Unable to connect to db: {e}'.format(e=err))

        return True

    def register(self, ip, port):
        """Start the register server process
        Allow a new RA to get its certificate based on seed value
        """
        try:
            # Register seed value
            seed = "seed:{s}".format(s=x509.random_serial_number())
            self._config._seed = hashlib.sha1(seed.encode('utf-8')).hexdigest()
        except Exception as err:
            raise upkica.core.UPKIError(36, 'Unable to generate seed: {e}'.format(e=err))

        if not validators.ipv4(ip):
            raise upkica.core.UPKIError(37, 'Invalid listening IP')
        if not validators.between(int(port), 1024, 65535):
            raise upkica.core.UPKIError(38, 'Invalid listening port')

        # Update config
        self._config._host = ip
        self._config._port = port

        try:
            # Setup listeners
            register = upkica.connectors.ZMQRegister(self._config, self._storage, self._profiles)
        except Exception as err:
            raise upkica.core.UPKIError(39, 'Unable to initialize register: {e}'.format(e=err))

        cmd = "./ra_server.py"
        if self._config._host != '127.0.0.1':
            cmd += " --ip {i}".format(i=self._config._host)
        if self._config._port != 5000:
            cmd += " --port {p}".format(p=self._config._port)
        cmd += " register --seed {s}".format(s=seed.split('seed:',1)[1]) 

        try:
            t1 = threading.Thread(target=register.run, args=(ip, port,), kwargs={'register': True}, name='uPKI CA listener')
            t1.daemon = True
            t1.start()

            self.output("Download the upki-ra project on your RA server (the one facing Internet)", light=True)
            self.output("Project at: https://github.com/proh4cktive/upki-ra", light=True)
            self.output("Install it, then start your RA with command: \n{c}".format(c=cmd), light=True)
            # Stay here to catch KeyBoard interrupt
            t1.join()
            # while True: time.sleep(100)
        except (KeyboardInterrupt, SystemExit):
            self.output('Quitting...', color='red')
            self.output('Bye', color='red')
            raise SystemExit()

        return True 

    def listen(self, ip, port):

        if not validators.ipv4(ip):
            raise upkica.core.UPKIError(40, 'Invalid listening IP')
        if not validators.between(int(port), 1024, 65535):
            raise upkica.core.UPKIError(41, 'Invalid listening port')

        # Update config
        self._config._host = ip
        self._config._port = port

        try:
            # Setup listeners
            listener = upkica.connectors.ZMQListener(self._config, self._storage, self._profiles)
        except Exception as err:
            raise upkica.core.UPKIError(42, 'Unable to initialize listener: {e}'.format(e=err))
        
        try:
            t1 = threading.Thread(target=listener.run, args=(ip, port,), name='uPKI CA listener')
            t1.daemon = True
            t1.start()
            
            # Stay here to catch KeyBoard interrupt
            t1.join()
            while True: time.sleep(100)
        except (KeyboardInterrupt, SystemExit):
            self.output('Quitting...', color='red')
            self.output('Bye', color='red')
            raise SystemExit()