# -*- coding:utf-8 -*-

import os
import zmq
import datetime

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes

import upkica

class Listener(upkica.core.Common):
    def __init__(self, config, storage, profiles, admins):
        try:
            super(Listener, self).__init__(config._logger)
        except Exception as err:
            raise Exception(err)

        self._config   = config
        self._storage  = storage
        self._profiles = profiles
        self._admins   = admins
        self._socket   = None
        self._run      = False

        # Register private backend
        self._backend = default_backend()

        # Register file path
        self._certs_dir   = os.path.join(self._config._dpath, 'certs/')
        self._reqs_dir    = os.path.join(self._config._dpath, 'reqs/')
        self._keys_dir    = os.path.join(self._config._dpath, 'private/')
        self._profile_dir = os.path.join(self._config._dpath, 'profiles/')

    def _send_error(self, msg):
        if msg is None:
            return False

        msg = str(msg).strip()

        if len(msg) == 0:
            return False
        
        try:
            self._socket.send_json({'EVENT':'UPKI ERROR', 'MSG': msg})
        except Exception as err:
            raise Exception(err)

    def _send_answer(self, data):
        if data is None:
            return False

        try:
            self._socket.send_json({'EVENT':'ANSWER', 'DATA': data})
        except Exception as err:
            raise Exception(err)

    def __load_keychain(self):
        self._ca = dict({})
        self.output('Loading CA keychain', level="DEBUG")
        self._ca['public'] = self._storage.get_ca().encode('utf-8')
        self._ca['private'] = self._storage.get_ca_key().encode('utf-8')
        
        try:
            self._ca['cert'] = x509.load_pem_x509_certificate(self._ca['public'], backend=self._backend)
            self._ca['dn'] = self._get_dn(self._ca['cert'].subject)
            self._ca['cn'] = self._get_cn(self._ca['dn'])
        except Exception as err:
            raise Exception('Unable to load CA public certificate: {e}'.format(e=err))

        try:
            self._ca['key'] = serialization.load_pem_private_key(self._ca['private'], password=self._config.password, backend=self._backend)
        except Exception as err:
            raise Exception('Unable to load CA private key: {e}'.format(e=err))

        return True

    def _upki_get_ca(self, params):
        try:
            result = self._ca['public'].decode('utf-8')
        except Exception as err:
            raise Exception(err)

        return result

    def _upki_get_crl(self, params):
        try:
            crl_pem = self._storage.get_crl()
        except Exception as err:
            raise Exception(err)

        return crl_pem

    def _upki_generate_crl(self, params):
        self.output('Start CRL generation')
        now = datetime.datetime.utcnow()
        try:
            builder = (
                x509.CertificateRevocationListBuilder()
                .issuer_name(self._ca['cert'].issuer)
                .last_update(now)
                .next_update(now + datetime.timedelta(days=3))
            )
        except Exception as err:
            raise Exception('Unable to build CRL: {e}'.format(e=err))

        for entry in self._storage.get_revoked():
            try:
                revoked_cert = (
                    x509.RevokedCertificateBuilder()
                    .serial_number(entry['Serial'])
                    .revocation_date(datetime.datetime.strptime(entry['Revoke_Date'],'%Y%m%d%H%M%SZ'))
                    .add_extension(x509.CRLReason(x509.ReasonFlags.cessation_of_operation), critical=False)
                    .build(self._backend)
                )
            except Exception as err:
                self.output('Unable to build CRL entry for {d}: {e}'.format(d=entry['DN'], e=err), level='ERROR')
                continue

            try:
                builder = builder.add_revoked_certificate(revoked_cert)
            except Exception as err:
                self.output('Unable to add CRL entry for {d}: {e}'.format(d=entry['DN'], e=err), level='ERROR')
                continue
        
        try:
            crl = builder.sign(private_key=self._ca['key'], algorithm=hashes.SHA256(), backend=self._backend)
        except Exception as err:
            raise Exception('Unable to sign CSR: {e}'.format(e=err))

        try:
            crl_pem = crl.public_bytes(serialization.Encoding.PEM)
            self._storage.store_crl(crl_pem)
        except Exception as err:
            raise Exception(err)

        return {'state': 'OK'}

    def run(self, ip, port, register=False):
        def _invalid(_):
            self._send_error('Unknown command')
            return False

        try:
            self.__load_keychain()
        except Exception as err:
            raise Exception('Unable to load issuer keychain')

        try:
            self.output('Launching CA listener')
            context = zmq.Context()
            self.output("Listening socket use ZMQ version {v}".format(v=zmq.zmq_version()), level="DEBUG")
            self._socket = context.socket(zmq.REP)
            self._socket.bind('tcp://{host}:{port}'.format(host=ip, port=port))
            self.output("Listener Socket bind to tcp://{host}:{port}".format(host=ip, port=port))
        except zmq.ZMQError as err:
            raise upkica.core.UPKIError(20,"Stalker process failed with: {e}".format(e=err))
        except Exception as err:
            raise upkica.core.UPKIError(20,"Error on connection: {e}".format(e=err))

        self._run = True

        while self._run:
            try:
                msg = self._socket.recv_json()
            except zmq.ZMQError as e:
                self.output('ZMQ Error: {err}'.format(err=e), level="ERROR")
                continue
            except ValueError:
                self.output('Received unparsable message', level="ERROR")
                continue
            except SystemExit:
                self.output('Poison listener...', level="WARNING")
                break
            
            try:
                self.output('Receive {task} action...'.format(task=msg['TASK']), level="INFO")
                self.output('Action message: {param}'.format(param=msg), level="DEBUG")
                task = "_upki_{t}".format(t=msg['TASK'].lower())
            except KeyError:
                self.output('Received invalid message', level="ERROR")
                continue

            try:
                params = msg['PARAMS']
            except KeyError:
                params = {}

            func = getattr(self, task, _invalid)
            
            try:
                res = func(params)
            except Exception as err:
                self.output('Error: {e}'.format(e=err), level='error')
                self._send_error(err)
                continue

            if res is False:
                continue

            try:
                self._send_answer(res)
            except Exception as err:
                self.output('Error: {e}'.format(e=err), level='error')
                self._send_error(err)
                continue