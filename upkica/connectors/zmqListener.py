# -*- coding:utf-8 -*-

import os
import base64
import time
import datetime

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes

import upkica

from .listener import Listener

class ZMQListener(Listener):
    def __init__(self, config, storage, profiles, admins):
        try:
            super(ZMQListener, self).__init__(config, storage, profiles, admins)
        except Exception as err:
            raise Exception(err)

        # Register handles to X509
        self._public  = upkica.ca.PublicCert(config)
        self._request = upkica.ca.CertRequest(config)
        self._private = upkica.ca.PrivateKey(config)

    def _upki_list_admins(self, params):
        return self._admins.list()
        
    def _upki_add_admin(self, dn):
        if dn is None:
            raise Exception('Missing admin DN')
        try:
            self.output('Add admin {d}'.format(d=dn))
            self._admins.store(dn)
        except Exception as err:
            raise Exception(err)

        return True
        
    def _upki_remove_admin(self, dn):
        if dn is None:
            raise Exception('Missing admin DN')
        try:
            self.output('Delete admin {d}'.format(d=dn))
            self._admins.delete(dn)
        except Exception as err:
            raise Exception(err)

        return True
        
    def _upki_list_profiles(self, dn):
        return self._profiles.list()

    def _upki_profile(self, profile_name):
        if profile_name is None:
            raise Exception('Missing profile name')

        if not self._profiles.exists(profile_name):
            raise Exception('This profile does not exists')

        data = None
        try:
            self.output('Retrieve profile {p} values'.format(p=profile_name))
            data = self._profiles.load(name)
        except Exception as err:
            raise Exception(err)

        return data

    def _upki_add_profile(self, params):

        try:
            name = params['name']
        except KeyError:
            raise Exception('Missing profile name')

        try:
            self.output('Add profile {n}'.format(n=name))
            self._profiles.store(name, params)
        except Exception as err:
            raise Exception(err)

        return True

    def _upki_update_profile(self, params):

        try:
            name = params['name']
        except KeyError:
            raise Exception('Missing profile name')

        try:
            origName = params['origName']
        except KeyError:
            raise Exception('Missing original profile name')

        try:
            self.output('Update profile {n}'.format(n=name))
            self._profiles.update(origName, name, params)
        except Exception as err:
            raise Exception(err)

        return True

    def _upki_remove_profile(self, params):
        try:
            name = params['name']
        except KeyError:
            raise Exception('Missing profile name')

        try:
            self.output('Delete profile {n}'.format(n=name))
            self._profiles.delete(name)
        except Exception as err:
            raise Exception(err)

        return True

    def _upki_get_options(self, params):
        return vars(self._profiles._allowed)

    def _upki_list_nodes(self, params):
        try:
            nodes = self._storage.list_nodes()
        except Exception as err:
            raise Exception(err)

        # Humanize serials
        for i, node in enumerate(nodes):
            if node['Serial']:
                try:
                    # Humanize serials
                    nodes[i]['Serial'] = self._prettify(node['Serial'])
                except Exception as err:
                    self.output(err, level='ERROR')
                    continue

        return nodes

    def _upki_get_node(self, params):
        try:
            if isinstance(params, dict):
                node = self._storage.get_node(params['cn'], profile=params['profile'])
            elif isinstance(params, basestring):
                node = self._storage.get_node(params)
            else:
                raise NotImplementedError('Unsupported params')
        except Exception as err:
            raise Exception(err)

        if (node['Expire'] != None) and (node['Expire'] <= int(time.time())):
            node['State'] = 'Expired'
            self._storage.expire_node(node['DN'])

        try:
            # Humanize serials
            node['Serial'] = self._prettify(node['Serial'])
        except Exception as err:
            raise Exception(err)

        return node

    def _upki_download_node(self, dn):
        try:
            node = self._storage.get_node(dn)
        except Exception as err:
            raise Exception(err)

        if node['State'] != 'Valid':
            raise Exception('Only valid certificate can be downloaded')

        try:
            nodename = "{p}.{c}".format(p=node['Profile'], c=node['CN'])
        except KeyError:
            raise Exception('Unable to build nodename, missing mandatory infos')

        try:
            result = self._storage.download_public(nodename)
        except Exception as err:
            raise Exception(err)
        
        return result

    def _upki_register(self, params):
        try:
            dn = params['dn']
        except KeyError:
            raise Exception('Missing DN option')

        if self._storage.exists(dn):
            raise Exception('Node already registered')

        try:
            cn = self._get_cn(dn)
        except Exception as err:
            raise Exception(err)

        try:
            profile = self._profiles.load(params['profile'])
        except KeyError:
            raise Exception('Missing profile option')
        except Exception as err:
            raise Exception('Unable to load profile from listener: {e}'.format(e=err))

        try:
            local = bool(params['local'])
        except (ValueError, KeyError):
            local = False

        try:
            clean = self._check_node(params, profile)
        except Exception as err:
            raise Exception('Invalid node parameters: {e}'.format(e=err))

        try:
            self.output('Register node {n} with profile {p}'.format(n=cn, p=params['profile']))
            res = self._storage.register_node(dn,
                    params['profile'],
                    profile,
                    sans=clean['sans'],
                    keyType=clean['keyType'],
                    keyLen=clean['keyLen'],
                    digest=clean['digest'],
                    duration=clean['duration'],
                    local=local
            )
        except Exception as err:
            raise Exception(err)

        return res

    def _upki_generate(self, params):
        try:
            dn = params['dn']
        except KeyError:
            raise Exception('Missing DN option')

        try:
            cn = self._get_cn(dn)
        except Exception as err:
            raise Exception('Unable to get CN: {e}'.format(e=err))

        if not self._storage.exists(dn):
            if self._config.clients != 'all':
                raise Exception('You must register this node first')
            try:
                # Set local flag
                params['local'] = True
                self._upki_register(params)
            except Exception as err:
                raise Exception('Unable to register node dynamically: {e}'.format(e=err))

        try:
            profile_name = params['profile']
        except KeyError:
            raise Exception('Missing profile option')

        try:
            profile = self._profiles.load(profile_name)
        except Exception as err:
            raise Exception('Unable to load profile in generate: {e}'.format(e=err))

        try:
            node_name = "{p}.{c}".format(p=profile_name, c=cn)
        except KeyError:
            raise Exception('Unable to build node name')

        try:
            if isinstance(params['sans'], list):
                sans = params['sans']
            elif isinstance(params['sans'], basestring):
                sans = [san.strip() for san in str(params['sans']).split(',')]
        except KeyError:
            sans = []

        try:
            # Generate Private Key
            self.output('Generating private key based on {p} profile'.format(p=profile_name))
            pkey = self._private.generate(profile)
        except Exception as err:
            raise Exception('Unable to generate Private Key: {e}'.format(e=err))

        try:
            key_pem = self._private.dump(pkey)
            self._storage.store_key(key_pem, nodename=node_name)
        except Exception as err:
            raise Exception('Unable to store Server Private key: {e}'.format(e=err))

        try:
            # Generate CSR
            self.output('Generating CSR based on {p} profile'.format(p=profile_name))
            csr = self._request.generate(pkey, cn, profile, sans=sans)
        except Exception as err:
            raise Exception('Unable to generate Certificate Signing Request: {e}'.format(e=err))

        try:
            csr_pem = self._request.dump(csr)
            self._storage.store_request(csr_pem, nodename=node_name)
        except Exception as err:
            raise Exception('Unable to store Server Certificate Request: {e}'.format(e=err))

        try:
            self.output('Activate node {n} with profile {p}'.format(n=dn, p=profile_name))
            self._storage.activate_node(dn)
        except Exception as err:
            raise Exception(err)

        return {'key': key_pem, 'csr': csr_pem}

    def _upki_update(self, params):
        try:
            dn = params['dn']
        except KeyError:
            raise Exception('Missing DN option')

        try:
            cn = self._get_cn(dn)
        except Exception as err:
            raise Exception('Unable to get CN: {e}'.format(e=err))

        if not self._storage.exists(dn):
            raise Exception('This node does not exists. Note: DN (and so CN) are immutable once registered.')
        
        try:
            node = self._storage.get_node(dn)
        except Exception as err:
            raise Exception('Unable to get node: {e}'.format(e=err))

        if node['State'] != 'Init':
            raise Exception('You can no longer update this node')

        try:
            profile = self._profiles.load(params['profile'])
        except KeyError:
            raise Exception('Missing profile option')
        except Exception as err:
            raise Exception('Unable to load profile from listener: {e}'.format(e=err))

        try:
            local = bool(params['local'])
        except (ValueError, KeyError):
            local = False

        try:
            clean = self._check_node(params, profile)
        except Exception as err:
            raise Exception('Invalid node parameters: {e}'.format(e=err))

        try:
            self.output('Update node {n} with profile {p}'.format(n=cn, p=params['profile']))
            res = self._storage.update_node(dn,
                    params['profile'],
                    profile,
                    sans=clean['sans'],
                    keyType=clean['keyType'],
                    keyLen=clean['keyLen'],
                    digest=clean['digest'],
                    duration=clean['duration'],
                    local=local
            )
        except Exception as err:
            raise Exception(err)

        # Append DN and profile
        clean['dn'] = dn
        clean['profile'] = params['profile']

        return clean

    def _upki_sign(self, params):
        try:
            csr_pem = params['csr'].encode('utf-8')
            csr = self._request.load(csr_pem)
        except KeyError:
            raise Exception('Missing CSR data')
        except Exception as err:
            raise Exception('Invalid CSR: {e}'.format(e=err))

        try:
            dn = self._get_dn(csr.subject)
        except Exception as err:
            raise Exception('Unable to get DN: {e}'.format(e=err)) 

        try:
            cn = self._get_cn(dn)
        except Exception as err:
            raise Exception('Unable to get CN: {e}'.format(e=err))

        try:
            node = self._storage.get_node(dn)
        except Exception as err:
            if self._config.clients != 'all':
                raise Exception('Unable to get node: {e}'.format(e=err))
            
            try:
                # Allow auto-signing if insecure param "all" is set
                # TODO: verify params (probably missing some options)
                node = self._upki_register(params)
            except Exception as err:
                raise Exception(err)
            

        if node['State'] in ['Valid','Revoked','Expired']:
            if node['State'] == 'Valid':
                raise Exception('Certificate already generated!')
            elif node['State'] == 'Revoked':
                raise Exception('Certificate is revoked!')
            elif node['State'] == 'Expired':
                raise Exception('Certificate has expired!')

        try:
            profile = self._profiles.load(node['Profile'])
        except Exception as err:
            raise Exception('Unable to load profile in generate: {e}'.format(e=err))

        try:
            pub_key = self._public.generate(csr, self._ca['cert'], self._ca['key'], profile, duration=node['Duration'], sans=node['Sans'])
        except Exception as err:
            raise Exception('Unable to generate Public Key: {e}'.format(e=err))

        try:
            self.output('Certify node {n} with profile {p}'.format(n=dn, p=node['Profile']))
            self._storage.certify_node(dn, pub_key)
        except Exception as err:
            raise Exception(err)

        try:
            crt_pem = self._public.dump(pub_key)
            csr_file = self._storage.store_request(csr_pem, nodename="{p}.{c}".format(p=node['Profile'], c=cn))
            crt_file = self._storage.store_public(crt_pem, nodename="{p}.{c}".format(p=node['Profile'], c=cn))
        except Exception as err:
            raise Exception('Error while storing certificate: {e}'.format(e=err))

        return {'dn':dn, 'profile':node['Profile'], 'certificate':crt_pem.decode('utf-8')}

    def _upki_renew(self, params):
        try:
            dn = params['dn']
        except KeyError:
            raise Exception('Missing DN option')

        try:
            cn = self._get_cn(dn)
        except Exception as err:
            raise Exception('Unable to get CN: {e}'.format(e=err))

        try:
            node = self._storage.get_node(dn)
        except Exception as err:
            raise Exception('Can not retrieve node: {e}'.format(e=err))

        if node['State'] in ['Init','Revoked']:
            if node['State'] == 'Init':
                raise Exception('Certificate is not initialized!')
            elif node['State'] == 'Revoked':
                raise Exception('Certificate is revoked!')

        try:
            csr_pem = self._storage.download_request('{p}.{n}'.format(p=node['Profile'], n=cn))
        except Exception as err:
            raise Exception('Unable to load CSR data: {e}'.format(e=err))

        try:
            csr = self._request.load(csr_pem.encode('utf-8'))
        except Exception as err:
            raise Exception('Unable to load CSR object: {e}'.format(e=err))

        now = time.time()

        try:
            profile = self._profiles.load(node['Profile'])
        except Exception as err:
            raise Exception('Unable to load profile in renew: {e}'.format(e=err))

        # Only renew certificate over 2/3 of their validity time
        until_expire = (datetime.datetime.fromtimestamp(node['Expire']) - datetime.datetime.fromtimestamp(time.time())).days
        if until_expire >= node['Duration']*0.66:
            msg = 'Still {d} days until expiration...'.format(d=until_expire)
            self.output(msg, level="warning")
            return {'renew':False, 'reason':msg}
        
        try:
            pub_crt = self._public.generate(csr, self._ca['cert'], self._ca['key'], profile, duration=node['Duration'], sans=node['Sans'])
        except Exception as err:
            raise Exception('Unable to re-generate Public Key: {e}'.format(e=err))

        try:
            pub_pem = self._public.dump(pub_crt)
        except Exception as err:
            raise Exception('Unable to dump new certificate: {e}'.format(e=err))

        try:
            self.output('Renew node {n} with profile {p}'.format(n=dn, p=node['Profile']))
            self._storage.renew_node(dn, pub_crt, node['Serial'])
        except Exception as err:
            raise Exception('Unable to renew node: {e}'.format(e=err))

        try:
            # Store the a new certificate
            self._storage.store_public(pub_pem, nodename="{p}.{c}".format(p=node['Profile'], c=node['CN']))
        except Exception as err:
            raise Exception('Error while storing new certificate: {e}'.format(e=err))

        return {'renew':True, 'dn':dn, 'profile':node['Profile'], 'certificate':pub_pem.decode('utf-8')}

    def _upki_revoke(self, params):
        try:
            dn = params['dn']
        except KeyError:
            raise Exception('Missing DN option')

        try:
            node = self._storage.get_node(dn)
        except Exception as err:
            raise Exception('Can not retrieve node: {e}'.format(e=err))

        if node['State'] == 'Revoked':
            raise Exception('Node is already revoked.')

        if node['State'] == 'Init':
            raise Exception('Can not revoke an unitialized node!')

        try:
            reason = params['reason']
        except KeyError:
            raise Exception('Missing Reason option')

        try:
            self.output('Will revoke certificate {d}'.format(d=dn))
            self._storage.revoke_node(dn, reason=reason)
        except Exception as err:
            raise Exception('Unable to revoke node: {e}'.format(e=err))

        # Generate a new CRL
        try:
            self._upki_generate_crl(params)
        except Exception as err:
            raise Exception(err)

        return True

    def _upki_unrevoke(self, params):
        try:
            dn = params['dn']
        except KeyError:
            raise Exception('Missing DN option')

        try:
            node = self._storage.get_node(dn)
        except Exception as err:
            raise Exception('Can not retrieve node: {e}'.format(e=err))

        if node['State'] != 'Revoked':
            raise Exception('Node is not in revoked state.')

        try:
            self.output('Should unrevoke certificate {d}'.format(d=dn))
            self._storage.unrevoke_node(dn)
        except Exception as err:
            raise Exception('Unable to unrevoke node: {e}'.format(e=err))

        # Generate a new CRL
        try:
            self._upki_generate_crl(params)
        except Exception as err:
            raise Exception(err)

        return True

    def _upki_delete(self, params):
        try:
            dn = params['dn']
        except KeyError:
            raise Exception('Missing DN option')

        try:
            serial = params['serial']
        except KeyError:
            raise Exception('Missing Serial option')

        try:
            cn = self._get_cn(dn)
        except KeyError:
            raise Exception('Missing CN option')

        if not self._storage.exists(dn):
            raise Exception('Node is not registered')

        self.output('Deleting node {d}'.format(d=dn))

        try:
            node = self._storage.get_node(dn)
        except Exception as err:
            raise Exception('Unknown node: {e}'.format(e=err))

        try:
            node_name = "{p}.{c}".format(p=node['Profile'], c=cn)
        except KeyError:
            raise Exception('Unable to build node name')
        
        try:
            self._storage.delete_node(dn, serial)
        except Exception as err:
            raise Exception('Unable to delete node: {e}'.format(e=err))

        # If Key has been generated localy
        if node['Local']:
            try:
                self._storage.delete_private(node_name)
            except Exception as err:
                raise Exception(err)
        # If certificate has been generated
        if node['State'] in ['Active','Revoked']:
            try:
                self._storage.delete_request(node_name)
            except Exception as err:
                raise Exception(err)
            try:
                self._storage.delete_public(node_name)
            except Exception as err:
                raise Exception(err)

        if node['State'] == 'Revoked':
            # Generate a new CRL
            try:
                self._upki_generate_crl(params)
            except Exception as err:
                raise Exception(err)

        return True

    def _upki_view(self, params):
        try:
            dn = params['dn']
        except KeyError:
            raise Exception('Missing DN option')

        try:
            cn = self._get_cn(dn)
        except Exception as err:
            raise Exception('Unable to get CN: {e}'.format(e=err))

        try:
            node = self._storage.get_node(dn)
        except Exception as err:
            raise Exception('Can not retrieve node: {e}'.format(e=err))

        if node['State'] in ['Init','Revoked']:
            # Retreive node values only
            return {'node':node}
        
        elif node['State'] in ['Active']:
            # Should return certificate/Request of Provate key infos
            return {'node':node}

        else:
            return {'node':node}

    def _upki_ocsp_check(self, params):
        try:
            ocsp_req = x509.ocsp.load_der_ocsp_request(params['ocsp'])
        except KeyError:
            raise Exception('Missing OCSP data')
        except Exception as err:
            raise Exception('Invalid OCSP request: {e}'.format(e=err))

        try:
            pem_cert = params['cert'].decode('utf-8')
            cert = x509.load_pem_x509_certificate(pem_cert, self._backend)
        except KeyError:
            raise Exception('Missing certificate data')
        except Exception as err:
            raise Exception('Invalid certificate: {e}'.format(e=err))

            
        
        try:
            (status, rev_time, rev_reason) = self._storage.is_valid(ocsp_req.serial_number)
        except Exception as err:
            self.output('OCSP checking error: {e}'.format(e=err), level="ERROR")
            cert_status = x509.ocsp.OCSPCertStatus.UNKNOWN
            rev_time = None
            rev_reason = None

        if status == 'Valid':
            cert_status = x509.ocsp.OCSPCertStatus.GOOD
        else:
            cert_status = x509.ocsp.OCSPCertStatus.REVOKED

        try:
            builder = x509.ocsp.OCSPResponseBuilder()
            builder = builder.add_response(
                    cert=pem_cert,
                    issuer=cert.issuer,
                    algorithm=hashes.SHA1(),
                    cert_status=cert_status,
                    this_update=datetime.datetime.now(),
                    next_update=datetime.datetime.now(),
                    revocation_time=rev_time,
                    revocation_reason=rev_reason
                ).responder_id(x509.ocsp.OCSPResponderEncoding.HASH, self._ca['cert'])
            response = builder.sign(self._ca['key'], hashes.SHA256())
        except Exception as err:
            raise Exception('Unable to build OCSP response: {e}'.format(e=err))

        return {'response': base64.encodebytes(response)}
