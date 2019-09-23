# -*- coding:utf-8 -*-

import os
import time
import shutil
import tinydb
import datetime

import upkica

from .abstractStorage import AbstractStorage

class FileStorage(AbstractStorage):
    def __init__(self, logger, options):
        try:
            super(FileStorage, self).__init__(logger)
        except Exception as err:
            raise Exception(err)

        try:
            options['path']
        except KeyError:
            raise Exception('Missing mandatory DB options')

        # Define values (pseudo-db)
        self._serials_db  = os.path.join(options['path'], '.serials.json')
        self._nodes_db    = os.path.join(options['path'], '.nodes.json')
        self._admins_db   = os.path.join(options['path'], '.admins.json')
        self._profiles_db = os.path.join(options['path'], 'profiles')
        self._certs_db    = os.path.join(options['path'], 'certs')
        self._reqs_db     = os.path.join(options['path'], 'reqs')
        self._keys_db     = os.path.join(options['path'], 'private')
        
        # Setup handles
        self.db           = dict({'serials': None, 'nodes': None})
        self._options     = options

        # Setup flags
        self._connected   = False
        self._initialized = self._is_initialized()

    def _is_initialized(self):
        # Check DB file, profiles, public, requests and private exists
        if not os.path.isfile(os.path.join(self._keys_db, "ca.key")):
            return False
        if not os.path.isfile(os.path.join(self._reqs_db, "ca.csr")):
            return False
        if not os.path.isfile(os.path.join(self._certs_db, "ca.crt")):
            return False
        if not os.path.isdir(self._profiles_db):
            return False
        if not os.path.isfile(self._serials_db):
            return False
        if not os.path.isfile(self._nodes_db):
            return False
        if not os.path.isfile(self._admins_db):
            return False

        return True

    def initialize(self):
        try:
            self.output("Create directory structure on {p}".format(p=self._options['path']), level="DEBUG")
            # Create directories
            for repo in ['profiles/', 'certs/', 'private/', 'reqs/']:
                self._mkdir_p(os.path.join(self._options['path'], repo))
        except Exception as err:
            raise Exception('Unable to create directories: {e}'.format(e=err))

        return True

    def connect(self):
        try:
            # Create serialFile
            self.db['serials'] = tinydb.TinyDB(self._serials_db)
            # Create indexFile
            self.db['nodes']   = tinydb.TinyDB(self._nodes_db)
            # Create adminFile
            self.db['admins']  = tinydb.TinyDB(self._admins_db)
            self.output('FileDB connected to directory dir://{p}'.format(p=self._options['path']), level="DEBUG")
        except Exception as err:
            raise Exception(err)

        # Set flag
        self._connected    = True

        return True

    def list_admins(self):
        return self.db['admins'].all()

    def add_admin(self, dn):
        if not self.exists(dn):
            raise Exception('This node does not exists')

        try:
            cn = self._get_cn(dn)
        except Exception as err:
            raise Exception('Unable to extract CN from admin DN')

        Query = tinydb.Query()
        
        self.output('Promote user {c} to admin role in nodes DB'.format(c=cn), level="DEBUG")
        self.db['nodes'].update({"Admin":True},Query.DN.search(dn))

        self.output('Add admin {d} in admins DB'.format(d=dn), level="DEBUG")
        self.db['admins'].insert({"name": cn, "dn": dn})

        return True

    def remove_admin(self, dn):
        if not self.exists(dn):
            raise Exception('This node does not exists')

        try:
            cn = self._get_cn(dn)
        except Exception as err:
            raise Exception('Unable to extract CN from admin DN')

        Query = tinydb.Query()
        
        self.output('Un-Promote user {c} to admin role in nodes DB'.format(c=cn), level="DEBUG")
        self.db['nodes'].update({"Admin":False},Query.DN.search(dn))

        self.output('Remove admin {d} from admins DB'.format(d=dn), level="DEBUG")
        self.db['admins'].remove(tinydb.where('dn') == dn)

        return True

    def list_profiles(self):
        profiles = dict({})

        # Parse all profiles set
        for file in os.listdir(self._profiles_db):
            if file.endswith('.yml'):
                # Only store filename without extensions
                filename = os.path.splitext(file)[0]
                try:
                    data  = self._parseYAML(os.path.join(self._profiles_db, file))
                    clean = self._check_profile(data)
                    profiles[filename] = dict(clean)
                except Exception as err:
                    self.output(err, level='ERROR')
                    # If file is not a valid profile just skip it
                    continue
        
        return profiles

    def load_profile(self, name):
        try:
            data = self._parseYAML(os.path.join(self._profiles_db, '{n}.yml'.format(n=name)))
        except Exception as err:
            raise Exception(err)

        return data

    def update_profile(self, original, name, clean):
        try:
            self._storeYAML(os.path.join(self._profiles_db, '{n}.yml'.format(n=name)), clean)
        except Exception as err:
            raise Exception(err)

        return True
        
    def store_profile(self, name, clean):
        try:
            self._storeYAML(os.path.join(self._profiles_db, '{n}.yml'.format(n=name)), clean)
        except Exception as err:
            raise Exception(err)

        return True

    def delete_profile(self, name):
        try:
            os.remove(os.path.join(self._profiles_db, '{n}.yml'.format(n=name)))
        except Exception as err:
            raise Exception('Unable to delete profile file: {e}'.format(e=err))

        return True

    def serial_exists(self, serial):
        Serial = tinydb.Query()
        return self.db['serials'].contains(Serial.number == serial)

    def store_key(self, pkey, nodename, ca=False, encoding='PEM'):
        """Create a pem file in private/ directory
            - pkey (bytes) is content
            - nodename (string) for naming
        """
        if nodename is None:
            raise Exception('Can not store private key with null name.')

        if encoding == 'PEM':
            ext = 'key'
        elif encoding in 'DER':
            ext = 'key'
        elif encoding in ['PFX','P12']:
            # ext = 'p12'
            raise NotImplementedError('P12 private encoding not yet supported, sorry!')
        else:
            raise NotImplementedError('Unsupported private key encoding')

        key_path = os.path.join(self._keys_db, "{n}.{e}".format(n=nodename, e=ext))
        with open(key_path, 'wb') as raw:
            raw.write(pkey)

        try:
            # Protect CA private keys from rewrite
            if ca:
                os.chmod(key_path, 0o400)
        except Exception as err:
            raise Exception(err)

        return key_path

    def store_request(self, req, nodename, ca=False, encoding='PEM'):
        """Create a pem file in reqs/ directory
            - req (bytes) is content
            - nodename (string) for naming
        """
        if nodename is None:
            raise Exception('Can not store certificate request with null name.')

        if encoding == 'PEM':
            ext = 'csr'
        elif encoding in 'DER':
            ext = 'csr'
        elif encoding in ['PFX','P12']:
            # ext = 'p12'
            raise NotImplementedError('P12 certificate request encoding not yet supported, sorry!')
        else:
            raise NotImplementedError('Unsupported certificate request encoding')

        csr_path = os.path.join(self._reqs_db, "{n}.{e}".format(n=nodename, e=ext))
        with open(csr_path, 'wb') as raw:
            raw.write(req)

        try:
            # Protect CA certificate request from rewrite
            if ca:
                os.chmod(csr_path, 0o400)
        except Exception as err:
            raise Exception(err)

        return csr_path

    def download_request(self, nodename, encoding='PEM'):
        if nodename is None:
            raise Exception('Can not download a certificate request with null name')

        if encoding == 'PEM':
            ext = 'csr'
        elif encoding in 'DER':
            ext = 'csr'
        elif encoding in ['PFX','P12']:
            # ext = 'p12'
            raise NotImplementedError('P12 certificate request encoding not yet supported, sorry!')
        else:
            raise NotImplementedError('Unsupported certificate request encoding')

        csr_path = os.path.join(self._reqs_db, "{n}.{e}".format(n=nodename, e=ext))

        if not os.path.isfile(csr_path):
            raise Exception('Certificate request does not exists!')

        with open(csr_path, 'rt') as node_file:
            result = node_file.read()

        return result

    def delete_request(self, nodename, ca=False, encoding='PEM'):
        """Delete the PEM file used for request
        """
        if nodename is None:
            raise Exception('Can not delete certificate request with null name.')

        if encoding == 'PEM':
            ext = 'csr'
        elif encoding in 'DER':
            ext = 'csr'
        elif encoding in ['PFX','P12']:
            # ext = 'p12'
            raise NotImplementedError('P12 certificate request encoding not yet supported, sorry!')
        else:
            raise NotImplementedError('Unsupported certificate request encoding')

        csr_path = os.path.join(self._reqs_db, "{n}.{e}".format(n=nodename, e=ext))
        # If CSR does NOT exists: no big deal
        if os.path.isfile(csr_path):
            try:
                if ca:
                    # Remove old certificate protection
                    os.chmod(csr_path, 0o600)
                # Then delete file
                os.remove(csr_path)
            except Exception as err:
                raise Exception('Unable to delete certificate request: {e}'.format(e=err))

        return True

    def store_public(self, crt, nodename, ca=False, encoding='PEM'):
        """Create a pem file in certs/ directory
            - crt (bytes) is content
            - nodename (string) for naming
        """
        if nodename is None:
            raise Exception('Can not store certificate with null name.')

        if encoding == 'PEM':
            ext = 'crt'
        elif encoding in 'DER':
            ext = 'cer'
        elif encoding in ['PFX','P12']:
            # ext = 'p12'
            raise NotImplementedError('P12 certificate encoding not yet supported, sorry!')
        else:
            raise NotImplementedError('Unsupported certificate encoding')

        crt_path = os.path.join(self._certs_db, "{n}.{e}".format(n=nodename, e=ext))
        with open(crt_path, 'wb') as raw:
            raw.write(crt)

        try:
            # Protect CA certificate from rewrite
            if ca:
                os.chmod(crt_path, 0o400)
        except Exception as err:
            raise Exception(err)

        return crt_path

    def download_public(self, nodename, encoding='PEM'):
        """Download a certificate from certs/ directory
        """
        if nodename is None:
            raise Exception('Can not download a public certificate with name null')

        if encoding == 'PEM':
            ext = 'crt'
        elif encoding in 'DER':
            ext = 'cer'
        elif encoding in ['PFX','P12']:
            # ext = 'p12'
            raise NotImplementedError('P12 certificate encoding not yet supported, sorry!')
        else:
            raise NotImplementedError('Unsupported certificate encoding')

        filename = "{n}.{e}".format(n=nodename, e=ext)
        node_path = os.path.join(self._certs_db, filename)

        if not os.path.isfile(node_path):
            raise Exception('Certificate does not exists!')

        with open(node_path, 'rt') as node_file:
            result = node_file.read()

        return result

    def delete_public(self, nodename, ca=False, encoding='PEM'):
        """Delete the PEM file used for certificate
        """
        if nodename is None:
            raise Exception('Can not delete certificate with null name.')

        if encoding == 'PEM':
            ext = 'crt'
        elif encoding in 'DER':
            ext = 'cer'
        elif encoding in ['PFX','P12']:
            # ext = 'p12'
            raise NotImplementedError('P12 certificate encoding not yet supported, sorry!')
        else:
            raise NotImplementedError('Unsupported certificate encoding')

        crt_path = os.path.join(self._certs_db, "{n}.{e}".format(n=nodename, e=ext))
        try:
            if ca:
                # Remove old certificate protection
                os.chmod(crt_path, 0o600)
            # Then delete file
            os.remove(crt_path)
        except Exception as err:
            raise Exception('Unable to delete certificate: {e}'.format(e=err))

        return True

    def store_crl(self, crl, next_crl_days=30):
        """Create a pem file named crl.pem
            - crl (bytes) is content
            - next_crl_days (int) default 30 force next CRL generation date
        """
        crl_path = os.path.join(self._options['path'], "crl.pem")
        with open(crl_path, 'wb') as raw:
            raw.write(crt)

        return True

    def terminate(self):
        """Delete all PKI data and certs
        Remove CA certificates locks
        Delete CRL if exists
        Delete databases
        Delete certs/ reqs/ and private/ directories and content
        Note: logs/ is kept with config file
        """
        self.output('Delete all PKI data and certs', level="WARNING")

        try:
            # Remove CA locks
            os.chmod(os.path.join(self._keys_db, 'ca.key'), 0o700)
            os.chmod(os.path.join(self._reqs_db, 'ca.csr'), 0o700)
            os.chmod(os.path.join(self._certs_db, 'ca.crt'), 0o700)
        except Exception as err:
            self.output('Unable to remove CA keychain locks: {e}'.format(e=err), level='WARNING')

        try:
            # Remove CRL if exists
            crl_file = os.path.join(self._options['path'],'crl.pem')
            self.output('Delete CRL file {f}'.format(f=crl_file), level="WARNING")
            os.remove(crl_file)
        except Exception as err:
            self.output('Unable to remove CRL file: {e}'.format(e=err), level='WARNING')

        try:
            # Remove all DB
            for filename in [self._serial_db, self._nodes_db]:
                self.output('Remove database {f}'.format(f=filename), level="WARNING")
                os.chmod(filename, 0o700)
                os.remove(filename)
        except Exception as err:
            self.output('Unable to remove datases: {e}'.format(e=err), level='WARNING')

        try:
            # Remove all directories (keep logs/ and config)
            for repo in ['profiles', 'certs', 'private', 'reqs']:
                dirname = os.path.join(self._options['path'], repo)
                self.output('Delete directory {d}'.format(d=dirname), level="WARNING")
                shutil.rmtree(dirname, ignore_errors=True)
        except Exception as err:
            self.output('Unable to remove directories: {e}'.format(e=err), level='WARNING')
        
        return True
    
    def exists(self, name, profile=None, uid=None):
        """Check if an entry is set
            - name (string) if used alone MUST be a DN, with profile MUST be a CN
            - profile (string) is a profile name
            - uid (int) when used other parameters are ignored
        """
        Node = tinydb.Query()
        if uid is not None:
            # If uid is set, return corresponding
            return self.db['nodes'].contains(doc_ids=[uid])
        elif profile is None:
            # If profile is empty, must find a DN for name
            return self.db['nodes'].contains(Node.DN == name)
        # Search for name/profile couple entry
        return self.db['nodes'].contains((Node.CN == name) & (Node.Profile == profile))

    def is_valid(self, serial_number):
        """Return if a particular certificate serial number is valid
        """
        if serial_number is None:
            raise Exception('Serial number missing')

        self.output('OCSP request against {n} serial'.format(n=serial_number))

        Node = tinydb.Query()
        if not self.db['nodes'].contains(Node.Serial == serial_number):
            raise Exception('Certificate does not exists')

        result = self.db['nodes'].search(Node.Serial == serial_number)
        revocation_time = None
        revocation_reason = None

        try:
            cert_status = result[0]['State']
        except (IndexError, KeyError):
            raise Exception('Certificate not properly configured')

        try:
            revocation_time   = result[0]['Revoke_Date']
            revocation_reason = result[0]['Reason']
        except (IndexError, KeyError):
            pass

        return (cert_status, revocation_time, revocation_reason)

    def get_ca(self):
        """Return CA certificate content (PEM encoded)
        """
        with open(os.path.join(self._certs_db, 'ca.crt'), 'rt') as cafile:
            data = cafile.read()

        return data

    def get_crl(self):
        """Return CRL content (PEM encoded)
        """
        crl_path = os.path.join(self._options['path'], 'crl.pem')

        if not os.path.isfile(crl_path):
            raise Exception('CRL as not been generated yet!')

        with open(crl_path, 'rt') as crlfile:
            data = crlfile.read()

        return data

    def store_crl(self, crl_pem):
        """Store the CRL (PEM encoded) file on disk
        """
        crl_path = os.path.join(self._options['path'], 'crl.pem')

        # Complete rewrite of file
        # TODO: Also publish updates ?
        with open(crl_path, 'wb') as crlfile:
            crlfile.write(crl_pem)

        return True

    def register_node(self, dn, profile_name, profile_data, sans=[], keyType=None, keyLen=None, digest=None, duration=None, local=False):
        """Register node in DB only
        Note: no check are done on values
        """
        try:
            cn = self._get_cn(dn)
        except Exception as err:
            raise Exception('Unable to extract CN')

        # Auto-configure infos based on profile if necessary
        if keyType is None:
            keyType = profile_data['keyType']
        if keyLen is None:
            keyLen = profile_data['keyLen']
        if digest is None:
            digest = profile_data['digest']
        if duration is None:
            duration = profile_data['duration']

        try:
            altnames = profile_data['altnames']
        except KeyError:
            altnames = False
        try:
            domain = profile_data['domain']
        except KeyError:
            domain = None

        Node = tinydb.Query()
        now = time.time()
        created_human = datetime.datetime.utcfromtimestamp(now).strftime('%Y-%m-%d %H:%M:%S')
        return self.db['nodes'].insert({
                "Admin": False,
                "DN": dn,
                "CN": cn,
                "Sans": sans,
                "State": "Init",
                "Created": int(now),
                "Created_human": created_human,
                "Start": None,
                "Start_human": None,
                "Expire": None,
                "Expire_human": None,
                "Duration": duration,
                "Serial": None,
                "Profile": profile_name,
                "Domain": domain,
                "Altnames": altnames,
                "Remote": True,
                "Local": local,
                "KeyType": keyType,
                "KeyLen": keyLen,
                "Digest": digest})
    
    def update_node(self, dn, profile_name, profile_data, sans=[], keyType=None, keyLen=None, digest=None, duration=None, local=False):
        """Update node in DB only
        Note: no check are done on values
        """
        try:
            cn = self._get_cn(dn)
        except Exception as err:
            raise Exception('Unable to extract CN')

        # Auto-configure infos based on profile if necessary
        if keyType is None:
            keyType = profile_data['keyType']
        if keyLen is None:
            keyLen = profile_data['keyLen']
        if digest is None:
            digest = profile_data['digest']
        if duration is None:
            duration = profile_data['duration']

        try:
            altnames = profile_data['altnames']
        except KeyError:
            altnames = False
        try:
            domain = profile_data['domain']
        except KeyError:
            domain = None

        # Update can only work on certain fields
        Node = tinydb.Query()
        self.db['nodes'].update({"Profile":profile_name},Node.DN.search(dn))
        self.db['nodes'].update({"Sans":sans},Node.DN.search(dn))
        self.db['nodes'].update({"KeyType":keyType},Node.DN.search(dn))
        self.db['nodes'].update({"KeyLen":keyLen},Node.DN.search(dn))
        self.db['nodes'].update({"Digest":digest},Node.DN.search(dn))
        self.db['nodes'].update({"Duration":duration},Node.DN.search(dn))
        self.db['nodes'].update({"Local":local},Node.DN.search(dn))

        return True
        
    def get_node(self, name, profile=None, uid=None):
        """Return a specific node and this one as expired auto update it
        """
        Node = tinydb.Query()
        if uid is not None:
            # If uid is set, return corresponding
            result = [self.db['nodes'].get(doc_id=uid)]
        elif profile is None:
            # If profile is empty, must find a DN for name
            result = self.db['nodes'].search(Node.DN == name)
        else:
            # Search for name/profile couple entry
            result = self.db['nodes'].search((Node.CN == name) & (Node.Profile == profile))
        
        if len(result) > 1:
            raise Exception('Multiple entry found...')

        if len(result) == 0:
            raise Exception('Unknown entry')

        try:
            node = dict(result[0])
            node['DN']
            node['State']
            node['Expire']
        except (IndexError, KeyError):
            raise Exception('No entry found')

        if (node['Expire'] != None) and (node['Expire'] <= int(time.time())):
            node['State'] = 'Expired'
            self.expire_node(node['DN'])

        return node

    def list_nodes(self):
        """Return list of all nodes, auto update expired ones
        """
        Node = tinydb.Query()

        nodes = self.db['nodes'].all()

        # Use loop to clean datas
        for i, node in enumerate(nodes):
            try:
                node['DN']
                node['Serial']
                node['State']
                node['Expire']
            except KeyError:
                continue
            # Check expiration
            if (node['Expire'] != None) and (node['Expire'] <= int(time.time())):
                nodes[i]['State'] = 'Expired'
                try:
                    self.expire_node(node['DN'])
                except Exception:
                    continue
        
        return nodes

    def get_revoked(self):
        Node = tinydb.Query()
        return self.db['nodes'].search(Node.State == 'Revoked')

    def activate_node(self, dn):
        Node = tinydb.Query()
        # Should set state to Manual if config requires it
        self.db['nodes'].update({"State":"Active"},Node.DN.search(dn))
        self.db['nodes'].update({"Generated":True},Node.DN.search(dn))

        return True
        
    def certify_node(self, dn, cert, internal=False):
        Node = tinydb.Query()

        self.output('Add serial {s} in serial DB'.format(s=cert.serial_number), level="DEBUG")
        self.db['serials'].insert({'number':cert.serial_number})

        # Do not register internal certificates (CA/Server/RA)
        if not internal:
            self.output('Add certificate for {d} in node DB'.format(d=dn), level="DEBUG")
            self.db['nodes'].update({"Serial":cert.serial_number},Node.DN.search(dn))
            self.db['nodes'].update({"State":"Valid"},Node.DN.search(dn))
            # Update start time
            start_time = cert.not_valid_before.timestamp()
            start_human = cert.not_valid_before.strftime('%Y-%m-%d %H:%M:%S')
            self.db['nodes'].update({"Start":int(start_time)},Node.DN.search(dn))
            self.db['nodes'].update({"Start_human":start_human},Node.DN.search(dn))
            # Set end time
            end_time = cert.not_valid_after.timestamp()
            end_human = cert.not_valid_after.strftime('%Y-%m-%d %H:%M:%S')
            self.db['nodes'].update({"Expire":int(end_time)},Node.DN.search(dn))
            self.db['nodes'].update({"Expire_human":end_human},Node.DN.search(dn))
        elif self.exists(dn):
            self.output('Avoid register {d}. Used for internal purpose'.format(d=dn), level="WARNING")
            self.db['nodes'].remove(tinydb.where('DN') == dn)

        return True

    def expire_node(self, dn):
        Node = tinydb.Query()
        self.output('Set certificate {d} as expired'.format(d=dn), level="DEBUG")

        self.db['nodes'].update({"State":'Expired'}, Node.DN.search(dn))

        return True
        
    def renew_node(self, dn, cert, old_serial):
        Node = tinydb.Query()
        
        self.output('Remove old serial {s} in serial DB'.format(s=old_serial), level="DEBUG")
        self.db['serials'].remove(tinydb.where('number') == old_serial)

        self.output('Add new serial {s} in serial DB'.format(s=cert.serial_number), level="DEBUG")
        self.db['serials'].insert({'number':cert.serial_number})

        # Update start time
        start_time = cert.not_valid_before.timestamp()
        start_human = cert.not_valid_before.strftime('%Y-%m-%d %H:%M:%S')
        self.db['nodes'].update({"Start":int(start_time)},Node.DN.search(dn))
        self.db['nodes'].update({"Start_human":start_human},Node.DN.search(dn))

        # Set end time
        end_time = cert.not_valid_after.timestamp()
        end_human = cert.not_valid_after.strftime('%Y-%m-%d %H:%M:%S')
        self.db['nodes'].update({"Expire":int(end_time)},Node.DN.search(dn))
        self.db['nodes'].update({"Expire_human":end_human},Node.DN.search(dn))

        return True
        
    def revoke_node(self, dn, reason='unspecified'):
        Node = tinydb.Query()
        # self.db['nodes'].update({"Start":None},Node.DN.search(dn))
        # self.db['nodes'].update({"Expire":None},Node.DN.search(dn))
        self.db['nodes'].update({"State":"Revoked"},Node.DN.search(dn))
        self.db['nodes'].update({"Reason":reason}, Node.DN.search(dn))
        self.db['nodes'].update({"Revoke_Date":datetime.datetime.utcnow().strftime('%Y%m%d%H%M%SZ')}, Node.DN.search(dn))

        return True
    
    def unrevoke_node(self, dn):
        Node = tinydb.Query()
        # self.db['nodes'].update({"Start":None},Node.DN.search(dn))
        # self.db['nodes'].update({"Expire":None},Node.DN.search(dn))
        self.db['nodes'].update({"State":"Valid"},Node.DN.search(dn))
        self.db['nodes'].update({"Reason":None}, Node.DN.search(dn))
        self.db['nodes'].update({"Revoke_Date":None}, Node.DN.search(dn))

        return True
    
    def delete_node(self, dn, serial):
        self.db['serials'].remove(tinydb.where('number') == serial)
        self.db['nodes'].remove(tinydb.where('DN') == dn)

        return True

    
    

    