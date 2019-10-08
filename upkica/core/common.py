# -*- coding:utf-8 -*-

import os
import re
import sys
import yaml
import validators

import upkica

class Common(object):
    def __init__(self, logger, fuzz=False):
        self._logger = logger
        self._fuzz   = fuzz

        self._allowed  = upkica.core.Options()

    def output(self, msg, level=None, color=None, light=False):
        """Generate output to CLI and log file
        """
        try:
            self._logger.write(msg, level=level, color=color, light=light)
        except Exception as err:
            sys.out.write('Unable to log: {e}'.format(e=err))

    def _storeYAML(self, yaml_file, data):
        """Store data in YAML file
        """
        with open(yaml_file, 'wt') as raw:
            raw.write(yaml.safe_dump(data, default_flow_style=False, indent=4))

        return True

    def _parseYAML(self, yaml_file):
        """Parse YAML file and return object generated
        """
        with open(yaml_file, 'rt') as stream:
            cfg = yaml.safe_load(stream.read())
        
        return cfg

    def _check_profile(self, data):
        try:
            data['keyType']  = data['keyType'].lower()
            data['keyLen']   = int(data['keyLen'])
            data['duration'] = int(data['duration'])
            data['digest']   = data['digest'].lower()
            data['certType'] = data['certType']
            data['subject']
            data['keyUsage']
        except KeyError:
            raise Exception('Missing profile mandatory value')
        except ValueError:
            raise Exception('Invalid profile values')

        # Auto-setup optionnal values
        try:
            data['altnames']
        except KeyError:
            data['altnames'] = False

        try:
            data['crl']
        except KeyError:
            data['crl'] = None

        try:
            data['ocsp']
        except KeyError:
            data['ocsp'] = None

        # Start building clean object
        clean = dict({})
        clean['altnames'] = data['altnames']
        clean['crl']      = data['crl']
        clean['ocsp']     = data['ocsp']

        try:
            data['domain']
            if not validators.domain(data['domain']):
                raise Exception('Domain is invalid')
            clean['domain'] = data['domain']
        except KeyError:
            clean['domain'] = None
        
        try:
            data['extendedKeyUsage']
        except KeyError:
            data['extendedKeyUsage'] = list()

        if data['keyType'] not in self._allowed.KeyTypes:
            raise NotImplementedError('Private key only support {t} key type'.format(t=self._allowed.KeyTypes))
        clean['keyType'] = data['keyType']

        if data['keyLen'] not in self._allowed.KeyLen:
            raise NotImplementedError('Private key only support {b} key size'.format(b=self._allowed.KeyLen))
        clean['keyLen'] = data['keyLen']

        if not validators.between(data['duration'],1,36500):
            raise Exception('Duration is invalid')
        clean['duration'] = data['duration']
        
        if data['digest'] not in self._allowed.Digest:
            raise NotImplementedError('Hash signing only support {h}'.format(h=self._allowed.Digest))
        clean['digest'] = data['digest']

        if not isinstance(data['certType'], list):
            raise Exception('Certificate type values are incorrect')
        for value in data['certType']:
            if value not in self._allowed.CertTypes:
                raise NotImplementedError('Profiles only support {t} certificate types'.format(t=self._allowed.CertTypes))
        clean['certType'] = data['certType']

        if not isinstance(data['subject'], list):
            raise Exception('Subject values are incorrect')
        if not len(data['subject']):
            raise Exception('Subject values can not be empty')
        if len(data['subject']) < 4:
            raise Exception('Subject seems too short (minimum 4 entries: /C=XX/ST=XX/L=XX/O=XX)')
        clean['subject'] = list()
        # Set required keys
        required = list(['C','ST','L','O'])
        for subj in data['subject']:
            if not isinstance(subj, dict):
                raise Exception('Subject entries are incorrect')
            try:
                key = list(subj.keys())[0]
                value = subj[key]
            except IndexError:
                continue
            key = key.upper()
            if key not in self._allowed.Fields:
                raise Exception('Subject only support fields from {f}'.format(f=self._allowed.Fields))
            clean['subject'].append({key: value})
            # Allow multiple occurences
            if key in required:
                required.remove(key)
        if len(required):
            raise Exception('Subject fields required at least presence of: C (country), ST (state) ,L (locality), O (organisation)')

        if not isinstance(data['keyUsage'], list):
            raise Exception('Key values are incorrect')
        clean['keyUsage'] = list()
        for kuse in data['keyUsage']:
            if kuse not in self._allowed.Usages:
                raise Exception('Key usage only support fields from {f}'.format(f=self._allowed.Usages))
            clean['keyUsage'].append(kuse)

        if not isinstance(data['extendedKeyUsage'], list):
            raise Exception('Extended Key values are incorrect')
        clean['extendedKeyUsage'] = list()
        for ekuse in data['extendedKeyUsage']:
            if ekuse not in self._allowed.ExtendedUsages:
                raise Exception('Extended Key usage only support fields from {f}'.format(f=self._allowed.ExtendedUsages))
            clean['extendedKeyUsage'].append(ekuse)

        return clean

    def _check_node(self, params, profile):
        """Check basic options from node
        """
        clean = dict({})
        try:
            if isinstance(params['sans'], list):
                clean['sans'] = params['sans']
            elif isinstance(params['sans'], basestring):
                clean['sans'] = [san.strip() for san in params['sans'].split(',')]
        except KeyError:
            clean['sans'] = []

        try:
            clean['keyType'] = self._allowed.clean(params['keyType'], 'KeyTypes')
        except KeyError:
            clean['keyType'] = profile['keyType']

        try:
            clean['keyLen'] = self._allowed.clean(int(params['keyLen']), 'KeyLen')
        except (KeyError,ValueError):
            clean['keyLen'] = profile['keyLen']

        try:
            clean['duration'] = int(params['duration'])
            if 0 >= clean['duration'] <= 36500:
                clean['duration'] = profile['duration']
        except (KeyError,ValueError):
            clean['duration'] = profile['duration']

        try:
            clean['digest'] = self._allowed.clean(params['digest'], 'Digest')
        except KeyError:
            clean['digest'] = profile['digest']

        return clean

    def _mkdir_p(self, path):
        """Create directories from a pth if does not exists
        like mkidr -p"""

        try:
            # Extract directory from path if filename
            path = os.path.dirname(path)
        except Exception as err:
            raise Exception(err)

        try:
            self.output('Create {d} directory...'.format(d=path), level="DEBUG")
            os.makedirs(path)
        except OSError as err:
            if err.errno == os.errno.EEXIST and os.path.isdir(path):
                pass
            else:
                raise Exception(err)

        return True

    def _get_dn(self, subject):
        """Convert x509 subject object in standard string
        """
        rdn = list()
        for n in subject.rdns:
            rdn.append(n.rfc4514_string())
        dn = '/'.join(rdn)
        
        return '/' + dn
        # return subject.rfc4514_string()
    
    def _get_cn(self, dn):
        """Retrieve the CN value from complete DN
        perform validity check on CN found
        """
        try:
            cn = str(dn).split('CN=')[1]
        except Exception:
            raise Exception('Unable to get CN from DN string')

        # Ensure cn is valid
        if (cn is None) or not len(cn):
            raise Exception('Empty CN option')
        if not (re.match('^[\w\-_\.\s@]+$', cn) is not None):
            raise Exception('Invalid CN')

        return cn

    def _prettify(self, serial, group=2, separator=':'):
        """Return formatted string from serial number
        bytes to "XX:XX:XX:XX:XX"
        """
        if serial is None:
            return None

        try:
            human_serial = "{0:2x}".format(serial).upper()
            return separator.join(human_serial[i:i+group] for i in range(0, len(human_serial), group))
        except Exception as err:
            raise Exception('Unable to convert serial number: {e}'.format(e=err))

        return None

    def _ask(self, msg, default=None, regex=None, mandatory=True):
        """Allow to interact with user in CLI to fill missing values
        """
        while True:
            if default is not None:
                rep = input("{m} [{d}]: ".format(m=msg,d=default))
            else:
                rep = input("{m}: ".format(m=msg))
            
            if len(rep) is 0:
                if (default is None) and mandatory:
                    self.output('Sorry this value is mandatory.', level="ERROR")
                    continue
                rep = default
            
            # Do not check anything while fuzzing
            if (not self._fuzz) and (regex is not None):
                if (regex.lower() == 'domain') and not validators.domain(rep):
                    self.output('Sorry this value is invalid.', level="ERROR")
                    continue
                elif (regex.lower() == 'email') and not validators.email(rep):
                    self.output('Sorry this value is invalid.', level="ERROR")
                    continue
                elif (regex.lower() == 'ipv4') and not validators.ipv4(rep):
                    self.output('Sorry this value is invalid.', level="ERROR")
                    continue
                elif (regex.lower() == 'ipv6') and not validators.ipv6(rep):
                    self.output('Sorry this value is invalid.', level="ERROR")
                    continue
                elif (regex.lower() == 'port') and not validators.between(rep, min=1,max=65535):
                    self.output('Sorry this value is invalid.', level="ERROR")
                    continue
                elif (not re.match(regex, rep)):
                    self.output('Sorry this value is invalid.', level="ERROR")
                    continue

            break

        return rep