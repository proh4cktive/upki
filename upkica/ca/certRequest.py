# -*- coding:utf-8 -*-

import ipaddress
import validators

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes

import upkica

class CertRequest(upkica.core.Common):
    def __init__(self, config):
        try:
            super(CertRequest, self).__init__(config._logger)
        except Exception as err:
            raise Exception('Unable to initialize certRequest: {e}'.format(e=err))

        self._config   = config

        # Private var
        self.__backend = default_backend()

    def generate(self, pkey, cn, profile, sans=None):
        """Generate a request based on:
            - privatekey (pkey)
            - commonName (cn)
            - profile object (profile)
        add Additional CommonName if needed sans argument
        """

        subject = list([])
        # Extract subject from profile
        try:
            for entry in profile['subject']:
                for subj, value in entry.items():
                    subj = subj.upper()
                    if subj == 'C':
                        subject.append(x509.NameAttribute(NameOID.COUNTRY_NAME, value))
                    elif subj == 'ST':
                        subject.append(x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, value))
                    elif subj == 'L':
                        subject.append(x509.NameAttribute(NameOID.LOCALITY_NAME, value))
                    elif subj == 'O':
                        subject.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, value))
                    elif subj == 'OU':
                        subject.append(x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, value))
        except Exception as err:
            raise Exception('Unable to extract subject: {e}'.format(e=err))
        
        try:
            # Append cn at the end
            subject.append(x509.NameAttribute(NameOID.COMMON_NAME, cn))
        except Exception as err:
            raise Exception('Unable to setup subject name: {e}'.format(e=err))

        try:
            builder = x509.CertificateSigningRequestBuilder().subject_name(x509.Name(subject))
        except Exception as err:
            raise Exception('Unable to create structure: {e}'.format(e=err))

        subject_alt = list([])
        # Best pratices wants to include FQDN in SANS for servers
        if profile['altnames']:
            # Add IPAddress for Goland compliance
            if validators.ipv4(cn):
                subject_alt.append(x509.DNSName(cn))
                subject_alt.append(x509.IPAddress(ipaddress.ip_address(cn)))
            elif validators.domain(cn):
                subject_alt.append(x509.DNSName(cn))
            elif validators.email(cn):
                subject_alt.append(x509.RFC822Name(cn))
            elif validators.url(cn):
                subject_alt.append(x509.UniformResourceIdentifier(cn))
            else:
                if 'server' in profile['certType']:
                    self.output('ADD ALT NAMES {c}.{d} FOR SERVER USAGE'.format(c=cn,d=profile['domain']))
                    subject_alt.append(x509.DNSName("{c}.{d}".format(c=cn,d=profile['domain'])))
                if 'email' in profile['certType']:
                    subject_alt.append(x509.RFC822Name("{c}@{d}".format(c=cn,d=profile['domain'])))
        
        # Add alternate names if needed
        if isinstance(sans, list) and len(sans):
            for entry in sans:
                # Add IPAddress for Goland compliance
                if validators.ipv4(entry):
                    if x509.DNSName(entry) not in subject_alt:
                        subject_alt.append(x509.DNSName(entry))
                    if x509.IPAddress(ipaddress.ip_address(entry)) not in subject_alt:
                        subject_alt.append(x509.IPAddress(ipaddress.ip_address(entry)))
                elif validators.domain(entry) and (x509.DNSName(entry) not in subject_alt):
                    subject_alt.append(x509.DNSName(entry))
                elif validators.email(entry) and (x509.RFC822Name(entry) not in subject_alt):
                    subject_alt.append(x509.RFC822Name(entry))

        if len(subject_alt):
            try:
                builder = builder.add_extension(x509.SubjectAlternativeName(subject_alt), critical=False)
            except Exception as err:
                raise Exception('Unable to add alternate name: {e}'.format(e=err))

        # Add Deprecated nsCertType (still required by some software)
        # nsCertType_oid = x509.ObjectIdentifier('2.16.840.1.113730.1.1')
        # for c_type in profile['certType']:
        #     if c_type.lower() in ['client', 'server', 'email', 'objsign']:
        #         builder.add_extension(nsCertType_oid, c_type.lower())

        if profile['digest'] == 'md5':
            digest = hashes.MD5()
        elif profile['digest'] == 'sha1':
            digest = hashes.SHA1()
        elif profile['digest'] == 'sha256':
            digest = hashes.SHA256()
        elif profile['digest'] == 'sha512':
            digest = hashed.SHA512()
        else:
            raise NotImplementedError('Private key only support {s} digest signatures'.format(s=self._allowed.Digest))

        try:
            csr = builder.sign(private_key=pkey, algorithm=digest, backend=self.__backend)
        except Exception as err:
            raise Exception('Unable to sign certificate request: {e}'.format(e=err))

        return csr

    def load(self, raw, encoding='PEM'):
        """Load a CSR and return a cryptography CSR object
        """
        csr = None
        try:
            if encoding == 'PEM':
                csr = x509.load_pem_x509_csr(raw, backend=self.__backend)
            elif encoding in ['DER','PFX','P12']:
                csr = x509.load_der_x509_csr(raw, backend=self.__backend)
            else:
                raise NotImplementedError('Unsupported certificate request encoding')
        except Exception as err:
            raise Exception(err)
        
        return csr

    def dump(self, csr, encoding='PEM'):
        """Export Certificate requests (CSR) object in PEM mode
        """
        data = None

        if encoding == 'PEM':
            enc = serialization.Encoding.PEM
        elif encoding in ['DER','PFX','P12']:
            enc = serialization.Encoding.DER
        else:
            raise NotImplementedError('Unsupported certificate request encoding')

        try:
            data = csr.public_bytes(enc)
        except Exception as err:
            raise Exception(err)

        return data

    def parse(self, raw, encoding='PEM'):
        """Parse CSR data (PEM default) and return dict with values
        """
        data = dict({})
        
        try:
            if encoding == 'PEM':
                csr = x509.load_pem_x509_csr(raw, backend=self.__backend)
            elif encoding in ['DER','PFX','P12']:
                csr = x509.load_der_x509_csr(raw, backend=self.__backend)
            else:
                raise NotImplementedError('Unsupported certificate request encoding')
        except Exception as err:
            raise Exception(err)

        data['subject'] = csr.subject
        data['digest'] = csr.signature_hash_algorithm
        data['signature'] = csr.signature

        return data