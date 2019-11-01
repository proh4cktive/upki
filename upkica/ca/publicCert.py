# -*- coding:utf-8 -*-

import sys
import datetime
import validators

from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID, ExtendedKeyUsageOID
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes

import upkica

class PublicCert(upkica.core.Common):
    def __init__(self, config):
        try:
            super(PublicCert, self).__init__(config._logger)
        except Exception as err:
            raise Exception('Unable to initialize publicCert: {e}'.format(e=err))

        self._config   = config

        # Private var
        self.__backend = default_backend()

    def _generate_serial(self):
        """Generate a certificate serial number
        check serial does not exists in DB
        """
        serial = x509.random_serial_number()
        while self._config.storage.serial_exists(serial):
            serial = x509.random_serial_number()

        return serial

    def generate(self, csr, issuer_crt, issuer_key, profile, ca=False, selfSigned=False, start=None, duration=None, digest=None, sans=[]):
        """Generate a certificate using:
            - Certificate request (csr)
            - Issuer certificate (issuer_crt)
            - Issuer key (issuer_key)
            - profile object (profile)
        Optional parameters set:
            - a CA certificate role (ca)
            - a self-signed certificate (selfSigned)
            - a specific start timestamp (start) 
        """
        
        # Retrieve subject from csr
        subject = csr.subject
        self.output('Subject found: {s}'.format(s=subject.rfc4514_string()), level="DEBUG")
        dn = self._get_dn(subject)
        self.output('DN found is {d}'.format(d=dn), level="DEBUG")
        
        try:
            alt_names = None
            alt_names = csr.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            self.output('Subject alternate found: {s}'.format(s=alt_names), level="DEBUG")
        except x509.ExtensionNotFound as err:
            pass

        # Force default if necessary
        now = datetime.datetime.utcnow() if start is None else datetime.fromtimestamp(start)
        duration = profile['duration'] if duration is None else duration

        # Generate serial number
        try:
            serial_number = self._generate_serial()
        except Exception as err:
            raise Exception('Error during serial number generation: {e}'.format(e=err))

        # For self-signed certificate issuer is certificate itself
        issuer_name   = subject if selfSigned else issuer_crt.issuer
        issuer_serial = serial_number if selfSigned else issuer_crt.serial_number
        
        try:
            # Define basic constraints
            if ca:
                basic_contraints = x509.BasicConstraints(ca=True, path_length=0)
            else:
                basic_contraints = x509.BasicConstraints(ca=False, path_length=None)
            builder = (
                x509.CertificateBuilder()
                .subject_name(subject)
                .issuer_name(issuer_name)
                .public_key(csr.public_key())
                .serial_number(serial_number)
                .not_valid_before(now)
                .not_valid_after(now + datetime.timedelta(days=duration))
                .add_extension(basic_contraints, critical=True)
            )
        except Exception as err:
            raise Exception('Unable to build structure: {e}'.format(e=err))

        # We never trust CSR extensions
        # they may have been alterated by the user
        try:
            # Due to uPKI design (TLS for renew), digital_signature MUST be setup
            digital_signature  = True
            # Initialize key usage
            content_commitment = False
            key_encipherment   = False
            data_encipherment  = False
            key_agreement      = False
            key_cert_sign      = False
            crl_sign           = False
            encipher_only      = False
            decipher_only      = False

            # Build Key Usages from profile
            for usage in profile['keyUsage']:
                if usage == 'digitalSignature':
                    digital_signature = True
                elif usage == 'nonRepudiation':
                    content_commitment = True
                elif usage == 'keyEncipherment':
                    key_encipherment = True
                elif usage == 'dataEncipherment':
                    data_encipherment = True
                elif usage == 'keyAgreement':
                    key_agreement = True
                elif usage == 'keyCertSign':
                    key_cert_sign = True
                elif usage == 'cRLSign':
                    crl_sign = True
                elif usage == 'encipherOnly':
                    encipher_only = True
                elif usage == 'decipherOnly':
                    decipher_only = True
            
            # Setup X509 Key Usages
            key_usages = x509.KeyUsage(
                digital_signature=digital_signature,
                content_commitment=content_commitment,
                key_encipherment=key_encipherment,
                data_encipherment=data_encipherment,
                key_agreement=key_agreement,
                key_cert_sign=key_cert_sign,
                crl_sign=crl_sign,
                encipher_only=encipher_only,
                decipher_only=decipher_only
            )
            builder = builder.add_extension(key_usages, critical=True)
        except KeyError:
            # If no Key Usages are set, thats strange
            raise Exception('No Key Usages set.')
        except Exception as err:
            raise Exception('Unable to set Key Usages: {e}'.format(e=err))

        try:
            # Build Key Usages extended based on profile
            key_usages_extended = list()
            for eusage in profile['extendedKeyUsage']:
                if eusage == 'serverAuth':
                    key_usages_extended.append(ExtendedKeyUsageOID.SERVER_AUTH)
                elif eusage == 'clientAuth':
                    key_usages_extended.append(ExtendedKeyUsageOID.CLIENT_AUTH)
                elif eusage == 'codeSigning':
                    key_usages_extended.append(ExtendedKeyUsageOID.CODE_SIGNING)
                elif eusage == 'emailProtection':
                    key_usages_extended.append(ExtendedKeyUsageOID.EMAIL_PROTECTION)
                elif eusage == 'timeStamping':
                    key_usages_extended.append(ExtendedKeyUsageOID.TIME_STAMPING)
                elif eusage == 'OCSPSigning':
                    key_usages_extended.append(ExtendedKeyUsageOID.OCSP_SIGNING)
            
            #### CHECK TROUBLES ASSOCIATED WITH THIS CHOICE #####
            # Always add 'clientAuth' for automatic renewal
            if ExtendedKeyUsageOID.CLIENT_AUTH not in key_usages_extended:
                key_usages_extended.append(ExtendedKeyUsageOID.CLIENT_AUTH)
            #####################################################

            # Add Deprecated nsCertType (still required by some software)
            # nsCertType_oid = x509.ObjectIdentifier('2.16.840.1.113730.1.1')
            # for c_type in profile['certType']:
            #     if c_type.lower() in ['client', 'server', 'email', 'objsign']:
            #         builder.add_extension(nsCertType_oid, c_type.lower())

            # Set Key Usages if needed
            if len(key_usages_extended):
                builder = builder.add_extension(x509.ExtendedKeyUsage(key_usages_extended), critical=False)
        except KeyError:
            # If no extended key usages are set, do nothing
            pass
        except Exception as err:
            raise Exception('Unable to set Extended Key Usages: {e}'.format(e=err))

        # Add alternate names if found in CSR
        if alt_names is not None:
            # Verify each time that SANS entry was registered
            # We can NOT trust CSR data (client manipulation)
            subject_alt = list([])
            
            for entry in alt_names.value.get_values_for_type(x509.IPAddress):
                if entry not in sans:
                    continue
                subject_alt.append(x509.IPAddress(ipaddress.ip_address(entry)))
            
            for entry in alt_names.value.get_values_for_type(x509.DNSName):
                if entry not in sans:
                    continue
                subject_alt.append(x509.DNSName(entry))
            
            for entry in alt_names.value.get_values_for_type(x509.RFC822Name):
                if entry not in sans:
                    continue
                subject_alt.append(x509.RFC822Name(entry))
            
            for entry in alt_names.value.get_values_for_type(x509.UniformResourceIdentifier):
                if entry not in sans:
                    continue
                subject_alt.append(x509.UniformResourceIdentifier(entry))
            
            try:
                # Add all alternates to certificate
                builder = builder.add_extension(x509.SubjectAlternativeName(subject_alt), critical=False)
            except Exception as err:
                raise Exception('Unable to set alternatives name: {e}'.format(e=err))

        try:
            # Register signing authority
            issuer_key_id = x509.SubjectKeyIdentifier.from_public_key(issuer_key.public_key())
            builder = builder.add_extension(x509.AuthorityKeyIdentifier(issuer_key_id.digest, [x509.DirectoryName(issuer_name)], issuer_serial), critical=False)
        except Exception as err:
            raise Exception('Unable to setup Authority Identifier: {e}'.format(e=err))

        ca_endpoints = list()
        try:
            # Default value if not set in profile
            ca_url = profile['ca'] if profile['ca'] else "https://certificates.{d}/certs/ca.crt".format(d=profile['domain'])
        except KeyError:
            ca_url = None
        try:
            # Default value if not set in profile
            ocsp_url = profile['ocsp'] if profile['ocsp'] else "https://certificates.{d}/ocsp".format(d=profile['domain'])
        except KeyError:
            ocsp_url = None

        try:
            # Add CA certificate distribution point and OCSP validation url
            if ca_url:
                ca_endpoints.append(x509.AccessDescription(x509.oid.AuthorityInformationAccessOID.OCSP,x509.UniformResourceIdentifier(ca_url)))
            if ocsp_url:
                ca_endpoints.append(x509.AccessDescription(x509.oid.AuthorityInformationAccessOID.OCSP,x509.UniformResourceIdentifier(ocsp_url)))
            builder = builder.add_extension(x509.AuthorityInformationAccess(ca_endpoints), critical=False)
        except Exception as err:
            raise Exception('Unable to setup OCSP/CA endpoint: {e}'.format(e=err))

        try:
            # Add CRL distribution point
            crl_endpoints = list()
            # Default value if not set in profile
            url = "https://certificates.{d}/certs/crl.pem".format(d=profile['domain'])
            try:
                if profile['csr']:
                    url = profile['csr']
            except KeyError:
                pass
            crl_endpoints.append(x509.DistributionPoint([x509.UniformResourceIdentifier(url)], None, None, [x509.DNSName(issuer_name.rfc4514_string())]))
            builder = builder.add_extension(x509.CRLDistributionPoints(crl_endpoints), critical=False)
        except Exception as err:
            raise Exception('Unable to setup CRL endpoints: {e}'.format(e=err))

        if digest is None:
            digest = profile['digest']

        if digest == 'md5':
            digest = hashes.MD5()
        elif digest == 'sha1':
            digest = hashes.SHA1()
        elif digest == 'sha256':
            digest = hashes.SHA256()
        elif digest == 'sha512':
            digest = hashed.SHA512()
        else:
            raise NotImplementedError('Private key only support {s} digest signatures'.format(s=self._allowed.Digest))

        try:
            pub_crt = builder.sign(private_key=issuer_key, algorithm=digest, backend=self.__backend)
        except Exception as err:
            raise Exception('Unable to sign certificate: {e}'.format(e=err))

        return pub_crt

    def load(self, raw, encoding='PEM'):
        """Load a Certificate and return a cryptography Certificate object
        """
        crt = None
        try:
            if encoding == 'PEM':
                crt = x509.load_pem_x509_certificate(raw, backend=self.__backend)
            elif encoding in ['DER','PFX','P12']:
                crt = x509.load_der_x509_certificate(raw, backend=self.__backend)
            else:
                raise NotImplementedError('Unsupported certificate encoding')
        except Exception as err:
            raise Exception(err)
        
        return crt

    def dump(self, crt, encoding='PEM'):
        """Export Certificate requests (CSR) in PEM mode
        """
        data = None

        if encoding == 'PEM':
            enc = serialization.Encoding.PEM
        elif encoding in ['DER','PFX','P12']:
            enc = serialization.Encoding.DER
        else:
            raise NotImplementedError('Unsupported public certificate encoding')

        try:
            data = crt.public_bytes(enc)
        except Exception as err:
            raise Exception(err)

        return data

    def parse(self, raw, encoding='PEM'):
        """Parse Certificate data (PEM default) and return dict with values
        """
        data = dict({})

        try:
            if encoding == 'PEM':
                crt = x509.load_pem_x509_certificate(raw, backend=self.__backend)
            elif encoding in ['DER','PFX','P12']:
                crt = x509.load_der_x509_certificate(raw, backend=self.__backend)
            else:
                raise NotImplementedError('Unsupported certificate encoding')
        except Exception as err:
            raise Exception(err)

        try:
            serial_number = "{0:x}".format(crt.serial_number)
        except Exception as err:
            raise Exception('Unable to parse serial number')
        
        try:
            data['version'] = crt.version
            data['fingerprint'] = crt.fingerprint(crt.signature_hash_algorithm)
            data['subject'] = crt.subject
            data['serial'] = serial_number
            data['issuer'] = crt.issuer
            data['not_before'] = crt.not_valid_before
            data['not_after']  = crt.not_valid_after
            data['signature'] = crt.signature
            data['bytes'] = crt.public_bytes(enc)
            data['constraints'] = crt.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS)
            data['keyUsage'] = crt.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE)
        except Exception as err:
            raise Exception(err)
        try:
            data['extendedKeyUsage'] = crt.extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE)
        except x509.ExtensionNotFound as err:
            pass
        except Exception as err:
            raise Exception(err)
        try:
            data['CRLDistribution'] = crt.extensions.get_extension_for_oid(ExtensionOID.CRL_DISTRIBUTION_POINTS)
        except x509.ExtensionNotFound as err:
            pass
        except Exception as err:
            raise Exception(err)
        try:
            data['OCSPNOcheck'] = crt.extensions.get_extension_for_oid(ExtensionOID.OCSP_NO_CHECK)
        except x509.ExtensionNotFound as err:
            pass
        except Exception as err:
            raise Exception(err)

        return data