#!/usr/bin/env python3
# Prototype implementation of https://gist.github.com/emlun/4c3efd99a727c7037fdb86ffd43c020d  # noqa: E501

import base64
import binascii
import datetime
import json
import secrets
import struct

from collections import namedtuple
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.x509.oid import NameOID
from fastecdsa.curve import P256
from fastecdsa.point import Point
from fido2 import cbor, cose, ctap2

BackupSeed = namedtuple('BackupSeed', ['alg', 'aaguid', 'pubkey'])


N = P256.q


def ecdh(pri_a, pub_b):
    return pri_a * pub_b


def fastecdsa_point_to_cryptography_pubkey(pub):
    return (
        ec.EllipticCurvePublicNumbers(pub.x, pub.y, ec.SECP256R1())
        .public_key(default_backend()))


def cryptography_to_point(pubkey):
    nums = pubkey.public_numbers()
    return Point(nums.x, nums.y, P256)


def encode_pub(pubkey):
    return pubkey.public_bytes(Encoding.X962, PublicFormat.CompressedPoint)


def sha256(data):
    hash = hashes.Hash(hashes.SHA256(), default_backend())
    hash.update(data)
    return hash.finalize()


def hmac(key, data):
    hmac = HMAC(key, hashes.SHA256(), default_backend())
    hmac.update(data)
    return hmac.finalize()


def hkdf(ikm, length=64):
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=None,
        info=None,
        backend=default_backend(),
    )
    return hkdf.derive(ikm)


def b64d(data):
    data_bytes = data.encode('utf-8') if isinstance(data, str) else data
    pad_length = (4 - (len(data_bytes) % 4)) % 4
    return base64.urlsafe_b64decode(data_bytes + (b'=' * pad_length))


def pack_attested_credential_data(aaguid, cred_id, cred_pub):
    cose_pubkey = cose.ES256.from_cryptography_key(cred_pub)
    cbor_pubkey = cbor.encode(cose_pubkey)
    return struct.pack(f'>16sH{len(cred_id)}s{len(cbor_pubkey)}s',
                       aaguid,
                       len(cred_id),
                       cred_id,
                       cbor_pubkey)


class InvalidState(Exception):
    pass


class NoCredentialAvailable(Exception):
    pass


class RpIdMismatch(Exception):
    pass


class UnknownAction(Exception):
    pass


class UnknownKeyAgreementScheme(Exception):
    pass


class Authenticator:

    def __init__(self):
        self._aaguid = binascii.a2b_hex('00112233445566778899aabbccddeeff')
        self._recovery_seed_pri_key = None
        self._seeds = []
        self._state = 0
        self._credentials = {}

        self._attestation_key = ec.generate_private_key(
            ec.SECP256R1(),
            default_backend())
        att_cert_subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, u'Yubico Test')
        ])
        attestation_cert = x509.CertificateBuilder().subject_name(
            att_cert_subject
        ).issuer_name(
            issuer
        ).public_key(
            self._attestation_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.utcnow()
        ).not_valid_after(
            datetime.datetime.utcnow() + datetime.timedelta(days=10)
        ).sign(self._attestation_key, hashes.SHA256(), default_backend())
        self.attestation_cert_der = attestation_cert.public_bytes(Encoding.DER)

    def _initialize_recovery_seed(self):
        self._recovery_seed_pri_key = ec.generate_private_key(
            ec.SECP256R1(),
            default_backend())

    def export_recovery_seed(self, allow_algs):
        for alg in allow_algs:
            if alg == 0:
                if self._recovery_seed_pri_key is None:
                    self._initialize_recovery_seed()

                S = self._recovery_seed_pri_key.public_key()
                S_enc = encode_pub(S)

                signed_data = struct.pack('>B16s33s', alg, self._aaguid, S_enc)
                sig = self._attestation_key.sign(
                    signed_data,
                    ec.ECDSA(hashes.SHA256()))
                payload = {
                    1: alg,
                    2: [self.attestation_cert_der],
                    3: self._aaguid,
                    4: sig,
                    -1: S_enc,
                }
                return cbor.encode(payload)

        raise UnknownKeyAgreementScheme(allow_algs)

    def import_recovery_seed(self, exported_seed):
        payload = cbor.decode(exported_seed)
        alg = payload[1]
        attestation_cert_bytes = payload[2][0]
        aaguid = payload[3]
        sig = payload[4]

        assert isinstance(alg, int)
        assert isinstance(attestation_cert_bytes, bytes)
        assert isinstance(aaguid, bytes)
        assert isinstance(sig, bytes)

        if alg == 0:
            S_enc = payload[-1]
            assert isinstance(S_enc, bytes)
            S = ec.EllipticCurvePublicKey.from_encoded_point(
                ec.SECP256R1(),
                S_enc)

            attestation_cert = x509.load_der_x509_certificate(
                attestation_cert_bytes,
                default_backend())
            signed_data = struct.pack('>B16s33s', alg, aaguid, S_enc)
            attestation_cert.public_key().verify(
                sig,
                signed_data,
                ec.ECDSA(hashes.SHA256()))

            self._seeds.append(BackupSeed(alg, aaguid, S))

        else:
            raise UnknownKeyAgreementScheme(alg)

        self._state += 1

    def authenticator_make_credential(self, args_cbor):
        args = cbor.decode(args_cbor)
        clientDataJSON_hash = args[0x01]
        rp_id = args[0x02]['id']
        extension_inputs = args[0x06]
        rp_id_hash = sha256(rp_id.encode('utf-8'))
        flags = 0b11000001  # ED, AT, UP
        sign_count = 0

        credential_id = secrets.token_bytes(32)
        credential_private_key = ec.generate_private_key(
            ec.SECP256R1(),
            default_backend()
        )

        self._credentials[credential_id] = credential_private_key

        attested_cred_data = pack_attested_credential_data(
            self._aaguid,
            credential_id,
            credential_private_key.public_key(),
        )

        authData_without_extensions = struct.pack(
            f'>32sBL{len(attested_cred_data)}s',
            rp_id_hash,
            flags,
            sign_count,
            attested_cred_data,
        )

        extensions = {}

        if "recovery" in extension_inputs:
            extensions["recovery"] = self.process_recovery_extension(
                rp_id,
                authData_without_extensions,
                clientDataJSON_hash,
                extension_inputs["recovery"],
            )

        authData = authData_without_extensions + cbor.encode(extensions)
        attStmt = {
            0x01: 'packed',
            0x02: authData,
            0x03: {
                'alg': -7,
                'sig': self._attestation_key.sign(authData + clientDataJSON_hash, ec.ECDSA(hashes.SHA256())),
                'x5c': [self.attestation_cert_der]
            },
        }
        return cbor.encode(attStmt)

    def authenticator_get_assertion(self, args_cbor):
        args = cbor.decode(args_cbor)
        rp_id = args[0x01]
        clientDataJSON_hash = args[0x02]
        extension_inputs = args[0x04]
        rp_id_hash = sha256(rp_id.encode('utf-8'))
        flags = 0b10000001  # ED, UP
        sign_count = 0

        extensions = {}

        authData_without_extensions = struct.pack(
            f'>32sBL',
            rp_id_hash,
            flags,
            sign_count,
        )

        if "recovery" in extension_inputs:
            extensions["recovery"] = self.process_recovery_extension(
                rp_id,
                authData_without_extensions,
                clientDataJSON_hash,
                extension_inputs["recovery"]
            )

        authData = authData_without_extensions + cbor.encode(extensions)

        sig = None
        for cred_descriptor in args[0x03]:
            if cred_descriptor['id'] in self._credentials:
                sig = self._credentials[cred_descriptor['id']].sign(
                    authData + clientDataJSON_hash,
                    ec.ECDSA(hashes.SHA256()))
                break
        if sig is None:
            raise NoCredentialAvailable()

        return cbor.encode({
            0x02: authData,
            0x03: sig,
        })

    def process_recovery_extension(
            self,
            rp_id,
            authData_without_extensions,
            clientDataHash,
            extension_input,
    ):
        action = extension_input['action']
        if action == 'state':
            return self._get_state_counter()
        elif action == 'generate':
            return self._generate_backup_credentials(rp_id)
        elif action == 'recover':
            return self._generate_recovery_signature(
                rp_id,
                authData_without_extensions,
                clientDataHash,
                extension_input['allowCredentials']
            )
        else:
            return UnknownAction()

    def _get_state_counter(self):
        return {
            'action': 'state',
            'state': self._state,
        }

    def _generate_backup_credentials(self, rp_id):
        creds = [self._generate_backup_credential(seed, rp_id)
                 for seed in self._seeds]
        ext_output = {
            'action': 'generate',
            'state': self._state,
            'creds': creds,
        }
        return ext_output

    def _generate_backup_credential(self, backup_seed, rp_id):
        if backup_seed.alg != 0:
            raise UnknownKeyAgreementScheme(backup_seed.alg)

        def pack_cred_id(eph_pub, rp_id, mac_key):
            compressed_pubkey = encode_pub(eph_pub)
            rp_id_hash = sha256(rp_id.encode('utf-8'))

            full_mac = hmac(mac_key,
                            struct.pack('>B33s32s',
                                        backup_seed.alg,
                                        compressed_pubkey,
                                        rp_id_hash))
            mac = full_mac[0:16]

            return struct.pack('>B33s16s',
                               backup_seed.alg,
                               compressed_pubkey,
                               mac)

        seed_pub = backup_seed.pubkey
        eph_pri = ec.generate_private_key(ec.SECP256R1(), default_backend())
        eph_pub = eph_pri.public_key()

        ikm = eph_pri.exchange(ec.ECDH(), seed_pub)
        okm = hkdf(ikm, length=64)
        cred_key = okm[0:32]
        cred_key_int = int.from_bytes(cred_key, 'big', signed=False)

        assert cred_key_int < N, "cred_key >= N: " + str(cred_key_int)

        mac_key = okm[32:64]

        seed_pub_point = cryptography_to_point(seed_pub)
        cred_pub_point = (cred_key_int * P256.G) + seed_pub_point
        assert cred_pub_point != P256.G.IDENTITY_ELEMENT

        cred_pub = fastecdsa_point_to_cryptography_pubkey(cred_pub_point)
        cred_id = pack_cred_id(eph_pub, rp_id, mac_key)
        cred_data = pack_attested_credential_data(backup_seed.aaguid, cred_id, cred_pub)
        return cred_data

    def _generate_recovery_signature(
            self,
            rp_id,
            authData_without_extensions,
            clientDataHash,
            allow_credentials,
    ):
        if self._recovery_seed_pri_key is None:
            return InvalidState()

        for cred in allow_credentials:
            cred_id = cred['id']
            alg = cred_id[0]

            if alg == 0:
                try:
                    cred_pri = self._derive_private_key(
                        self._recovery_seed_pri_key,
                        cred_id, rp_id)
                    sig = cred_pri.sign(
                        authData_without_extensions + clientDataHash,
                        ec.ECDSA(hashes.SHA256()))
                except RpIdMismatch:
                    continue
            else:
                continue

            extension_output = {
                'action': 'recover',
                'credId': cred_id,
                'sig': sig,
                'state': self._state,
            }
            return extension_output

        raise NoCredentialAvailable()

    def _derive_private_key(self, seed_pri, cred_id, rp_id):
        alg = cred_id[0]
        if alg != 0:
            raise UnknownKeyAgreementScheme(alg)

        eth_pub = ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256R1(),
            cred_id[1:-16])
        ikm = seed_pri.exchange(ec.ECDH(), eth_pub)
        okm = hkdf(ikm, length=64)
        cred_key = okm[0:32]
        cred_key_int = int.from_bytes(cred_key, 'big', signed=False)

        mac_key = okm[32:64]
        full_mac = hmac(mac_key,
                        struct.pack('>B33s32s',
                                    alg,
                                    encode_pub(eth_pub),
                                    sha256(rp_id.encode('utf-8'))))
        mac = full_mac[0:16]

        recon_cred_id = struct.pack('>B33s16s', alg, encode_pub(eth_pub), mac)
        if cred_id != recon_cred_id:
            raise RpIdMismatch()

        assert cred_key_int < N, "cred_key >= N: " + str(cred_key_int)

        mac_key = okm[32:64]

        cred_pri = ec.derive_private_key(
            (cred_key_int + seed_pri.private_numbers().private_value) % N,
            ec.SECP256R1(),
            default_backend())
        return cred_pri


class RelyingParty:

    def __init__(self):
        self._recovery_credentials = {}

    def get_recovery_cred_descriptors(self):
        return [
            {'type': 'public-key', 'id': id}
            for id in self._recovery_credentials.keys()
            ]

    def makecredential_process_recovery_extension(
            self,
            authData,
            clientDataHash,
            extension_output,
    ):
        action = extension_output['action']

        if action == 'state':
            pass
        elif action == 'recover':
            authData_without_extensions = authData
            self._recovery_credentials[
                extension_output['credId']
            ].public_key.verify(
                authData_without_extensions + clientDataHash,
                extension_output['sig']
            )
        else:
            raise UnknownAction()

    def getassertion_process_recovery_extension(self, extension_output):
        action = extension_output['action']

        if action == 'state':
            pass
        elif action == 'generate':
            backup_cred_data = extension_output['creds']
            self._recovery_credentials.update({
                cred.credential_id: cred
                for cred in
                (ctap2.AttestedCredentialData(cd) for cd in backup_cred_data)
            })
        else:
            raise UnknownAction()


def ctap2_to_webauthn_attestation_object(attObj_cbor):
    attObj = cbor.decode(attObj_cbor)
    return cbor.encode({
        'fmt': attObj[0x01],
        'authData': attObj[0x02],
        'attStmt': attObj[0x03],
    })


def create_credential(authenticator, request_json):
    request = json.loads(request_json)
    pkcco = request['publicKeyCredentialCreationOptions']
    collectedClientData = {
        'type': 'webauthn.create',
        'challenge': pkcco['challenge'],
        'origin': 'https://localhost:8443',
    }
    clientDataJSON = json.dumps(collectedClientData, indent=None).encode('utf-8')
    clientDataJSON_hash = sha256(clientDataJSON)

    if 'extensions' in pkcco and 'recovery' in pkcco['extensions'] and 'allowCredentials' in pkcco['extensions']['recovery']:
        for cred in pkcco['extensions']['recovery']['allowCredentials']:
            cred['id'] = b64d(cred['id'])

    attObj_bytes = authenticator.authenticator_make_credential(cbor.encode({
        0x01: clientDataJSON_hash,
        0x02: pkcco['rp'],
        0x06: pkcco['extensions'],
    }))
    attObj = ctap2.AttestationObject(attObj_bytes)
    credential_id = attObj.auth_data.credential_data.credential_id
    credential = {
        'type': 'public-key',
        'id': base64.urlsafe_b64encode(credential_id).decode('utf-8'),
        'response': {
            'attestationObject': base64.urlsafe_b64encode(ctap2_to_webauthn_attestation_object(attObj_bytes)).decode('utf-8'),
            'clientDataJSON': base64.urlsafe_b64encode(clientDataJSON).decode('utf-8'),
        },
        'clientExtensionResults': {},
    }
    print(json.dumps(credential, indent=2))


def get_assertion(authenticator, request_json):
    request = json.loads(request_json)
    pkcro = request['publicKeyCredentialRequestOptions']
    collectedClientData = {
        'type': 'webauthn.get',
        'challenge': pkcro['challenge'],
        'origin': 'https://localhost:8443',
    }
    clientDataJSON = json.dumps(collectedClientData, indent=None).encode('utf-8')
    clientDataJSON_hash = sha256(clientDataJSON)
    authenticator_response = cbor.decode(authenticator.authenticator_get_assertion(cbor.encode({
        0x01: pkcro['rpId'],
        0x02: clientDataJSON_hash,
        0x04: pkcro['extensions'],
    })))
    authenticatorData = authenticator_response[0x02]
    sig = authenticator_response[0x03]
    credential = {
        'type': 'public-key',
        'id': base64.urlsafe_b64encode(authenticator._credential_id).decode('utf-8'),
        'response': {
            'authenticatorData': base64.urlsafe_b64encode(authenticatorData).decode('utf-8'),
            'clientDataJSON': base64.urlsafe_b64encode(clientDataJSON).decode('utf-8'),
            'signature': base64.urlsafe_b64encode(sig).decode('utf-8'),
        },
        'clientExtensionResults': {},
    }
    print(json.dumps(credential, indent=2))


if __name__ == '__main__':
    main_authnr = Authenticator()
    backup_authnr = Authenticator()
    rp = RelyingParty()

    main_authnr.import_recovery_seed(
        backup_authnr.export_recovery_seed([0]))

    gen_ext_output = main_authnr.process_recovery_extension(
        'yubico.com',
        b'',
        b'',
        {'action': 'generate'})
    rp.getassertion_process_recovery_extension(gen_ext_output)

    authData = b'Hej hej'
    clientDataHash = sha256(b'Herp le derp')
    recover_ext_output = backup_authnr.process_recovery_extension(
        'yubico.com',
        authData,
        clientDataHash,
        {
            'action': 'recover',
            'allowCredentials': rp.get_recovery_cred_descriptors(),
        })
    rp.makecredential_process_recovery_extension(
        authData,
        clientDataHash,
        recover_ext_output)
