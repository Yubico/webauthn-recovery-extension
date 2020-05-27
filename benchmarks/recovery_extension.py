#!/usr/bin/env python3
# Prototype implementation of https://gist.github.com/emlun/4c3efd99a727c7037fdb86ffd43c020d  # noqa: E501

import base64
import binascii
import datetime
import fastecdsa
import hashlib
import fastecdsa.keys
import json
import secrets
import struct

from collections import namedtuple
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from fastecdsa import ecdsa
from fastecdsa.curve import P256
from fastecdsa.encoding.der import DEREncoder
from fastecdsa.encoding.sec1 import SEC1Encoder
from fastecdsa.point import Point
from fido2 import cbor, cose, ctap2

BackupSeed = namedtuple('BackupSeed', ['alg', 'aaguid', 'pubkey'])


N = P256.q


def encode_pub(pubkey):
    return SEC1Encoder().encode_public_key(pubkey, compressed=False)


def sha256(data):
    hash = hashes.Hash(hashes.SHA256(), default_backend())
    hash.update(data)
    return hash.finalize()


def hmac(key, data):
    hmac = HMAC(key, hashes.SHA256(), default_backend())
    hmac.update(data)
    return hmac.finalize()


def hkdf(ikm, info, length=32):
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=None,
        info=info,
        backend=default_backend(),
    )
    return hkdf.derive(ikm)


def b64d(data):
    data_bytes = data.encode('utf-8') if isinstance(data, str) else data
    pad_length = (4 - (len(data_bytes) % 4)) % 4
    return base64.urlsafe_b64decode(data_bytes + (b'=' * pad_length))


def point_to_cose_key(point):
    return {
        1: 2,
        3: -7,
        -1: 1,
        -2: fastecdsa.encoding.util.int_to_bytes(point.x),
        -3: fastecdsa.encoding.util.int_to_bytes(point.y),
    }


def cose_key_to_point(cose):
    return SEC1Encoder.decode_public_key(
        b'\x04' + cose[-2] + cose[-3],
        P256
    )


def pack_attested_credential_data(aaguid, cred_id, cred_pub):
    cose_pubkey = point_to_cose_key(cred_pub)
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

        self._attestation_key = fastecdsa.keys.gen_private_key(P256)

    def _initialize_recovery_seed(self):
        self._recovery_seed_pri_key = fastecdsa.keys.gen_private_key(P256)

    def export_recovery_seed(self, allow_algs):
        for alg in allow_algs:
            if alg == 0:
                if self._recovery_seed_pri_key is None:
                    self._initialize_recovery_seed()

                S = fastecdsa.keys.get_public_key(self._recovery_seed_pri_key, P256)
                S_enc = encode_pub(S)

                signed_data = struct.pack('>B16s65s', alg, self._aaguid, S_enc)
                sig = DEREncoder.encode_signature(
                    *ecdsa.sign(
                        signed_data,
                        self._attestation_key,
                        hashfunc=hashlib.sha256
                    )
                )
                payload = {
                    1: alg,
                    2: [],
                    3: self._aaguid,
                    4: sig,
                    -1: S_enc,
                }
                return cbor.encode(payload)

        raise UnknownKeyAgreementScheme(allow_algs)

    def import_recovery_seed(self, exported_seed):
        payload = cbor.decode(exported_seed)
        alg = payload[1]
        aaguid = payload[3]
        sig = payload[4]

        assert isinstance(alg, int)
        assert isinstance(aaguid, bytes)
        assert isinstance(sig, bytes)

        if alg == 0:
            S_enc = payload[-1]
            assert isinstance(S_enc, bytes)
            S = SEC1Encoder().decode_public_key(S_enc, P256)

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
        (credential_private_key, credential_public_key) = fastecdsa.keys.gen_keypair(P256)

        self._credentials[credential_id] = credential_private_key

        attested_cred_data = pack_attested_credential_data(
            self._aaguid,
            credential_id,
            credential_public_key,
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
                'sig': DEREncoder.encode_signature(
                    *ecdsa.sign(
                        authData + clientDataJSON_hash,
                        self._attestation_key,
                        hashfunc=hashlib.sha256
                    )
                ),
                'x5c': []
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
                sig = DEREncoder.encode_signature(
                    *ecdsa.sign(
                        authData + clientDataJSON_hash,
                        self._credentials[cred_descriptor['id']],
                        hashfunc=hashlib.sha256
                    )
                )
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
            uncompressed_pubkey = encode_pub(eph_pub)
            rp_id_hash = sha256(rp_id.encode('utf-8'))

            full_mac = hmac(mac_key,
                            struct.pack('>B65s32s',
                                        backup_seed.alg,
                                        uncompressed_pubkey,
                                        rp_id_hash))
            mac = full_mac[0:16]

            return struct.pack('>B65s16s',
                               backup_seed.alg,
                               uncompressed_pubkey,
                               mac)

        seed_pub = backup_seed.pubkey
        eph_pri, eph_pub = fastecdsa.keys.gen_keypair(P256)

        ecdh_point = seed_pub * eph_pri
        ikm_x = fastecdsa.encoding.util.int_to_bytes(ecdh_point.x)
        cred_key = hkdf(ikm_x, "webauthn.recovery.cred_key".encode('utf-8'), length=32)
        cred_key_int = int.from_bytes(cred_key, 'big', signed=False)

        assert cred_key_int < N, "cred_key >= N: " + str(cred_key_int)

        mac_key = hkdf(ikm_x, "webauthn.recovery.mac_key".encode('utf-8'), length=32)

        cred_pub = (cred_key_int * P256.G) + seed_pub
        assert cred_pub != P256.G.IDENTITY_ELEMENT

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
                    sig = DEREncoder.encode_signature(
                        *ecdsa.sign(
                            authData_without_extensions + clientDataHash,
                            cred_pri,
                            hashfunc=hashlib.sha256
                        )
                    )
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

        eph_pub_enc = cred_id[1:][:65]
        eph_pub = SEC1Encoder.decode_public_key(eph_pub_enc, P256)

        ecdh_point = seed_pri * eph_pub
        ikm_x = fastecdsa.encoding.util.int_to_bytes(ecdh_point.x)
        cred_key = hkdf(ikm_x, binascii.a2b_hex('776562617574686e2e7265636f766572792e637265645f6b6579'), length=32)
        cred_key_int = int.from_bytes(cred_key, 'big', signed=False)

        mac_key = hkdf(ikm_x, binascii.a2b_hex('776562617574686e2e7265636f766572792e6d61635f6b6579'), length=32)
        full_mac = hmac(mac_key,
                        struct.pack('>B65s32s',
                                    alg,
                                    eph_pub_enc,
                                    sha256(rp_id.encode('utf-8'))))
        mac = full_mac[0:16]

        recon_cred_id = struct.pack('>B65s16s', alg, eph_pub_enc, mac)
        if cred_id != recon_cred_id:
            raise RpIdMismatch()

        assert cred_key_int < N, "cred_key >= N: " + str(cred_key_int)

        cred_pri = cred_key_int + seed_pri % N
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
            pubkey_cose = self._recovery_credentials[
                extension_output['credId']
            ].public_key
            pubkey = cose_key_to_point(pubkey_cose)
            assert ecdsa.verify(
                DEREncoder.decode_signature(extension_output['sig']),
                authData_without_extensions + clientDataHash,
                pubkey,
                hashfunc=hashlib.sha256
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
