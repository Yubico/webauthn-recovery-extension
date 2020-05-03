#!/usr/bin/env python3
# Prototype implementation of ARKG

import fastecdsa
import fastecdsa.keys
import hashlib
import os

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from fastecdsa import ecdsa
from fastecdsa.curve import P256
from fastecdsa.encoding.sec1 import SEC1Encoder


N = P256.q


def encode_pub(pubkey):
    return fastecdsa.keys.export_key(pubkey, encoder=SEC1Encoder)


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


class NoCredentialAvailable(Exception):
    pass


class InvalidMac(Exception):
    pass


def derive_pk(seed_pub, aux):
    def pack_cred(eph_pub, aux, mac_key):
        compressed_pubkey = encode_pub(eph_pub)

        full_mac = hmac(mac_key, compressed_pubkey + aux)
        mac = full_mac[0:16]

        return (eph_pub, aux, mac)

    eph_pri, eph_pub = fastecdsa.keys.gen_keypair(P256)

    ecdh_point = seed_pub * eph_pri
    ikm_x = fastecdsa.encoding.util.int_to_bytes(ecdh_point.x)
    okm = hkdf(ikm_x, length=64)
    cred_key = okm[0:32]
    cred_key_int = int.from_bytes(cred_key, 'big', signed=False)

    assert cred_key_int < N, "cred_key >= N: " + str(cred_key_int)

    mac_key = okm[32:64]

    cred_pub = (cred_key_int * P256.G) + seed_pub
    assert cred_pub != P256.G.IDENTITY_ELEMENT

    cred = pack_cred(eph_pub, aux, mac_key)
    return cred_pub, cred


def derive_sk(seed_pri, cred):
    eph_pub, aux, input_mac = cred
    eph_pub_enc = encode_pub(eph_pub)

    ecdh_point = seed_pri * eph_pub
    ikm_x = fastecdsa.encoding.util.int_to_bytes(ecdh_point.x)
    okm = hkdf(ikm_x, length=64)
    cred_key = okm[0:32]
    cred_key_int = int.from_bytes(cred_key, 'big', signed=False)

    mac_key = okm[32:64]
    full_mac = hmac(mac_key, eph_pub_enc + aux)
    mac = full_mac[0:16]

    if mac != input_mac:
        raise InvalidMac()

    assert cred_key_int < N, "cred_key >= N: " + str(cred_key_int)

    cred_pri = cred_key_int + seed_pri % N
    return cred_pri

class Authenticator:

    def __init__(self):
        self._seed_pri = None
        self._seed_pub = None
        self._imported_seeds = []
        self._credentials = {}

    def _initialize_recovery_seed(self):
        self._seed_pri, self._seed_pub = fastecdsa.keys.gen_keypair(P256)

    def make_credential(self, challenge):
        '''Abstraction of the basic WebAuthn registration operation.'''

        cred = os.urandom(32)
        pri, pub = fastecdsa.keys.gen_keypair(P256)
        self._credentials[cred] = pri
        sig = ecdsa.sign(
            challenge,
            pri,
            hashfunc=hashlib.sha256
        )
        return pub, cred, sig

    def get_assertion(self, challenge, creds):
        '''Abstraction of the basic WebAuthn authentication operation.'''

        for cred in creds:
            if cred in self._credentials:
                sig = ecdsa.sign(
                    challenge,
                    self._credentials[cred],
                    hashfunc=hashlib.sha256
                )
                return cred, sig

        raise NoCredentialAvailable()

    def export_recovery_seed(self):
        '''Export a backup seed public key for importing into another authenticator.'''

        if self._seed_pri is None:
            self._initialize_recovery_seed()

        return self._seed_pub

    def import_recovery_seed(self, S):
        '''Import a backup seed public key to derive backup keys from.'''

        self._imported_seeds.append(S)

    def derivepk_all(self, aux):
        '''Perform DerivePK with all imported seed public keys.'''
        return [
            derive_pk(seed, aux)
            for seed in self._imported_seeds]


    def make_credential_derivepk(self, challenge, aux):
        '''Create a credential keypair, derive all backup public keys,
        and sign the challenge and backup public keys with the credential private key.'''

        backup_creds = self.derivepk_all(aux)

        signed_data = challenge
        for cred in backup_creds:
            signed_data += encode_pub(cred[0])

        cred = os.urandom(32)
        pri, pub = fastecdsa.keys.gen_keypair(P256)
        self._credentials[cred] = pri
        sig = ecdsa.sign(
            signed_data,
            pri,
            hashfunc=hashlib.sha256
        )
        return pub, cred, sig, backup_creds

    def derivepk_all(self, aux):
        '''Perform DerivePK with all imported seed public keys.'''
        return [
            derive_pk(seed, aux)
            for seed in self._imported_seeds]

    def derivesk_find(self, creds):
        '''
        Find a cred in creds that matches this authenticator's backup seed private key,
        derive the private key and return it.
        '''
        for cred in creds:
            try:
                pri_key = derive_sk(self._seed_pri, cred)
                return cred, pri_key
            except InvalidMac:
                pass

        raise NoCredentialAvailable()


    def derivesk_authenticate(self, challenge, creds):
        '''
        Find a cred in creds that matches this authenticator's backup seed private key,
        derive the private key, and sign the challenge with it.
        '''
        chosen_cred, pri_key = self.derivesk_find(creds)
        sig = ecdsa.sign(
            challenge,
            pri_key,
            hashfunc=hashlib.sha256
        )
        return chosen_cred, sig


def verify_correctness():
    def separate_registration():
        primary_authnr = Authenticator()
        backup_authnr = Authenticator()

        # Create a credential with the primary authenticator
        challenge = os.urandom(32)
        pub, cred, sig = primary_authnr.make_credential(challenge)
        assert ecdsa.verify(sig, challenge, pub)
        standard_creds = [cred]

        # Authenticate with the primary authenticator
        challenge = os.urandom(32)
        cred, sig = primary_authnr.get_assertion(challenge, standard_creds)
        assert ecdsa.verify(sig, challenge, pub)
        assert cred in standard_creds

        # Transfer recovery seed from backup authenticator to primary
        primary_authnr.import_recovery_seed(backup_authnr.export_recovery_seed())

        # Create a backup public key with the primary authenticator
        aux = os.urandom(32)
        backup_creds = primary_authnr.derivepk_all(aux)
        backup_pub, backup_cred = backup_creds[0]

        # Perform recovery registration with backup authenticator
        challenge = os.urandom(32)
        chosen_cred, sig = backup_authnr.derivesk_authenticate(challenge, [backup_cred])
        assert ecdsa.verify(sig, challenge, backup_pub)
        assert chosen_cred == backup_cred
        assert chosen_cred[1] == aux


    def simultaneous_registration():
        primary_authnr = Authenticator()
        backup_authnr = Authenticator()

        # Transfer recovery seed from backup authenticator to primary
        primary_authnr.import_recovery_seed(backup_authnr.export_recovery_seed())

        # Create a credential and backup public key with the primary authenticator
        challenge = os.urandom(32)
        aux = os.urandom(32)
        pub, cred, sig, backup_creds = primary_authnr.make_credential_derivepk(challenge, aux)
        signed_data = challenge
        for c in backup_creds:
            signed_data += encode_pub(c[0])
        assert ecdsa.verify(sig, signed_data, pub)
        standard_creds = [cred]
        backup_pub, backup_cred = backup_creds[0]

        # Authenticate with the primary authenticator
        challenge = os.urandom(32)
        cred, sig = primary_authnr.get_assertion(challenge, standard_creds)
        assert ecdsa.verify(sig, challenge, pub)
        assert cred in standard_creds

        # Perform recovery registration with backup authenticator
        challenge = os.urandom(32)
        chosen_cred, sig = backup_authnr.derivesk_authenticate(challenge, [backup_cred])
        assert ecdsa.verify(sig, challenge, backup_pub)
        assert chosen_cred == backup_cred
        assert chosen_cred[1] == aux

    separate_registration()
    simultaneous_registration()


verify_correctness()
