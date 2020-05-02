#!/usr/bin/env python3

import sys
import os
import timeit
import fastecdsa.keys

from fastecdsa import ecdsa
from fastecdsa.encoding.der import DEREncoder
from fido2 import cbor, ctap2

from recovery_extension import Authenticator, cose_key_to_point


RP_ID = 'example.org'
ORIGIN = f'https://{RP_ID}'


def basic_make_credential(authenticator, clientDataJSON_hash):
    authenticator.authenticator_make_credential(cbor.encode({
        0x01: clientDataJSON_hash,
        0x02: {'id': RP_ID},
        0x06: {},
    }))


def basic_get_assertion(authenticator, clientDataJSON_hash, allowList):
    authenticator.authenticator_get_assertion(cbor.encode({
        0x01: RP_ID,
        0x02: clientDataJSON_hash,
        0x03: allowList,
        0x04: {},
    }))


def recovery_make_credential(authenticator, clientDataJSON_hash, recovery_allowCredentials):
    attObj_bytes = authenticator.authenticator_make_credential(cbor.encode({
        0x01: clientDataJSON_hash,
        0x02: {'id': RP_ID},
        0x06: {
            'recovery': {
                'action': 'recover',
                'allowCredentials': recovery_allowCredentials,
            },
        },
    }))
    return attObj_bytes


def generate_backups_get_assertion(authenticator, clientDataJSON_hash, allowList):
    authenticator_response = authenticator.authenticator_get_assertion(cbor.encode({
        0x01: RP_ID,
        0x02: clientDataJSON_hash,
        0x03: allowList,
        0x04: {
            'recovery': {
                'action': 'generate',
            }
        },
    }))
    return authenticator_response


def bench_basic_makecredential(iterations=100, repeats=10):
    iterations = int(iterations)

    clientDataJSON_hash = os.urandom(32)
    authnr = Authenticator()
    return iterations, repeats, timeit.repeat(
        stmt=lambda: basic_make_credential(authnr, clientDataJSON_hash),
        number=iterations,
        repeat=repeats,
    )


def bench_basic_getassertion(iterations=100, repeats=10):
    iterations = int(iterations)

    clientDataJSON_hash = os.urandom(32)
    authnr = Authenticator()
    basic_make_credential(authnr, clientDataJSON_hash)
    allowList = [{'type': 'public-key', 'id': i} for i in authnr._credentials.keys()]

    return iterations, repeats, timeit.repeat(
        stmt=lambda: basic_get_assertion(authnr, clientDataJSON_hash, allowList),
        number=iterations,
        repeat=repeats,
    )


def bench_recovery_makecredential(iterations=100, repeats=10, num_seeds=1):
    iterations = int(iterations)

    clientDataJSON_hash = os.urandom(32)
    primary_authnr = Authenticator()
    backup_authnr = Authenticator()
    basic_make_credential(primary_authnr, clientDataJSON_hash)
    allowList = [{'type': 'public-key', 'id': i} for i in primary_authnr._credentials.keys()]

    for i in range(num_seeds - 1):
        primary_authnr.import_recovery_seed(Authenticator().export_recovery_seed([0]))
    primary_authnr.import_recovery_seed(backup_authnr.export_recovery_seed([0]))

    recovery_allowCredentials = [
        {'id': ctap2.AttestedCredentialData(cred).credential_id, 'type': 'public-key'}
        for cred in ctap2.AuthenticatorData(
                cbor.decode(
                    generate_backups_get_assertion(primary_authnr, clientDataJSON_hash, allowList)
                )[2]
        ).extensions['recovery']['creds']
    ]

    return iterations, repeats, timeit.repeat(
        stmt=lambda: recovery_make_credential(backup_authnr, clientDataJSON_hash, recovery_allowCredentials),
        number=iterations,
        repeat=repeats,
    )


def bench_generate_backups_getassertion(iterations=100, repeats=10, num_seeds=1):
    iterations = int(iterations)

    clientDataJSON_hash = os.urandom(32)
    primary_authnr = Authenticator()
    basic_make_credential(primary_authnr, clientDataJSON_hash)
    allowList = [{'type': 'public-key', 'id': i} for i in primary_authnr._credentials.keys()]

    for i in range(num_seeds):
        primary_authnr.import_recovery_seed(Authenticator().export_recovery_seed([0]))

    return iterations, repeats, timeit.repeat(
        stmt=lambda: generate_backups_get_assertion(primary_authnr, clientDataJSON_hash, allowList),
        number=iterations,
        repeat=repeats,
    )


def verify_correctness():
    clientDataJSON_hash = os.urandom(32)
    primary_authnr = Authenticator()
    backup_authnr = Authenticator()

    # Create a credential with the primary authenticator
    basic_make_credential(primary_authnr, clientDataJSON_hash)
    allowList = [{'type': 'public-key', 'id': i} for i in primary_authnr._credentials.keys()]

    # Transfer recovery seed from backup authenticator to primary
    primary_authnr.import_recovery_seed(backup_authnr.export_recovery_seed([0]))

    # Generate a recovery credential with the primary authenticator
    recovery_creds = ctap2.AuthenticatorData(
        cbor.decode(
            generate_backups_get_assertion(primary_authnr, clientDataJSON_hash, allowList)
        )[2]
    ).extensions['recovery']['creds']
    recovery_pubkey = cose_key_to_point(
        ctap2.AttestedCredentialData(recovery_creds[0]).public_key
    )
    recovery_allowCredentials = [
        {'id': ctap2.AttestedCredentialData(cred).credential_id, 'type': 'public-key'}
        for cred in recovery_creds
    ]

    # Perform recovery registration with backup authenticator
    attObj_bytes = recovery_make_credential(backup_authnr, clientDataJSON_hash, recovery_allowCredentials)
    att_obj = ctap2.AttestationObject(attObj_bytes)

    # Verify that backup authenticator returns the correct recovery credential ID
    recovery_cred_id = att_obj.auth_data.extensions['recovery']['credId']
    assert recovery_cred_id == ctap2.AttestedCredentialData(recovery_creds[0]).credential_id

    # Verify that backup authenticator returns a valid recovery signature
    auth_data_without_extensions = att_obj.auth_data[:37 + len(att_obj.auth_data.credential_data)]
    recovery_sig = att_obj.auth_data.extensions['recovery']['sig']
    assert ecdsa.verify(
        DEREncoder.decode_signature(recovery_sig),
        auth_data_without_extensions + clientDataJSON_hash,
        recovery_pubkey
    )


def main(repeats=100):
    verify_correctness()

    iterations = 1

    def print_times(iterations_repeats_and_times):
        its, repeats, times = iterations_repeats_and_times
        its_tot = its * repeats
        time_tot = sum(times)
        min_avg = min(t / its for t in times)
        max_avg = max(t / its for t in times)
        print(f'Iterations:    {repeats}')
        print(f'Min:           {min_avg * 1000} ms/op')
        print(f'Average:       {time_tot * 1000 / its_tot} ms/op')
        print(f'Max:           {max_avg * 1000} ms/op')

    print('=== Benchmark: Normal credential registration ===')
    print_times(bench_basic_makecredential(iterations=iterations, repeats=repeats))

    print('\n')

    print('=== Benchmark: Normal authentication ===')
    print_times(bench_basic_getassertion(iterations=iterations, repeats=repeats))

    def bench_gen_auth(num_seeds):
        print('\n')
        print(f'=== Benchmark: Authentication with recovery credential generation ({num_seeds} seeds) ===')
        print_times(bench_generate_backups_getassertion(iterations=iterations, repeats=repeats, num_seeds=num_seeds))

    bench_gen_auth(0)
    bench_gen_auth(1)
    bench_gen_auth(2)
    bench_gen_auth(3)
    bench_gen_auth(4)
    bench_gen_auth(5)
    bench_gen_auth(10)

    def bench_rec_register(num_seeds):
        print('\n')
        print(f'=== Benchmark: Registration with recovery signature ({num_seeds} seeds) ===')
        print_times(bench_recovery_makecredential(iterations=iterations, repeats=repeats, num_seeds=num_seeds))

    bench_rec_register(0)
    bench_rec_register(1)
    bench_rec_register(2)
    bench_rec_register(3)
    bench_rec_register(4)
    bench_rec_register(5)
    bench_rec_register(10)


if __name__ == '__main__':
    if len(sys.argv) > 1:
        main(int(sys.argv[1]))
    else:
        main()
