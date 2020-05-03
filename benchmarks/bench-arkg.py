#!/usr/bin/env python3

import sys
import os
import timeit
import fastecdsa.keys

from fastecdsa import ecdsa
from fastecdsa.encoding.der import DEREncoder
from fido2 import cbor, ctap2

from arkg import Authenticator, encode_pub, verify_correctness


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

    challenge = os.urandom(32)
    authnr = Authenticator()
    return iterations, repeats, timeit.repeat(
        stmt=lambda: authnr.make_credential(challenge),
        number=iterations,
        repeat=repeats,
    )


def bench_basic_getassertion(iterations=100, repeats=10):
    iterations = int(iterations)

    challenge = os.urandom(32)
    authnr = Authenticator()

    pub, cred, sig = authnr.make_credential(challenge)
    assert ecdsa.verify(sig, challenge, pub)
    creds = [cred]

    return iterations, repeats, timeit.repeat(
        stmt=lambda: authnr.get_assertion(challenge, creds),
        number=iterations,
        repeat=repeats,
    )


def bench_derivepk_all(iterations=100, repeats=10, num_seeds=1):
    iterations = int(iterations)

    primary_authnr = Authenticator()
    for i in range(num_seeds):
        primary_authnr.import_recovery_seed(Authenticator().export_recovery_seed())

    aux = os.urandom(32)
    return iterations, repeats, timeit.repeat(
        stmt=lambda: primary_authnr.derivepk_all(aux),
        number=iterations,
        repeat=repeats,
    )


def bench_makecredential_derivepk(iterations=100, repeats=10, num_seeds=1):
    iterations = int(iterations)

    primary_authnr = Authenticator()
    for i in range(num_seeds):
        primary_authnr.import_recovery_seed(Authenticator().export_recovery_seed())

    challenge = os.urandom(32)
    aux = os.urandom(32)
    return iterations, repeats, timeit.repeat(
        stmt=lambda: primary_authnr.make_credential_derivepk(challenge, aux),
        number=iterations,
        repeat=repeats,
    )


def bench_derivesk_find(iterations=100, repeats=10, num_seeds=1):
    iterations = int(iterations)

    primary_authnr = Authenticator()
    for i in range(num_seeds - 1):
        primary_authnr.import_recovery_seed(Authenticator().export_recovery_seed())

    backup_authnr = Authenticator()
    if num_seeds > 0:
        primary_authnr.import_recovery_seed(backup_authnr.export_recovery_seed())

    aux = os.urandom(32)
    creds = primary_authnr.derivepk_all(aux)

    derivesk_creds = [cred[1] for cred in creds]

    return iterations, repeats, timeit.repeat(
        stmt=lambda: backup_authnr.derivesk_find(derivesk_creds),
        number=iterations,
        repeat=repeats,
    )


def bench_derivesk_authenticate(iterations=100, repeats=10, num_seeds=1):
    iterations = int(iterations)

    primary_authnr = Authenticator()
    for i in range(num_seeds - 1):
        primary_authnr.import_recovery_seed(Authenticator().export_recovery_seed())

    backup_authnr = Authenticator()
    if num_seeds > 0:
        primary_authnr.import_recovery_seed(backup_authnr.export_recovery_seed())

    aux = os.urandom(32)
    creds = primary_authnr.derivepk_all(aux)

    challenge = os.urandom(32)
    derivesk_creds = [cred[1] for cred in creds]

    return iterations, repeats, timeit.repeat(
        stmt=lambda: backup_authnr.derivesk_authenticate(challenge, derivesk_creds),
        number=iterations,
        repeat=repeats,
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

    def bench_dpka(num_seeds):
        print('\n')
        print(f'=== Benchmark: DerivePK ({num_seeds} seeds) ===')
        print_times(bench_derivepk_all(iterations=iterations, repeats=repeats, num_seeds=num_seeds))

    for num in [0, 1, 2, 5, 10]:
        bench_dpka(num)

    def bench_mcdpk(num_seeds):
        print('\n')
        print(f'=== Benchmark: Make credential, DerivePK, and sign ({num_seeds} seeds) ===')
        print_times(bench_makecredential_derivepk(iterations=iterations, repeats=repeats, num_seeds=num_seeds))

    for num in [0, 1, 2, 5, 10]:
        bench_mcdpk(num)


    print('\n')

    print('=== Benchmark: Normal authentication ===')
    print_times(bench_basic_getassertion(iterations=iterations, repeats=repeats))

    def bench_dskf(num_seeds):
        print('\n')
        print(f'=== Benchmark: DeriveSK ({num_seeds} seeds) ===')
        print_times(bench_derivesk_find(iterations=iterations, repeats=repeats, num_seeds=num_seeds))

    for num in [1, 2, 5, 10]:
        bench_dskf(num)

    def bench_dska(num_seeds):
        print('\n')
        print(f'=== Benchmark: DeriveSK and authenticate ({num_seeds} seeds) ===')
        print_times(bench_derivesk_authenticate(iterations=iterations, repeats=repeats, num_seeds=num_seeds))

    for num in [1, 2, 5, 10]:
        bench_dska(num)


if __name__ == '__main__':
    if len(sys.argv) > 1:
        main(int(sys.argv[1]))
    else:
        main()
