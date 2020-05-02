#!/usr/bin/env python3

import os
import sys
import timeit

from fido2.ctap2 import CTAP2
from fido2.hid import CtapHidDevice


RP_ID = 'example.org'
ORIGIN = f'https://{RP_ID}'
USER_ID = os.urandom(32)


def create_ctap2_handle():
    for dev in CtapHidDevice.list_devices():
        return CTAP2(dev)
    print("No FIDO device found")


def make_credential(ctap2: CTAP2, clientDataJSON_hash):
    att_obj = ctap2.make_credential(
        clientDataJSON_hash,
        {'id': RP_ID, 'name': 'Test RP'},
        {'id': USER_ID, 'name': 'test@example.org', 'displayName': 'Test'},
        [{'alg': -7, 'type': 'public-key'}],
    )

    return {'id': att_obj.auth_data.credential_data.credential_id, 'type': 'public-key'}


def get_assertion(ctap2: CTAP2, clientDataJSON_hash, allowList):
    return ctap2.get_assertions(
        RP_ID,
        clientDataJSON_hash,
        allowList,
        options={'up': False},
    )


def main(repeats=10):
    ctap2 = create_ctap2_handle()

    print("Please touch the authenticator to begin the benchmark...")
    clientDataJSON_hash = os.urandom(32)
    allowList = [make_credential(ctap2, clientDataJSON_hash)]

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

    print('=== Benchmark: Authentication with YubiKey ===')
    times = timeit.repeat(
        stmt=lambda: get_assertion(ctap2, clientDataJSON_hash, allowList),
        number=iterations,
        repeat=repeats,
    )
    print_times((iterations, repeats, times))


if __name__ == '__main__':
    if len(sys.argv) > 1:
        main(int(sys.argv[1]))
    else:
        main()
