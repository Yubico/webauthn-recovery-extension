# Runtime benchmarks

This directory contains some runtime benchmarks for the authenticator parts of the recovery extension.

The benchmarks are implemented in single-threaded Python,
using the [fastecdsa][fastecdsa] library for all elliptic curve arithmetic and cryptography.

To run the benchmark on the software implementation, just run [tox][tox]:

```
$ tox
```

You can also specify the number of iterations to run per benchmark (default is 100):

```
$ tox -- 10
```

There is also a benchmark running the standard authenticatorGetAssertion
against a connected CTAP2 authenticator. To run it, invoke tox as:

```
$ tox -e yubikey
```

This can also take an additional argument specifying the number of iterations:

```
$ tox -e yubikey -- 100
```


[fastecdsa]: https://pypi.org/project/fastecdsa/
[tox]: https://tox.readthedocs.io/
