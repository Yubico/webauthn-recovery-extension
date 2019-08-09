# Introduction

Web Authentication solves many problems in secure online authentication, but
also introduces some new challenges. One of the greatest challenges is loss of
an authenticator - what can the user do so that they isn't locked out of their
account if they lose an authenticator?

The current workaround to this problem is to have the user register more than
one authenticator, for example a roaming USB authenticator and a platform
authenticator integrated into a smartphone. That way the user can still use the
other authenticator to log in if they lose one of the two.

However, this approach has drawbacks. What we would like to enable is for the
user to have a separate _backup authenticator_ which they could leave in a safe
place and not keep with them day-to-day. This is not really feasible with the
aforementioned workaround, since the user would have to register the backup
authenticator with each new RP where they register their daily-use
authenticator. This effectively means that the user must keep the backup
authenticator with them, or in an easily accessible location, to not risk
forgetting to register the backup authenticator, which largely defeats the
purpose of the backup authenticator.

Under the restriction that we don't want to share any secrets or private keys
between authenticators, one simple way to solve this would be to import a public
key from the backup authenticator to the main authenticator, so that the main
authenticator can also register that public key with each RP. Then the backup
authenticator can later prove possession of the private key and recover access
to the account. This has a big drawback, however: a static public key would be
easily correlatable between RPs or accounts, undermining much of the privacy
protections in WebAuthn.

In this document we propose a key agreement scheme which allows a pair of
authenticators to agree on an EC key pair in such a way the main authenticator
can generate nondeterministic public keys, but only the backup authenticator can
derive the corresponding private keys. We present the scheme in the context of a
practical application as a WebAuthn extension for account recovery. This enables
the use case of placing the backup authenticator in a bank vault, for example,
while retaining WebAuthn's privacy protection of non-correlatable public keys.


# The key agreement scheme

The scheme has three participants:

- Bob, corresponding to the "backup" authenticator.
- Mary, corresponding to the "main" authenticator.
- Robin, corresponding to the WebAuthn Relying Party (RP).

The goal is that Mary will generate public keys for Robin to store. At a later
time, Bob will request the public keys from Robin and derive the corresponding
private keys without further communication with Mary.

The scheme is divided into three stages ordered in this forward sequence:

- In stage 1, Mary and Bob may communicate to perform some initial setup. Robin
  may not communicate with Mary or Bob.

  ```
  Mary <-> Bob



  Robin
  ```

- In stage 2, only Mary and Robin may communicate.

  ```
  Mary     Bob
   ^
   |
   v
  Robin
  ```

- In stage 3, only Bob and Robin may communicate.

  ```
  Mary     Bob
            ^
            |
            |
  Robin <---+
  ```


## Stage 1: Setup

This procedure is performed once to set up the parameters for the key agreement
scheme.

 1. Bob generates a new P-256 EC key pair with private key `s` and public key
    `S`.
 2. Bob sends `S` to Mary.
 3. Robin chooses a unique public identifier `rp_id`.


## Stage 2: Public key creation

The following steps are performed by Mary.

 1. Generate an ephemeral EC P-256 key pair: `e`, `E`.

 2. Use `HKDF(ECDH(e, S))` to derive `cred_key`, `mac_key` (both 32 byte
    keys).

 3. If `cred_key >= n`, where `n` is the order of the P-256 curve, start
    over from 1.

 4. Calculate `P = (cred_key * G) + S`, where * and + are EC point
    multiplication and addition, and `G` is the generator of the P-256 curve.

 5. If `P` is the point at infinity, start over from 1.

 6. Let `credential_id = E || LEFT(HMAC(mac_key, E || rp_id), 16)`,
    where `LEFT(X, n)` is the first `n` bytes of the byte array `X`.

 7. Send the pair `(P, credential_id)` to Robin for storage.


## Stage 3: Private key derivation

The following steps are performed by Bob.

 1. Retrieve a set of `credential_id`s from Robin. Perform the following steps
    for each `credential_id`.

 2. Let `E = DROP_RIGHT(credential_id, 16)`, where `DROP_RIGHT(X, n)` is the
    byte array `X` without the last `n` bytes.

 3. Use `HKDF(ECDH(s, E))` to derive `cred_key`, `mac_key`.

 4. Verify that `credential_id == E || LEFT(HMAC(mac_key, E || rp_id), 16)`. If
    not, this `credential_id` was generated for a different backup authenticator
    than Bob or a different relying party than Robin, and is not processed
    further.

 5. Calculate `p = cred_key + s mod n`,
    where `n` is the order of the P-256 curve.

 6. The private key is `p`, which Bob can now use to create a signature.

As a result of these procedures, Bob will have derived `p` such that

    p * G = (cred_key + s) *   G =
          = cred_key * G + s * G =
          = cred_key * G +     S = P.


# Application: WebAuthn extension

This section proposes an application of the above key agreement scheme as a
WebAuthn extension for recovery credentials. The second subsection describes how
the key agreement scheme is implemented in the YubiKey.


## Recovery Credentials Extension (`recovery`)

This extension allows for recovery credentials to be registered with an RP,
which can be used for account recovery in the case of a lost/destroyed main
authenticator. This is done by associating one or more backup authenticators
with the main authenticator, the latter of which is then able to provide
additional credentials for account recovery to the RP without involving the
backup authenticators. The mechanism of setting this up is outside of the scope
of this extension, however a `state` counter is defined as follows:

Let `state` be initialized to 0. Performing a device reset re-initializes
`state` to 0. When the set of registered backup authenticators for the device
changes (e.g., on adding/removing a backup authenticator, including adding the
first backup authenticator) `state` is incremented by one.

The `state` counter is stored by the main authenticator, and allows the RP to
automatically detect when the set of registered recovery credentials needs to be
updated.

NOTE: The choice to make registration of recovery credentials explicit is
deliberate, in an attempt to ensure that the user deliberately intends to do so
and understands the implications.


### Extension identifier

`recovery`


### Operation applicability

Registration and Authentication


### Client extension input

    partial dictionary AuthenticationExtensionsClientInputs {
      RecoveryExtensionInput recovery;
    }

    dictionary RecoveryExtensionInput {
      required RecoveryExtensionAction action;
      sequence<PublicKeyCredentialDescriptor> allowCredentials;
    }

    enum RecoveryExtensionAction {
      "state",
      "generate",
      "recover"
    }

The values of `action` have the following meanings. `X` indicates that the value
is applicable for the given WebAuthn operation:

| Value    | create()   | get()   | Description                                                                                          |
| :------: | :--------: | :-----: | -------------                                                                                        |
| state    | X          | X       | Get the state counter value from the main authenticator.                                             |
| generate |            | X       | Regenerate recovery credentials from the main authenticator.                                         |
| recover  | X          |         | Get a recovery signature from a backup authenticator, to replace the main credential with a new one. |


### Client extension processing

None required, except creating the authenticator extension input from the client
extension input.

If the client implements support for this extension, then when `action` is
`"generate"`, the client SHOULD notify the user of the number of recovery
credentials in the response.


### Client extension output
None.


### Authenticator extension input

The client extension input encoded as a CBOR map.


### Authenticator extension processing

If `action` is

- `"state"`,

  set the extension output to the CBOR encoding of `{"action": "state", "state":
  <state counter>}`.

- `"generate"`,

  generate one recovery credential for each associated backup authenticator,
  formatting these as a CBOR array of [attested credential data][att-cred-data]
  byte arrays. Set the extension output to the CBOR encoding of `{"action":
  "generate", "state": <state counter>, "creds": <list of recovery
  credentials>}`.

- `"recover"`,

  locate a usable recovery credential from the credential IDs in
  `allowCredentials` in the extension input.

  - If no usable credential is found, fail the authenticatorMakeCredential
    operation.

  - Let `creds` be an empty list.

  - Let `authenticatorDataWithoutExtensions` be the [authenticator
    data][authdata] that will be returned from this registration operation, but
    without the `extensions` part. The `ED` flag in
    `authenticatorDataWithoutExtensions` MUST be set even though
    `authenticatorDataWithoutExtensions` does not include extension data.

  - For each usable credential found:

     1. Let `cred` be the found credential.

     2. Let `sig` be a signature over `authenticatorDataWithoutExtensions ||
        clientDataHash` using `cred`.

     3. Add `{"credId": <credential ID of cred>, "sig": <sig>}` to `creds`.

  - Set the extension output to the CBOR encoding of `{"action": "recover",
    "creds": <creds>, "state": <state counter>}`.


### Authenticator extension output

A CBOR map with contents as defined above.

    dictionary RecoveryExtensionOutput {
      required RecoveryExtensionAction action;
      required int state;
      sequence<ArrayBuffer> creds;
      ArrayBuffer credId;
      ArrayBuffer sig;
    }

### Recovery credential considerations

- The RP MUST be very explicit in notifying the user when recovery credentials
  are registered, and how many, to avoid any credentials being registered
  without the user's knowledge. If possible, the client SHOULD also display the
  number of backup authenticators associated with the main authenticator.

- The RP SHOULD clearly display information about registered recovery
  credentials, just as it does with standard credentials.

- The same security considerations apply to recovery credentials as to standard
  credentials.

- Although recovery credentials are issued by the main authenticator, they can
  only ever be used by the backup authenticator.

- Recovery credentials are scoped to a specific RP ID, and the RP SHOULD
  also associate them with a specific main credential.

- Recovery credentials can only be used in registration ceremonies where the
  recovery extension is present, with `action == "recover"`.

- A main authenticator should ensure that the recovery credentials it issues on
  behalf of a backup authenticator are authentic.


## YubiKey implementation

The following describes how YubiKeys implement the recovery extension via the
key agreement scheme described above. It is assumed that each YubiKey has an
attestation certificate signed by a single root CA certificate, and that each
YubiKey has access to the public key of that root.


### Vendor specific commands

The following vendor specific commands are added. They are not exposed via any
browser API.

NOTE: the `s, S` key pair is used in ECDH as well as to derive the recovery
credential key pair. If desired, two distinct key pairs can be used, increasing
the amount of data in the Export/Import commands below.


#### Export Recovery Seed

Exports a seed which can be imported into other YubiKeys, enabling them to
register credentials on behalf of the exporting YubiKey, for the purpose of
account recovery.

This command has no arguments.

 1. If the recovery functionality is uninitialized, generate a new EC P-256 key
    pair and store it as `s, S` (these get erased on RESET).

 2. Using the attestation certificate private key, create and output the
    following as a CBOR map:

        {
          1: attestation_cert,  # DER encoded X509 certificate as a byte string.
          2: aaguid,  # Device AAGUID as a byte string.
          3: S  # Public key from above, encoded as a COSE key.
          4: sign(attestation_key, aaguid || S)  # ECDSA signature as a byte string (S in COSE form).
        }


#### Import Recovery Seed

Imports a recovery seed, enabling this YubiKey to issue recovery credentials on
behalf of a backup YubiKey. Multiple Recovery Seeds can be imported into a
YubiKey, limited by storage space. Resetting a YubiKey removes all stored
recovery seeds, and resets the `state` counter to 0.

This command takes the output of _Export Recovery Seed_ from another YubiKey as
input.

CTAP2_ERR_XXX represents some not yet specified error code.

 1. Using the root CA public key, validate the signature of `attestation_cert`.
    If invalid, return CTAP2_ERR_XXX.

 2. Extract the public key from `attestation_cert` and use it to validate the
    signature (key `4`) in the input. If invalid, return CTAP2_ERR_XXX.

 3. Store `(S, aaguid)` internally.

 4. Increment the `state` counter by one (the counter's initial value is 0).


### Main YubiKey extension processing

For `action == "state"`, return the value of the `state` counter.

For `action == "generate"`, the following process is used to generate a recovery
credential from a recovery seed:

 1. Generate an ephemeral EC P-256 key pair: `e, E`.

 2. Use HKDF(ECDH(`e`, `S`)) to derive `cred_key`, `mac_key` (both 32 byte
    keys).

 3. If `cred_key` >= `n`, where `n` is the order of the P-256 curve, start
    over from 1.

 4. Calculate `P` = (`cred_key` * `G`) + `S`, where * and + are EC point
    multiplication and addition, and `G` is the generator of the P-256 curve.

 5. If `P` is the point at infinity, start over from 1.

 6. Set `credential_id` = `E` || LEFT(HMAC(`mac_key`, `E || rp.id`), 16),
    where LEFT(`X`, `n`) is the first `n` bytes of the byte array `X`.

 7. The recovery credential is the P-256 public key `P`, with the credential id
    `credential_id`.


### Recovery YubiKey extension processing

For `action == "recover"`, the following process is used by the recovery YubiKey
to calculate the private key needed:

 1. Let `E` = DROP_RIGHT(`credential_id`, 16), where DROP_RIGHT(`X`, `n`) is the
    byte array `X` without the last `n` bytes.

 2. Use HKDF(ECDH(`s`, `E`)) to derive `cred_key`, `mac_key`.

 3. Verify that `credential_id` == `E` || LEFT(HMAC(`mac_key`, `E || rp.id`)).
    If not, the credential isn't valid for this YubiKey (or the RP is wrong),
    and it isn't processed further.

 4. Calculate `p` = `cred_key` + `s` mod `n`, where `n` is the order of the
    P-256 curve.

 5. The recovery credential private key is `p`, which can now be used to create
    a signature.


## RP support

An RP supporting this extension SHOULD include the extension the `action =
"state"` value whenever performing standard registration or authentication
ceremony. There are two cases where the response indicates that the RP should
initiate recovery credential registration (action `"generate"`), which are:

- Upon successful `create()`, if `state` > 0.
- Upon successful `get()`, if `state` > `old_state`, where `old_state` is the
  previous value for `state` that the RP has seen for the used credential.

To initiate recovery credential registration, the RP performs a `get()`
operation with `action = "generate"`. Upon a successful response, the returned
list of recovery credentials is stored, associated with the main credential.
Any prior recovery credentials for that main credential are replaced.

If the user initiates device recovery, the RP performs the following procedure:

 1. Ask the user which credential to recover. Let `mainCred` be the chosen
    credential.

 2. Let `allowCredentials` be a list of the credential descriptors of the
    recovery credentials associated with `mainCred`. If `allowCredentials` is
    empty, abort this procedure with an error.

 3. Initiate a `create()` operation with the extension input:

        "recovery": {
          "action": "recover",
          "allowCredentials": <allowCredentials as computed above>
        }

 4. Wait for the response from the client. If the operation fails, abort this
    procedure with an error.

 5. Let `publicKey` be the public key for the recovery credential identified by
    the credential ID `credId` in the extension output.

 5. Let `authenticatorDataWithoutExtensions` be the authenticator data in the
    PublicKeyCredential response, but without the extensions part. The `ED` flag
    in `authenticatorDataWithoutExtensions` MUST be set even though
    `authenticatorDataWithoutExtensions` does not include the extension outputs.

 6. Using `publicKey`, verify that `sig` in the extension output is a valid
    signature over `authenticatorDataWithoutExtensions || clientDataHash`.

 7. Finish the registration ceremony as usual. This means a new credential has
    now been registered using the backup authenticator.

 8. Revoke `mainCred` and all recovery credentials associated with it.

 9. If `state` in the extension output is greater than 0, the RP SHOULD initiate
    recovery credential registration (`action = "generate"`) for the newly
    registered credential.

As an alternative to proceeding to register a new credential for the backup
authenticator, the RP MAY choose to not replace the lost credential with the new
one, and instead disable 2FA or provide some other means for the user to access
their account. In either case, the associated main credential SHOULD be revoked
and no longer usable.


[authdata]: https://w3c.github.io/webauthn/#authenticator-data
[att-cred-data]: https://w3c.github.io/webauthn/#attested-credential-data
