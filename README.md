_NOTE: This is a draft and **not implementation ready**. Security analysis is
currently ongoing (2020-02-20)._

Authors: Emil Lundberg, Dain Nilsson

# Introduction

Web Authentication solves many problems in secure online authentication, but
also introduces some new challenges. One of the greatest challenges is loss of
an authenticator - what can the user do to prevent being locked out of their
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
key from the backup authenticator to the primary authenticator, so that the
primary authenticator can also register that public key with each RP. Then the
backup authenticator can later prove possession of the private key and recover
access to the account. This has a big drawback, however: a static public key
would be easily correlatable between RPs or accounts, undermining much of the
privacy protections in WebAuthn.

In this document we propose a key agreement scheme which allows a pair of
authenticators to agree on an EC key pair in such a way that the primary
authenticator can generate nondeterministic public keys, but only the backup
authenticator can derive the corresponding private keys. We present the scheme
in the context of a practical application as a WebAuthn extension for account
recovery. This enables the use case of storing the backup authenticator in a
secure location, while maintaining WebAuthn's privacy protection of
non-correlatable public keys.


# Terminology

The following terms are used throughout this document:

- `LEFT(X, n)` is the first `n` bytes of the byte array `X`.
- `DROP_LEFT(X, n)` is the byte array `X` without the first `n` bytes.
- `DROP_RIGHT(X, n)` is the byte array `X` without the last `n` bytes.
- CTAP2_ERR_XXX represents some not yet specified error code.


# The key agreement scheme

The scheme has three participants:

- PA: the _primary authenticator_
- BA: the _backup authenticator_
- RP: the WebAuthn _Relying Party_

The goal is that PA will generate public keys for RP to store. At a later
time, BA will request the public keys from RP and derive the corresponding
private keys without further communication with PA.

The scheme is divided into three stages ordered in this forward sequence:

- In stage 1, only PA and BA may communicate.

  ```
  PA <-> BA



  RP
  ```

  This corresponds to the initial setup done to pair the primary authenticator
  with the backup authenticator.

- In stage 2, only PA and RP may communicate.

  ```
  PA     BA
   ^
   |
   v
  RP
  ```

  This corresponds to using the primary authenticator for day-to-day
  authentication while the backup authenticator is stored away in a safe place.

- In stage 3, only BA and RP may communicate.

  ```
  PA     BA
         ^
         |
         |
  RP <---+
  ```

  This corresponds to the primary authenticator being lost and no longer
  available, and the backup authenticator having been retrieved from storage.


## Stage 1: Setup

This procedure is performed once to set up the parameters for the key agreement
scheme.

 1. BA generates a new P-256 EC key pair with private key `s` and public key
    `S`.
 2. BA sends `S` to PA.
 3. RP chooses a unique public identifier `rp_id`. This is effectively a
    protocol constant and implicitly available to all parties at all times.


## Stage 2: Public key creation

The following steps are performed by PA, the primary authenticator.

 1. Generate an ephemeral EC P-256 key pair: `e`, `E`.

 2. Use `HKDF(ECDH(e, S))` to derive `cred_key`, `mac_key` (both 32 byte
    keys).

 3. If `cred_key >= n`, where `n` is the order of the P-256 curve, start
    over from 1.

 4. Calculate `P = (cred_key * G) + S`, where * and + are EC point
    multiplication and addition, and `G` is the generator of the P-256 curve.

 5. If `P` is the point at infinity, start over from 1.

 6. Let `credential_id = E || LEFT(HMAC(mac_key, E || rp_id), 16)`.

 7. Send the pair `(P, credential_id)` to RP for storage.


## Stage 3: Private key derivation

The following steps are performed by BA, the backup authenticator.

 1. Retrieve a set of `credential_id`s from RP. Perform the following steps
    for each `credential_id`.

 1. Let `E = DROP_RIGHT(credential_id, 16)`. Verify that `E` is not the point at
    infinity.

 1. Use `HKDF(ECDH(s, E))` to derive `cred_key`, `mac_key`.

 1. Verify that `credential_id == E || LEFT(HMAC(mac_key, E || rp_id), 16)`. If
    not, this `credential_id` was generated for a different backup authenticator
    than BA or a different relying party than RP, and is not processed further.

 1. Calculate `p = cred_key + s mod n`,
    where `n` is the order of the P-256 curve.

 1. The private key is `p`, which BA can now use to create a signature.

As a result of these procedures, BA will have derived `p` such that

    p * G = (cred_key + s) *   G =
          = cred_key * G + s * G =
          = cred_key * G +     S = P.


# Application: WebAuthn extension

This section proposes an application of the above key agreement scheme as a
WebAuthn extension for recovery credentials. The second subsection proposes the
CTAP2 commands used to export and import the recovery seed.


## Recovery Credentials Extension (`recovery`)

This extension allows for recovery credentials to be registered with an RP,
which can be used for account recovery in the case of a lost or destroyed
_primary authenticator_. This is done by associating one or more _backup
authenticators_ with the primary authenticator, after which the latter can
provide additional credentials for account recovery to the RP without involving
the backup authenticators.

In summary, the extension works like this:

 1. The primary authenticator first generates public keys and credential IDs for
    recovery credentials. These are stored by the RP and associated with the
    primary authenticator's credential, the _primary credential_. These are
    delivered through the authenticator data, and therefore signed by the
    primary credential.

 1. After losing the primary authenticator, account recovery can be done by
    creating a new credential with the backup authenticator. The backup
    authenticator receives the recovery credential IDs from the RP, and can use
    one of them to derive the private key corresponding to the recovery public
    key. The backup authenticator uses this private key to sign the new
    credential public key, thus creating a signature chain from the primary
    credential to the new credential.

 1. Upon verifying the recovery signature, the RP invalidates the primary
    credential and all recovery credentials associated with it, and replaces it
    with the new credential. The backup authenticator is thus "promoted" and
    replaces the primary authenticator.

In order for the RP to detect when recovery credentials can be registered, or
need to be updated, the primary authenticator keeps a _recovery credentials
state counter_ defined as follows. Let `state` be initialized to 0. Performing a
device reset resets `state` to 0. When the set of registered backup
authenticators for the device changes (e.g., on adding or removing a backup
authenticator, including adding the first backup authenticator) `state` is
incremented by one.

NOTE: The choice to make registration of recovery credentials explicit is
deliberate, in an attempt to ensure that the user deliberately intends to do so
and understands the implications.

The authenticator operations are governed by an `alg` parameter,
an unsigned 8-bit integer identifying the key agreement scheme to be used.
Credential IDs for recovery credentials are always on the form
`alg || <key agreement data>`,
where the format and meaning of `<key agreement data>`
depends on the value of `alg`.
This allows for new key agreement schemes to be added in the future
without changes to the WebAuthn-facing interface;
clients and RPs are automatically compatible with any new key agreement schemes.
Currently the only valid value for `alg` is `alg=0`.


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
| state    | X          | X       | Get the _recovery credentials state counter_ value from the primary authenticator.                      |
| generate |            | X       | Regenerate recovery credentials from the primary authenticator.                                         |
| recover  | X          |         | Get a recovery signature from a backup authenticator, to replace the primary credential with a new one. |


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

   1. Let `state` be the current value of the _recovery credentials state
      counter_.

   2. Set the extension output to the CBOR encoding of `{"action": "state",
      "state": state}`.


- `"generate"`,

   1. If the current operation is not an `authenticatorGetAssertion` operation,
      return CTAP2_ERR_XXX.

   2. Let `creds` be an empty list.

   3. For each recovery seed tuple `(alg, aaguid, S)`
      stored in this authenticator:

       1. If `alg` equals

          - 0:

             1. Generate an ephemeral EC P-256 key pair: `e, E`. `E` MUST NOT be
                the point at infinity.

             1. Let `ikm = ECDH(e, S)`. Let `ikm_x` be the X coordinate of `ikm`,
                encoded as a byte string of length 32 as described in
                [SEC 1][sec1], section 2.3.7.

             1. Let `prk` be the pseudorandom key output from [HKDF-Extract][hkdf]
                with the arguments:

                - `Hash`: SHA-256.
                - `salt`: Not set.
                - `IKM`: `ikm_x`.

             1. Let `okm` be 64 bytes of output keying material from [HKDF-Expand][hkdf]
                with the arguments:

                - `Hash`: SHA-256.
                - `PRK`: `prk`.
                - `info`: Not set.
                - `L`: 64.

             1. Let `credKey = LEFT(okm, 32)` and `macKey = LEFT(DROP_LEFT(okm,
                32), 32)`, both parsed as big-endian unsigned 256-bit numbers.

             1. If `credKey >= n`, where `n` is the order of the P-256 curve,
                start over from 1.

             1. Let `P = (credKey * G) + S`, where * and + are EC point
                multiplication and addition, and `G` is the generator of the P-256
                curve.

             1. If `P` is the point at infinity, start over from 1.

             1. Let `rpIdHash` be the SHA-256 hash of `rpId`.

             1. Let `E_enc` be `E` encoded as described in [SEC 1][sec1], section
                2.3.3, using point compression.

             1. Set `credentialId = alg || E_enc || LEFT(HMAC-SHA-256(macKey, alg || E_enc ||
                rpIdHash), 16)`.

          - anything else:

             1. Return CTAP2_ERR_XXX.

                Note: This should never happen, since the _Import recovery seed_
                operation should never store a recovery seed with an unknown
                `alg` value.

       2. Let `attCredData` be a new [attested credential data][att-cred-data]
          structure with the following member values:

          - **aaguid**: `aaguid`.
          - **credentialIdLength**: The byte length of `credentialId`.
          - **credentialId**: `credentialId`.
          - **credentialPublicKey**: `P`.

       3. Add `attCredData` to `creds`.

   4. Let `state` be the current value of the _recovery credentials state
      counter_.

   5. Set the extension output to the CBOR encoding of `{"action": "generate",
      "state": state, "creds": creds}`.


- `"recover"`,

   1. If the current operation is not an `authenticatorMakeCredential`
      operation, return CTAP2_ERR_XXX.

   2. If the recovery seed key pair `s, S` has not been initialized, return
      CTAP2_ERR_XXX.

   3. For each `cred` in `allowCredentials`:

       1. Let `alg = LEFT(cred.id, 1)`.

       2. If `alg` equals

          - 0:

             1. Let `E_enc = DROP_LEFT(DROP_RIGHT(cred.id, 16), 1)`.

             1. Let `E` be the P-256 public key decoded from the compressed point
                `E_enc` as described in [SEC 1][sec1], section 2.3.4. If invalid,
                return CTAP2_ERR_XXX.

             1. If `E` is the point at infinity, return CTAP2_ERR_XXX.

             1. Let `ikm = ECDH(s, E)`. Let `ikm_x` be the X coordinate of `ikm`,
                encoded as a byte string of length 32 as described in
                [SEC 1][sec1], section 2.3.7.

             1. Let `prk` be the pseudorandom key output from [HKDF-Extract][hkdf]
                with the arguments:

                - `Hash`: SHA-256.
                - `salt`: Not set.
                - `IKM`: `ikm_x`.

             1. Let `okm` be 64 bytes of output keying material from [HKDF-Expand][hkdf]
                with the arguments:

                - `Hash`: SHA-256.
                - `PRK`: `prk`.
                - `info`: Not set.
                - `L`: 64.

             1. Let `credKey = LEFT(okm, 32)` and `macKey = LEFT(DROP_LEFT(okm,
                32), 32)`, both parsed as big-endian unsigned 256-bit numbers.

             1. Let `rpIdHash` be the SHA-256 hash of `rp.id`.

             1. If `cred.id` is not exactly equal to `alg || E || LEFT(HMAC-SHA-256(macKey, alg
                || E || rpIdHash), 16)`, _continue_.

             1. Let `p = credKey + s (mod n)`, where `n` is the order of the P-256
                curve.

             1. Let `authenticatorDataWithoutExtensions` be the [authenticator
                data][authdata] that will be returned from this registration operation,
                but without the `extensions` part. The `ED` flag in
                `authenticatorDataWithoutExtensions` MUST be set to 1 even though
                `authenticatorDataWithoutExtensions` does not include extension data.

             1. Let `sig` be a signature over `authenticatorDataWithoutExtensions ||
                clientDataHash` using `p`. `sig` is DER encoded as described in [RFC
                3279][rfc3279].

          - anything else:

             1. _Continue_.

       9. Let `state` be the current value of the _recovery credentials state
          counter_.

      10. Set the extension output to the CBOR encoding of `{"action":
          "recover", "credId": cred.id, "sig": sig, "state": state}` and end
          extension processing.

   4. Return an error code equivalent to ERR_XXX.

- anything else,

   1. Return CTAP2_ERR_XXX.


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
  number of backup authenticators associated with the primary authenticator.

- The RP SHOULD clearly display information about registered recovery
  credentials, just as it does with standard credentials. For example, the RP
  MAY use the AAGUIDs of recovery credentials to indicate the (alleged) model of
  the corresponding managing authenticator.

- All security and privacy considerations for standard credentials also apply to
  recovery credentials.

- Although recovery credentials are issued by the primary authenticator, they
  can only ever be used by the backup authenticator.

- Recovery credentials are scoped to a specific RP ID, and the RP SHOULD also
  associate each recovery credential with a specific primary credential.

- Recovery credentials can only be used in registration ceremonies where the
  recovery extension is present, with `action == "recover"`.

- A primary authenticator MAY refuse to import a recovery seed without a trusted
  attestation signature, to reduce the risk that an RP rejects the recovery
  credential that would later be generated by the backup authenticator.

- Recovery credentials cannot be used as resident credentials, since they by
  definition cannot be stored in the backup authenticator.


## Authenticator operations

The CTAP2 command `authenticatorRecovery` is added. It is not exposed via any
browser API.


### authenticatorRecovery (0x0D)

This command is used to export a recovery seed from a backup authenticator and
then to import the seed to another authenticator, so that the latter can issue
recovery credentials on behalf of the backup authenticator.

It takes the following input parameters:

  | Parameter name | Data type | Required? | Definition
  | --- | ---- | ---- | -----------
  | subCommand (0x01) | Unsigned integer | Required | Identifier for the subcommand to execute.
  | allowAlgs (0x02) | Array of unsigned integers | Optional | Required if subCommand = exportSeed (0x02). List of acceptable key agreement schemes for seed export.
  | seed (0x03) | RecoverySeed | Optional | Required if subCommand = importSeed (0x03). Recovery seed to import.
  | pinUvAuthProtocol (0x04) | Unsigned integer | Required | PIN/UV protocol version chosen by the client.
  | pinUvAuthParam (0x05) | Byte array | Required | First 16 bytes of HMAC-SHA-256 of contents using pinUvAuthToken

The list of sub commands for recovery seeds is:

  | subCommand Name | subCommand Number
  | --- | ----
  | getAllowAlgs | 0x01
  | exportSeed | 0x02
  | importSeed | 0x03

The RecoverySeed type is a CBOR map with the following structure:

  | Member name | Data type | Required? | Definition
  | --- | ---- | ---- | -----------
  | alg (0x01) | Unsigned integer | Required | Identifier for the key agreement scheme.
  | aaguid (0x02) | Byte array | Required | AAGUID of the authenticator that exported the `payload`.
  | x5c (0x03) | Array of byte arrays | Required | Sequence of DER encoded X.509 attestation certificates
  | sig (0x04) | Byte array | Required | DER encoded ECDSA signature.
  | S_enc (0xFF) | Byte array | Optional | Required if alg = 0x00. P-256 public key encoded as described in [SEC 1][sec1], section 2.3.4, using point compression.

On success, authenticator returns the following structure in its response:

  | Parameter name | Data type | Required? | Definition
  | --- | ---- | ---- | -----------
  | allowAlgs (0x02) | Array of unsigned integers | Optional | List of key agreement schemes the authenticator supports.
  | seed (0x03) | RecoverySeed | Optional | Recovery seed to be imported by another authenticator.


#### Feature detection

TODO


#### Get supported key agreement schemes (subCommand 0x01)

Used by the platform to get a suitable value for the allowAlgs (0x02) parameter
of the exportSeed (0x02) subcommand.

Following operations are performed to get the list of recovery key agreement
schemes an authenticator supports:

- Platform sends authenticatorRecovery command with following parameters:
  - subCommand (0x01): getAllowAlgs (0x01)
  - Authenticator returns authenticatorRecovery response with following
    parameters:
    - allowAlgs (0x02): An array containing the integer 0 as the only element.


#### Export Recovery Seed (subCommand 0x02)

Exports a seed which can be imported into other authenticators, enabling them to
register credentials on behalf of the exporting authenticator, for the purpose
of account recovery.


Following operations are performed to get a recovery seed:

- Platform gets pinUvAuthToken from the authenticator.
- Platform sends authenticatorRecovery command with following parameters:
  - subCommand (0x01): exportSeed (0x02)
  - allowAlgs (0x02): Output from getAllowAlgs (0x01) subcommand on a different
    authenticator

  - pinUvAuthProtocol (0x04): Pin Protocol used. Currently this is 0x01.
  - pinUvAuthParam (0x05): `LEFT(HMAC-SHA-256(pinUvAuthToken, exportSeed
    (0x02)), 16)`.

- Authenticator verifies pinUvAuthParam by generating
  `LEFT(HMAC-SHA-256(pinUvAuthToken, exportSeed (0x02)), 16)` and matching
  against input pinUvAuthParam parameter.
  - If pinUvAuthParam verification fails, authenticator returns
    CTAP2_ERR_PIN_AUTH_INVALID error.
  - If authenticator sees 3 consecutive mismatches, it returns
    CTAP2_ERR_PIN_AUTH_BLOCKED indicating that power recycle is needed for
    further operations. This is done so that malware running on the platform
    should not be able to block the device without user interaction.

- Authenticator performs following steps:

   1. For each `alg` in `allowAlgs`:

       1. If `alg` equals:

          - 0:

             1. If the recovery functionality is uninitialized, generate a new EC
                P-256 key pair and store it as `s, S`. The `authenticatorReset`
                command MUST erase `s` and `S`.

             1. Let `S_enc` be `S` encoded as described in [SEC 1][sec1], section
                2.3.3, using point compression.

             1. Let `sig` be a signature over the data `alg || aaguid || S_enc`
                using the authenticator's attestation key and the SHA-256 hash
                algorithm. `sig` is DER encoded as described in [RFC
                3279][rfc3279].

             1. Authenticator returns authenticatorRecovery response with
                following parameters:

                - seed (0x03): RecoverySeed structure with following parameters:
                  - alg (0x01): `alg`
                  - aaguid (0x02): Authenticator's AAGUID
                  - x5c (0x03): Authenticator's attestation certificate chain as
                    DER encoded X.509 certificates, with leaf attestation
                    certificate as the first element
                  - sig (0x04): `sig` as computed above
                  - S_enc (0xFF): `S_enc` as computed above

          - anything else:

             1. _Continue_.

   2. Return CTAP2_ERR_XXX.


#### Import Recovery Seed (subCommand 0x03)

Imports a recovery seed, enabling this authenticator to issue recovery
credentials on behalf of a backup authenticator. Multiple recovery seeds can be
imported into an authenticator, limited by storage space. Resetting the
authenticator removes all stored recovery seeds, and resets the `state` counter
to 0.

Following operations are performed to get a recovery seed:

- Platform gets pinUvAuthToken from the authenticator.
- Platform sends authenticatorRecovery command with following parameters:
  - subCommand (0x01): importSeed (0x03)
  - seed (0x03): Output from exportSeed (0x02) subcommand on a different
    authenticator, containing following parameters:
    - alg (0x01): Identifier for key agreement scheme
    - aaguid (0x02): AAGUID of the authenticator that exported the seed
    - x5c (0x03): Attestation certificate chain of the authenticator that
      exported the seed
    - sig (0x04): Attestation signature over the seed contents
    - S_enc (0xFF): Required if alg = 0x00. EC public key encoded with point compression.

  - pinUvAuthProtocol (0x04): Pin Protocol used. Currently this is 0x01.
  - pinUvAuthParam (0x05): `LEFT(HMAC-SHA-256(pinUvAuthToken, importSeed
    (0x03)), 16)`.

- Authenticator verifies pinUvAuthParam by generating
  `LEFT(HMAC-SHA-256(pinUvAuthToken, importSeed (0x03)), 16)` and matching
  against input pinUvAuthParam parameter.
  - If pinUvAuthParam verification fails, authenticator returns
    CTAP2_ERR_PIN_AUTH_INVALID error.
  - If authenticator sees 3 consecutive mismatches, it returns
    CTAP2_ERR_PIN_AUTH_BLOCKED indicating that power recycle is needed for
    further operations. This is done so that malware running on the platform
    should not be able to block the device without user interaction.

- Authenticator performs following steps:

   1. If the authenticator has no storage space available to import a recovery
      seed, return CTAP2_ERR_XXX.

   1. If `alg` equals:

      - 0:

         1. Let `S` be the P-256 public key decoded from the compressed point
            `S_enc` as described in [SEC 1][sec1], section 2.3.4. If invalid,
            return CTAP2_ERR_XXX.

         1. Let `attestation_cert` be the first element of `x5c`.

         1. Extract the public key from `attestation_cert` and use it to verify
            the signature `sig` against the signed data `alg || aaguid ||
            S_enc`. If invalid, return CTAP2_ERR_XXX.

         1. If `attestation_cert` contains an extension with OID
            1.3.6.1.4.1.45724.1.1.4 (`id-fido-gen-ce-aaguid`), verify that the
            value of this extension equals `aaguid`.

         1. OPTIONALLY, perform this sub-step:
             1. Using a vendor-specific store of trusted attestation CA
                certificates, verify the signature chain `x5c`. If invalid or
                untrusted, OPTIONALLY return CTAP2_ERR_XXX.

         1. Store `(alg, aaguid, S)` internally.

      - anything else:

         1. Return CTAP2_ERR_XXX.

   1. Increment the `state` counter by one (the counter's initial value is 0).

   1. Return CTAP2_OK.


## RP operations

An RP supporting this extension SHOULD include the extension with `action:
"state"` whenever performing a registration or authentication ceremony. There
are two cases where the response indicates that the RP SHOULD initiate recovery
credential registration (`action: "generate"`), which are:

- Upon successful `create()`, if `state` > 0.
- Upon successful `get()`, if `state` > `old_state`, where `old_state` is the
  previous value for `state` that the RP has seen for the used credential.

The following operations assume that each user account contains a
`recoveryStates` field, which is a map with credential IDs as keys.
`recoveryStates` is initialized to an empty map.


### Detecting changes to recovery seeds

To detect when the user's authenticator has updated its recovery seed settings,
the RP SHOULD add the following steps to all registration and authentication
ceremonies:

 1. When initiating any `create()` or `get()` operation, set the extension
    `"recovery": {"action": "state"}`.

 1. Let `pkc` be the PublicKeyCredential response from the client.

 1. In step 14 of the RP Operation to [Register a New
    Credential][rp-reg-ext-processing], or 15 of the RP Operation to [Verify an
    Authentication Assertion][rp-auth-ext-processing], perform the following
    steps:

     1. Let `extOutput` be the recovery extension output, or null if not
        present. For `create()` ceremonies, this is `extOutput =
        pkc.response.attestationObject["authData"].extensions["recovery"]`; for
        `get()` ceremonies it is `extOutput =
        pkc.response.authenticatorData.extensions["recovery"]`.

     1. If `extOutput` is not null:

         1. If `extOutput.action` does not equal `"state"`, or `extOutput.state`
            is not present, abort this extension processing and OPTIONALLY show
            a user-visible warning.

         1. If `extOutput.state > 0`:

             1. Let `recoveryState = recoveryStates[pkc.id]`, or null if not
                present.

             1. If `recoveryState` is null or `extOutput.state >
                recoveryState.state`:

                 1. If the ceremony finishes successfully, prompt the user that
                    their recovery credentials need to be updated and ask to
                    initiate a _Registering recovery credentials_ ceremony as
                    described below. It is RECOMMENDED to set `allowCredentials`
                    to contain only `pkc.id` in this authentication ceremony.

 4. Continue with the remaining steps of the standard registration or
    authentication ceremony.


### Registering recovery credentials

To register new recovery credentials for a given primary credential, or replace
the existing recovery credentials with updated ones, the RP performs the
following procedure:

 1. Initiate a `get()` operation and set the extension `"recovery": {"action":
    "generate"}`.

    If this ceremony was triggered as described in _Detecting changes to
    recovery seeds_, it is RECOMMENDED to set `allowCredentials` to contain only
    the credential that was used in that preceding ceremony.

 1. Let `pkc` be the PublicKeyCredential response from the client. If the
    operation fails, abort the ceremony with an error.

 1. In step 15 of the RP Operation to [Verify an Authentication
    Assertion][rp-auth-ext-processing], perform the following steps:

     1. Let `extOutput = pkc.response.authenticatorData.extensions["recovery"]`,
        or null if not present.

     1. If `extOutput` is null, `extOutput.action` does not equal `"generate"`,
        `extOutput.state` is not present, or `extOutput.creds` is not present,
        abort the ceremony with an error.

     1. Let `acceptedCreds` be a new empty list.

     1. Let `rejectedCreds` be a new empty list.

     1. For each `cred` in `extOutput.creds`:

         1. If `cred.aaguid` identifies an authenticator model accepted by the
            RP's policy, add `cred` to `acceptedCreds`. Otherwise, add `cred` to
            `rejectedCreds`.

     1. Set `recoveryStates[pkc.id] = (extOutput.state, acceptedCreds)`.

     1. Show the user a confirmation message containing the length of
        `acceptedCreds`.

     1. If `rejectedCreds` is not empty, show the user a warning message. The
        warning message SHOULD contain the length of `rejectedCreds` and, if
        possible, descriptions of the AAGUIDs that were rejected.

 1. Continue with the remaining steps of the standard authentication ceremony.


### Using a recovery credential to replace a lost primary credential

To authenticate the user with a recovery credential and create a new primary
credential, the RP performs the following procedure:

 1. Identify the user, for example by asking for a username.

 1. Let `allowCredentials` be a new empty list.

 1. For each `(state, creds)` value in the `recoveryStates` map stored in the
    user's account:

     1. For each `cred` in `creds`:

         1. Let `credDesc` be a PublicKeyCredentialDescriptor structure with the
            following member values:

            - **type**: `"public-key"`.
            - **id**: `cred.credentialId`.

         1. Add `credDesc` to `allowCredentials`.

 1. If `allowCredentials` is empty, abort this procedure with an error.

 1. Initiate a `create()` operation with the extension input:

        "recovery": {
          "action": "recover",
          "allowCredentials": <allowCredentials as computed above>
        }

 1. Let `pkc` be the PublicKeyCredential response from the client. If the
    operation fails, abort the ceremony with an error.

 1. In step 14 of the RP Operation to [Register a New
    Credential][rp-reg-ext-processing], perform the following steps:

     1. Let `extOutput = pkc.response.authenticatorData.extensions["recovery"]`,
        or null if not present.

     1. If `extOutput` is null, `extOutput.action` does not equal `"recover"`,
        `extOutput.state` is not present, `extOutput.credId` is not present, or
        `extOutput.sig` is not present, abort the ceremony with an error.

     1. Let `revokedCredId` be null.

     1. For each `primaryCredId` in the keys of `recoveryStates`:

         1. Let `(state, creds) = recoveryCreds[primaryCredId]`.

         1. For each `cred` in `creds`:

             1. If `cred.credentialId` equals `extOutput.credId`:

                 1. Verify that `credentialId` equals the `id` member of some
                    element of `allowCredentials`.

                 1. Let `publicKey` be the decoded public key `cred.credentialPublicKey`.

                 1. Let `authenticatorDataWithoutExtensions` be
                    `pkc.response.authenticatorData`, but without the `extensions` part. The
                    `ED` flag in `authenticatorDataWithoutExtensions` MUST be set to 1 even
                    though `authenticatorDataWithoutExtensions` does not include the
                    extension outputs.

                 1. Using `publicKey`, verify that `extOutput.sig` is a valid
                    signature over `authenticatorDataWithoutExtensions || clientDataHash`.
                    If the signature is invalid, fail the registration ceremony.

                 1. Set `revokedCredId = primaryCredId`.

                 1. _Break._

             1. Else, _continue_.

     1. If `revokedCredId` is null, abort the ceremony with an error.

 1. Continue with the remaining steps of the standard registration ceremony.
    This means a new credential has now been registered using the backup
    authenticator.

 1. Invalidate the credential identified by `revokedCredId` and all recovery
    credentials associated with it (i.e., delete
    `recoveryStates[revokedCredId]`). This step and the registration of the new
    credential SHOULD be performed as an atomic operation.

 1. It is RECOMMENDED to send the user an e-mail or similar notification about
    this change to their account.

 1. If `extOutput.state` is greater than 0, the RP SHOULD initiate
    recovery credential registration (`action = "generate"`) for the newly
    registered credential.

When identifying the user and building the `allowCredentials` list, please
consider the [risk of privacy leak via Credential
IDs](#sctn-credential-id-privacy-leak).

As an alternative to proceeding to register a new credential for the backup
authenticator, the RP MAY choose to not replace the lost credential with the new
one, and instead disable 2FA or provide some other means for the user to access
their account. In either case, the associated primary credential SHOULD be
revoked and no longer usable.


[att-cred-data]: https://w3c.github.io/webauthn/#attested-credential-data
[authdata]: https://w3c.github.io/webauthn/#authenticator-data
[ctap2-canon]: https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#ctap2-canonical-cbor-encoding-form
[hkdf]: https://tools.ietf.org/html/rfc5869
[rfc3279]: https://tools.ietf.org/html/rfc3279.html
[rp-auth-ext-processing]: https://w3c.github.io/webauthn/#sctn-verifying-assertion
[rp-reg-ext-processing]: https://w3c.github.io/webauthn/#sctn-registering-a-new-credential
[sec1]: http://www.secg.org/sec1-v2.pdf
