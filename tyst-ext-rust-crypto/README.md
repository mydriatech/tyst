# TYST external crypto algorithm implementations

This crate provides a selection of relevant and/or legacy algorithms from external parties.


## Imported PQC algorithms

### Key Encapsulation Mechanism (KEM) imports

* NIST FIPS 203 ML-KEM from [RustCrypto: Key Encapsulation Mechanisms (KEMs)](https://github.com/RustCrypto/KEMs/)


## Imported legacy algorithms

### Message Digest ("hash") imports

* Secure Hash Algorithm 2 (SHA-2) from [RustCrypto: Hashes](https://github.com/RustCrypto/hashes/)


### Signature Engine (SE) imports

* ECDSA from [RustCrypto: Signatures](https://github.com/RustCrypto/signatures/)
    * `secp256k1`
    * `P-384`
* EdDSA from [RustCrypto: Signatures](https://github.com/RustCrypto/signatures/)
    * `Ed25519`
* RSASSA from [RustCrypto: Signatures](https://github.com/RustCrypto/signatures/)
    * Vulnerable to [RUSTSEC-2023-0071](https://rustsec.org/advisories/RUSTSEC-2023-0071).
      Please ensure that your use-case is not vulnerable to this side-channel attack before use.
      This will be resolved in the upcoming `0.10.0` version of the [`rsa`](https://github.com/RustCrypto/RSA) crate.


## Security

The selected dependencies in this crate are provided for convenience and have not undergone the same level of scrutiny as those that are implemented by the project itself.

The selection criteria (without guarantees of compliance from this projects' maintainers) for the implementations were:

* Maintained crates with security reporting mechanism.
* No [unsafe](https://doc.rust-lang.org/reference/unsafe-keyword.html) code or wrapped C/C++.
* Reasonable well used in the Rust community.

It can NOT be expected that:

* vulnerabilities in these dependencies are corrected by this project's maintainers, since they are outside the projects control.
* the latest version of the source code of the external implementations has been reviewed by this project's maintainers.


### Known vulnerabilities

* [RUSTSEC-2023-0071](https://rustsec.org/advisories/RUSTSEC-2023-0071)


## Licenses

The license of each wrapped dependency might differ from the projects overall license.

A general policy is enforced using `deny.toml` in the projects root directory.
