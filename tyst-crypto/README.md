# TYST crypto algorithm implementations

This crate contains a collection of crypto algorithm implementations.

## Implemented algorithms

### Message Digest ("hash") implementations

* Keccak
* NIST FIPS 202 SHA3
* NIST FIPS 202 SHAKE

### Message Authentication Code (MAC) implementations

* HMAC (SHA3 versions of [RFC 2104](https://datatracker.ietf.org/doc/html/rfc2104))

### Psuedo-Random Number Generator (PRNG) implementations

A PRNG is also known as Deterministic Random Bit Generator (DRBG).

* NIST SP 800-90A (HMAC with SHA3 variant)

### Signature Engine (SE) implementations

* NIST FIPS 204 ML-DSA
