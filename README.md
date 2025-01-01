# TYST Cryptographic Provider

Easy crypto agility and Post-Quantum Cryptography (PQC) at scale for everyone in the [free world](LICENSE-Apache-2.0-with-FWM-Exception-1.0.0).

## Why

The worlds greatest crypto agile library [BouncyCastle](https://www.bouncycastle.org/) was not available for Rust when the author needed it. And so the rusTY ShelTer (TYST) was born.

## Components

### [`tyst-api-rest/`](tyst-api-rest/)

Tiny OCI container `ghcr.io/mydriatech/tyst` with a REST API that can be used
as language agnostic side-car crypto library in your Kubernetes
[Pod](https://kubernetes.io/docs/concepts/workloads/pods/).

### [`tyst-core/`](tyst-core/)

Rust crate `tyst_core` crypto library for crypto-agile algorithm lookup built
into your (Rust) software.

### [`tyst-crypto/`](tyst-crypto/)

Pure Rust crypto algorithm implementations free from
[unsafe](https://doc.rust-lang.org/reference/unsafe-keyword.html) code
maintained by this project.

### [`tyst-ext-rust-crypto/`](tyst-ext-rust-crypto/)

Convenient selection of external crypto algorithm implementations in Rust.

### Additional components

* [`tyst-enddec/`](tyst-enddec/): Encoding and decoding of hex, base64 etc.
* [`tyst-traits/`](tyst-traits/): Common interfaces and objects.

## Limitations

The implementation is for all practical purposes stateless and hence no stateful
algorithm will be supported.

Due to the license, there are no plans to support algorithms from countries
where this library may not be used.

The container only listens to plain HTTP connections, since it is assumed to
be used internally in a Pod or secured by a service mesh where a
[MITM attack](https://en.wikipedia.org/wiki/Man-in-the-middle_attack)
would already imply a serious compromise of the platform.
