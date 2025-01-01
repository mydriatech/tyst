# TYST Core

Core module for the TYST cryptographic provider.

## Description

The `tyst_core` acts as a lookup registry and contains no cryptographic algorithm
implementations.

Common implementations are added through the default feature flags and
additional `tyst_traits::CryptoBundle`s can be added at any time during your
application's runtime.

## Examples

You can find many examples in the `examples/` directory.

```text
# You can run these from the repository root
cargo run --example digest_example
cargo run --example kem_example
cargo run --example mac_example
cargo run --example prng_example
cargo run --example se_example
```
