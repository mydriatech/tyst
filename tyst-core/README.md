# TYST Core

Core module for the TYST cryptographic provider.

## Description

The `tyst` Rust crate acts as a lookup registry and contains no cryptographic algorithm
implementations.

Common implementations are added through the default feature flags and
additional `tyst::traits::CryptoBundle`s can be added at any time during your
application's runtime.

## Quick start

Add the following to `Cargo.toml`:

```text
[dependencies]
tyst = { git = "https://github.com/mydriatech/tyst.git", branch = "main" }
```

Sign a message using ML-DSA:

```
use tyst::Tyst;

if let Some(mut se) = Tyst::instance().ses().by_name("ML-DSA-87") {
    let (pub_key, priv_key) = se.generate_key_pair();
    let message = "This will be signed!";
    let signature = se.sign(priv_key.as_ref(), message.as_bytes()).unwrap();
    let _ok = se.verify(pub_key.as_ref(), &signature, &message.as_bytes());
}
```

## Examples

You can find many examples in the `examples/` directory.

```text
# You can run these from the repository root
cargo run --example digest_example
cargo run --example kdf_example
cargo run --example kem_example
cargo run --example mac_example
cargo run --example prng_example
cargo run --example se_example
```
