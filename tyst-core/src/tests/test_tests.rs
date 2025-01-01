use tyst_traits::{factory::FactoryCriteria, mac::ToMacKey};

use crate::*;

#[test]
fn test_lookups() {
    crate::test::common::init_logger();
    log::debug!(
        "Available digests: {:?}",
        Tyst::instance().digests().get_algorithms()
    );
    Tyst::instance().digests().by_name("SHA3-512").unwrap();
    // Lookup the same algorithm, but require a non-existing confinement type
    assert_eq!(
        false,
        Tyst::instance()
            .digests()
            .by_name_and_criteria_with_params(
                "SHA3-512",
                Some(FactoryCriteria::default().require_confinement_type("non-existing")),
                None,
            )
            .is_some()
    );
    log::debug!(
        "Available signature engines: {:?}",
        Tyst::instance().ses().get_algorithms()
    );
    Tyst::instance().kems().by_name("ML-KEM-768").unwrap();
    log::debug!(
        "Available KEMs: {:?}",
        Tyst::instance().kems().get_algorithms()
    );
    Tyst::instance().ses().by_name("ML-DSA-87").unwrap();
    log::debug!(
        "Available macs: {:?}",
        Tyst::instance().macs().get_algorithms()
    );
    Tyst::instance().macs().by_name("HMAC-SHA3-512").unwrap();
    log::debug!(
        "Available prngs: {:?}",
        Tyst::instance().prngs().get_algorithms()
    );
    Tyst::instance()
        .prngs()
        .by_name("HMAC-DRBG-SHA3-512")
        .unwrap();
}

#[test]
fn test_digest_sha3_244() {
    crate::test::common::init_logger();
    let msg = "";
    let hash_as_hex = &tyst_encdec::hex::encode(
        &Tyst::instance()
            .digests()
            .by_oid("2.16.840.1.101.3.4.2.7")
            .unwrap()
            .hash(&tyst_encdec::hex::decode(msg)),
    );
    assert_eq!(
        hash_as_hex, "6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7",
        "Failed to generate the correct hash."
    );
    let hash_as_hex = &tyst_encdec::hex::encode(
        &Tyst::instance()
            .digests()
            .by_name("SHA3-224")
            .unwrap()
            .hash(&tyst_encdec::hex::decode(msg)),
    );
    assert_eq!(
        hash_as_hex, "6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7",
        "Failed to generate the correct hash."
    );
}

#[test]
fn test_digest_keccak_384() {
    crate::test::common::init_logger();
    let msg = "";
    let hash_as_hex = &tyst_encdec::hex::encode(
        &Tyst::instance()
            .digests()
            .by_name("Keccak-384")
            .unwrap()
            .hash(&tyst_encdec::hex::decode(msg)),
    );
    assert_eq!(
        hash_as_hex, "2c23146a63a29acf99e73b88f8c24eaa7dc60aa771780ccc006afbfa8fe2479b2dd2b21362337441ac12b515911957ff",
        "Failed to generate the correct hash."
    );
}

#[test]
fn test_digest_shake256() {
    crate::test::common::init_logger();
    let msg = "";
    let hash_as_hex = &tyst_encdec::hex::encode(
        &Tyst::instance()
            .digests()
            .by_name("SHAKE256")
            .unwrap()
            .hash(&tyst_encdec::hex::decode(msg)),
    );
    assert_eq!(
        hash_as_hex, "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762fd75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be",
        "Failed to generate the correct hash."
    );
}

#[test]
fn test_prng_hmac_sha3_512() {
    crate::test::common::init_logger();
    let key = "1234567890abcdef";
    let msg = "";
    let mac_as_hex = tyst_encdec::hex::encode(
        &Tyst::instance()
            .macs()
            .by_oid("2.16.840.1.101.3.4.2.16")
            .unwrap()
            .mac(
                &tyst_encdec::hex::decode(key).to_mac_key(),
                &tyst_encdec::hex::decode(msg),
            ),
    );
    assert_eq!(
        mac_as_hex,
        "c19c91c3becbcd1f34e4500b77484f12b6b1683c90b1a2cba342fc9f91666763\
         75afd7da7a2a96a18a8a2ad114b93b1ae29a2e41b32cc542c9e356b190245fe3",
        "Failed to generate the correct mac."
    );
}

#[test]
fn test_mac_hmac_drbg_sha3_256() {
    crate::test::common::init_logger();
    let mut secure_random = Tyst::instance()
        .prngs()
        .by_name("HMAC-DRBG-SHA3-512")
        .unwrap();
    let first = secure_random.next_u64();
    let seconds = secure_random.next_u64();
    assert_ne!(
        first, seconds,
        "Random generator generated unprobable number sequence."
    );
    let mut secure_random2 = Tyst::instance()
        .prngs()
        .by_name("HMAC-DRBG-SHA3-512")
        .unwrap();
    let first2 = secure_random2.next_u64();
    assert_ne!(first, first2, "Random generator seems deterministic.");
}

#[test]
fn test_se_ml_dsa_happy_path() {
    crate::test::common::init_logger();
    let message = b"This is a test! Hold my beer while I sign this...";
    for algorithm_name in ["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"] {
        let mut engine = Tyst::instance().ses().by_name(algorithm_name).unwrap();
        let (public_key, private_key) = engine.generate_key_pair();
        let signature = engine.sign(&private_key, message).unwrap();
        assert_eq!(
            engine.verify(&public_key, &signature, message),
            true,
            "Failed to verify own signature."
        );
    }
}
