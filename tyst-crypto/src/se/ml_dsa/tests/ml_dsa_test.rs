use crate::prng::fixed_secure_random::FixedSecureRandom;
use crate::test::common::acvp;
use crate::test::common::acvp::AcvpTestGroup;

use super::super::*;

#[test]
fn test_key_generation() {
    crate::test::common::init_logger();
    let acvp_tests = acvp::get_acvp_test_data(
        "https://github.com/usnistgov/ACVP-Server/raw/refs/tags/v1.1.0.37/gen-val/json-files/ML-DSA-keyGen-FIPS204/internalProjection.json"
    )
    .unwrap();
    for test_group in acvp_tests.get_test_groups() {
        match test_group {
            AcvpTestGroup::KeyGen {
                tg_id,
                test_type,
                parameter_set,
                tests,
            } => {
                for test in tests {
                    let secure_random = Box::new(FixedSecureRandom::new(test.get_seed()));
                    let mut engine = MldsaEngine::new(parameter_set, Some(secure_random));
                    let (pub_key, priv_key) = engine.generate_key_pair();
                    assert_eq!(
                        &pub_key.try_as_raw().unwrap(),
                        &test.get_pk(),
                        "{test_type}/{parameter_set}: Public key does not match the expected for test {}/{tg_id}/{}.",
                        acvp_tests.get_vs_id(), test.get_tc_id()
                    );
                    assert_eq!(
                        &priv_key.try_as_bytes().unwrap(),
                        &test.get_sk(),
                        "{test_type}/{parameter_set}: Private (secret) key does not match the expected for test {}/{tg_id}/{}.",
                        acvp_tests.get_vs_id(), test.get_tc_id()
                    );
                }
            }
            _ => {
                log::info!(
                    "Ignoring unexpected test group of type '{}'.",
                    test_group.name()
                );
            }
        }
    }
}

#[test]
fn test_signature_generation() {
    crate::test::common::init_logger();
    let acvp_tests = acvp::get_acvp_test_data(
        "https://github.com/usnistgov/ACVP-Server/raw/refs/tags/v1.1.0.37/gen-val/json-files/ML-DSA-sigGen-FIPS204/internalProjection.json"
    )
    .unwrap();
    for test_group in acvp_tests.get_test_groups() {
        match test_group {
            AcvpTestGroup::SigGen {
                tg_id,
                test_type,
                parameter_set,
                deterministic,
                tests,
            } => {
                for test in tests {
                    let mut engine = MldsaEngine::new(parameter_set, None);
                    let priv_key =
                        MldsaPrivateKey::new(engine.get_ml_dsa_parameters(), test.get_sk());
                    let rnd = if *deterministic {
                        &[0u8; 32]
                    } else {
                        test.get_rnd()
                    };
                    //let rnd = [0u8; 32];

                    let signature = engine
                        .init_and_sign_internal(
                            priv_key.get_tr(),
                            false,
                            None,
                            test.get_message(),
                            priv_key.get_rho(),
                            priv_key.get_k(),
                            priv_key.get_t0(),
                            priv_key.get_s1(),
                            priv_key.get_s2(),
                            &rnd,
                        )
                        .unwrap();
                    assert_eq!(
                            &signature,
                            test.get_signature(),
                            "{test_type}/{parameter_set}: Generated signature does not match {}/{tg_id}/{}.",
                            acvp_tests.get_vs_id(), test.get_tc_id()
                        );
                }
            }
            _ => {
                log::info!(
                    "Ignoring unexpected test group of type '{}'.",
                    test_group.name()
                );
            }
        }
    }
}

#[test]
fn test_signature_verification() {
    crate::test::common::init_logger();
    let acvp_tests = acvp::get_acvp_test_data(
        "https://github.com/usnistgov/ACVP-Server/raw/refs/tags/v1.1.0.37/gen-val/json-files/ML-DSA-sigVer-FIPS204/internalProjection.json"
    )
    .unwrap();
    for test_group in acvp_tests.get_test_groups() {
        match test_group {
            AcvpTestGroup::SigVer {
                tg_id,
                test_type,
                parameter_set,
                pk,
                sk: _,
                tests,
            } => {
                for test in tests {
                    let actual = verify_signature(
                        parameter_set,
                        pk,
                        test.get_signature(),
                        test.get_message(),
                    );
                    assert_eq!(
                        actual,
                        test.get_test_passed(),
                        "{test_type}/{parameter_set}: Signature verification produced the wrong result for test {}/{tg_id}/{}.",
                        acvp_tests.get_vs_id(), test.get_tc_id()
                    );
                }
            }
            _ => {
                log::info!(
                    "Ignoring unexpected test group of type '{}'.",
                    test_group.name()
                );
            }
        }
    }
}

fn verify_signature(
    algorithm_name: &str,
    public_key: &[u8],
    signature: &[u8],
    message: &[u8],
) -> bool {
    let mut engine = MldsaEngine::new(algorithm_name, None);
    let pub_key = MldsaPublicKey::new(public_key);
    engine.init_verify(pub_key.get_rho(), pub_key.get_t1_packed(), false, None);
    engine.verify_internal_msg(
        signature,
        message,
        &pub_key.get_rho(),
        &pub_key.get_t1_packed(),
    )
}
