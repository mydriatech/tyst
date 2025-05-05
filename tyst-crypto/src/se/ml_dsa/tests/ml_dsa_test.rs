use super::super::*;
use crate::prng::fixed_secure_random::FixedSecureRandom;
use crate::test::common::acvp;
use crate::test::common::acvp::AcvpTestGroup;

#[test]
fn test_bc_generated_signature() {
    // ML-DSA-44
    let message = "to be signed".as_bytes();
    let encoded_pubkey_hex = "d7b2b47254aae0db45e7930d4a98d2c97d8f1397d1789dafa17024b316e9bec94fc9946d42f19b79a7413bbaa33e7149cb42ed5115693ac041facb988adeb5fe0e1d8631184995b592c397d2294e2e14f90aa414ba3826899ac43f4cccacbc26e9a832b95118d5cb433cbef9660b00138e0817f61e762ca274c36ad554eb22aac1162e4ab01acba1e38c4efd8f80b65b333d0f72e55dfe71ce9c1ebb9889e7c56106c0fd73803a2aecfeafded7aa3cb2ceda54d12bd8cd36a78cf975943b47abd25e880ac452e5742ed1e8d1a82afa86e590c758c15ae4d2840d92bca1a5090f40496597fca7d8b9513f1a1bda6e950aaa98de467507d4a4f5a4f0599216582c3572f62eda8905ab3581670c4a02777a33e0ca7295fd8f4ff6d1a0a3a7683d65f5f5f7fc60da023e826c5f92144c02f7d1ba1075987553ea9367fcd76d990b7fa99cd45afdb8836d43e459f5187df058479709a01ea6835935fa70460990cd3dc1ba401ba94bab1dde41ac67ab3319dcaca06048d4c4eef27ee13a9c17d0538f430f2d642dc2415660de78877d8d8abc72523978c042e4285f4319846c44126242976844c10e556ba215b5a719e59d0c6b2a96d39859071fdcc2cde7524a7bedae54e85b318e854e8fe2b2f3edfac9719128270aafd1e5044c3a4fdafd9ff31f90784b8e8e4596144a0daf586511d3d9962b9ea95af197b4e5fc60f2b1ed15de3a5bef5f89bdc79d91051d9b2816e74fa54531efdc1cbe74d448857f476bcd58f21c0b653b3b76a4e076a6559a302718555cc63f74859aabab925f023861ca8cd0f7badb2871f67d55326d7451135ad45f4a1ba69118fbb2c8a30eec9392ef3f977066c9add5c710cc647b1514d217d958c7017c3e90fd20c04e674b90486e9370a31a001d32f473979e4906749e7e477fa0b74508f8a5f2378312b83c25bd388ca0b0fff7478baf42b71667edaac97c46b129643e586e5b055a0c211946d4f36e675bed5860fa042a315d9826164d6a9237c35a5fbf495490a5bd4df248b95c4aae7784b605673166ac4245b5b4b082a09e9323e62f2078c5b76783446defd736ad3a3702d49b089844900a61833397bc4419b30d7a97a0b387c1911474c4d41b53e32a977acb6f0ea75db65bb39e59e701e76957def6f2d44559c31a77122b5204e3b5c219f1688b14ed0bc0b801b3e6e82dcd43e9c0e9f41744cd9815bd1bc8820d8bb123f04facd1b1b685dd5a2b1b8dbbf3ed933670f095a180b4f192d08b10b8fabbdfcc2b24518e32eea0a5e0c904ca844780083f3b0cd2d0b8b6af67bc355b9494025dc7b0a78fa80e3a2dbfeb51328851d6078198e9493651ae787ec0251f922ba30e9f51df62a6d72784cf3dd205393176dfa324a512bd94970a36dd34a514a86791f0eb36f0145b09ab64651b4a0313b299611a2a1c48891627598768a3114060ba4443486df51522a1ce88b30985c216f8e6ed178dd567b304a0d4cafba882a28342f17a9aa26ae58db630083d2c358fdf566c3f5d62a428567bc9ea8ce95caa0f35474b0bfa8f339a250ab4dfcf2083be8eefbc1055e18fe15370eecb260566d83ff06b211aaec43ca29b54ccd00f8815a2465ef0b46515cc7e41f3124f09efff739309ab58b29a1459a00bce5038e938c9678f72eb0e4ee5fdaae66d9f8573fc97fc42b4959f4bf8b61d78433e86b0335d6e9191c4d8bf487b3905c108cfd6ac24b0ceb7dcb7cf51f84d0ed687b95eaeb1c533c06f0d97023d92a70825837b59ba6cb7d4e56b0a87c203862ae8f315ba5925e8edefa679369a2202766151f16a965f9f81ece76cc070b55869e4db9784cf05c830b3242c8312";
    let encoded_pubkey = tyst_encdec::hex::decode(encoded_pubkey_hex).unwrap();
    let encoded_privkey_hex = "d7b2b47254aae0db45e7930d4a98d2c97d8f1397d1789dafa17024b316e9bec939ce0f7f77f8db5644dcda366bfe4734bd95f435ff9a613aa54aa41c2c694c04329a07b1fabb48f52a309f11a1898f848e2322ffe623ec810db3bee33685854a88269da320d5120bfcfe89a18e30f7114d83aa404a646b6c997389860d12522ee0006e2384819186619b260d118664d4a62822184482402898146148a6614c4248a19208c2382951244808a125c2083108c47120140914836c18a78084106ec9c07022b56408b0610c070498124451886959004622932041062e42b64c01164914284c41a85180460a5116515a0820022244dc9849d13251e13065d3c08592a85112a1640039220946621cc70cd9086dd0062652408580443091062c50c80924c5841a966d4a982c99066da4443220a7645a326e11b57020926124138e04852c0a4872c8a051d3082a99208058242024074e59148810a46460c06de0b28d1b1909203422c024410943710a212061a2015222521b80809a340013934dd3322922170a9892691a14512027219cc02062a2814818691a854d8344695b2041031242cb184601a90d0c023183b0215a224ac89205d9906904306a4b064ad2b2011c404081423252327254a6405a18100c321292c2805212625c82280bb46c03428d53100c14010ee1365288842491020a63462620062911c228d0204802b36ca236095a8648cbb4618b4662c440821a890910024d24b24520122524c90588288cc9c04d5948220a276ec134644c90605b445082864943880443b28c603080a2882d84a46d8ca629d0c68442064689885100a98d01498de4380da4068dd3947142b26c1a84611ba32842b42808a0711ac531e0a04c013765242862142890091061d940221b3360090292d02481200408491844a3222d5c8844149808a446610195640b390a0c9450ca406ad2b220c0380182308e13b908918084148829c0189112350da02422e20406d9c2850428121cc989180272d24029c20812d8062a9994719bb8682384291a2289144511dc82445096450c4484c0b2049aa60543862c44326e88442120a84c9a3070e3b82d63268803254903438c48a809ca147253344e1243081ba704593022d99480e234228142129c302a9434266104452426281346094a326d11280918b82562281113410d41b21190844c8b1212a2c688c9c030220606d2188e848630904452128831d9207113c52843060e033060cca6845826524c88011ef72562c85ffa43acfa49217f2b172d7bbc14620e6d980a71aabbdf0c45e9a206ecb1423fee15decc17601300149d9223cd6e6c6e1fa8e41fc7c64938ab68905fd3dcda50d87082e7d0d71d1bc9b2b84c85523ca8fe6cad294adf83be15b108ff721d0cc87bc3dd3a7590184b0e845663a91fc9e1c3c53a61d867420b04f092355753bc65a06368fd41295fd09924132c6f91f67964c142674a725c343914c4cecf58c074bcaf4558c97bf7911e07aa6d0938f2ee2bb3c1a8c595d635e84342fdea01dc24b211ad2fc281cf77e59110c7abc54bf0c86d480b9be276471dc9d603cee98cfdab3e9fcfb703793560549ea4450fa7b33fb9169c44b4d25fb9c457f49791cd3da03eac96095813c105132ccda4e63e49228cd23d8a1f37856f142d93b90db09f82af89258c63aab8047a80c036c9357ea2046f8dc6354f0c5295f342bb417d3cfeb0b1fd33622c29e14cbbd92e1363c65ebd4504b7512329b9670e32e1b2c67a54e7f1a55f8b9f9ea04e8ca3a705e62a3c5e637374afb7aeb6ddea612cde28f01a202d7aa4e34722d27dd3f9b89894d019fd5d4d7119efe3723bba104cb8bb0981e074de3afe200daaaead826cc45f244dbf431afab34efbdf782474d2fd57118f646214934ed99cba3b003e8d67a3836f6f19fc41910ce5163ee3ae99eb84d514eb761e63684ea56f9791d2dd4aac6e6168b948c817f75a222acb0e8cdc03cc4afe8f67157e1a363b7faeff9f172b98913677c5a1dd085e9ee4c22052c1af58193116673dcd3bfc5f34b855dcc6c77885649e9e71f43d4aea0f4b72ca7eda0578ba13d31a658d2d060a9a66ff69ed1be7997a2fb1d2723d38f9bfabe18f8e7b3cda906e4e9b5e942c8eaeb296070ebfd364947a940cc978bed66b37749e6d5dcd7be8c494440e2b84cecfefb98c0bedfb3c41e3359d2cd7197fbe720c48aa6c6b6465c1ee63e3569c2adc744491370b7f7826fe0b77a1d19d64101d032b918106b42d2ef73747e5601fe4ba50f23ede521f031a817d15294a43722e8378784b6db0cf1ba9e8ae911d9201b9ce9cc3019c6f5c27cb98da26144b64225a7c932b30f761e78a2d59a1d8b83ec6344a2f6dd47e765706d00bf4a79a6a926c3ba91d812c8f2c797ab1796709e5d16856778293529f0286d015c3b5399619642a333e9e593d6e3f5353994208e9e6a332851d7f652522a928b917e27e2d6d42137dfe2ebfa6fb1c67b26c0254528685f7ebdbe315a68eaa2da769e8a9f42d3e60007c71330926b2c0012d83ead4e4fd1ed872ccd1972201d2b027f3545ac2d30cd78bc1d740feccbc6fc2a0446c6e30eac51f5a69098aa2d447f2085b4e4e4b92ccc26921d2de478518cd090ce267aea2d27ada57fd88b4976d89fb843cdccf49a76ca2679e6801bfa7fb031896fb50629704b9923936bb5dd385311121cadfb11995e59b73034cf67ed03ab813867648d025828087e949a9afd16b95d72d99b1edca257aac132ffb7a0709aed5a9c0ff05fb0f2bbf28409eed7b5f5801be964ced019e1cb7851d3851f10290674e19ffb008b301c4acf641a2bb14216e1d69cabf52b5ef227496b0f30799a855d117fad3744a6fa33503ea798b52ddd7ee5426609dbfcd3f0c13b164d6c051f7ed4a119719a712e388d328402081ff1354b554d2c237afed3b151c4ba8e9f4bdeb8499a3066e26bbc69e8af089dec71731d1dc529eab17ef7374734c0fe475494c83836bdd34a03b9bc89914716061bfb98ec6e61c3ed4438edcaf25243c647086b9ea7018b0d9a8a0b00cecb00abde2498d69c2336101a772cbe4f571523f51bd05882cdf358b849cc140aa1faf22423a12851ce0e33fd48975a4959fa5c5fe418c93908191ab6e741b77bfe02cbd698ee795c466d615619e6441382c6eac01834ee9ab73cea80bbe235c78da91bd79b6f82f899785d68700d393e675c2224d6b7a1ad21320495679adaed70167b50866713a53109db7b6f7d81304ecdfd83b319b1ef248306b45ad29e7ddcc863dac56048b5d69ea175011f7614c00a86a863cde1872a8932878b9ac7e1ac5bda4997b72064f0cd75f4c814e034de11acb9013cf7ea926b4e7eaace070c7ba2188efad2e431e1223d45dd05c4d8403c2e45cee6413ecbe7527e873e455c4e610a61839aacc0bd56d2483e78f298b66a478eb2f558cbafca86be847baeb02c5b216c8cd88fea4df249b09e670a20703abac24b0a91abc4a5646601442ba10becfd30993880051d07f56a05a9379e7a8e6befee3f22faa106398f7706006e42e9be1ef89d25c272f11a95095c587d713732284de9dbd3c7217b0689e21d8eb0ff69668";
    let encoded_privkey = tyst_encdec::hex::decode(&encoded_privkey_hex).unwrap();
    let encoded_signature_hex = "9d7e2c681d27aba1f4170f76c39e513ff02ce919f7e742742ccc96b7caecf3b29c416bdbe298c71cfbab2d52653d54dba743ca4f1337352b6b3ffa659403525628953ec98dd591b24c08389e033bd445fe277caff6644bcd2272ef44014be790e86de215e99e19583940d1af2758f1e77098038cc87e1a5e59de5f27f723bffe75dfd8731acc160b7cacf30c8561d9eca80ec062ff45ac54cd14232e47092df30088cdaa3de269258d6e535dd3d32ea4e14f877d2290718c5f138fda0b4e890ea3a49783a04119d9c530e329bbf8cc4fcd6909aa0f9654c7cbb5442536b97c1bff2dd955d87cc25df927d63538ecf07c9f1f77fcb6a6e39572fb3844b46317b7cbc5c4a3d47a668723d99b35f8c108c4e9aff54c20452a1337bfadab51aaf02f8c5095fbed943d4cda86dacb64880eee2e4a33722a93a44112e432de902fc66fc2d06925b786cfc810abf109eba1b65ca7b073b01f394517baaa6c1ae2758cdd28cd25fdc73db12a62a1f15bda8fa1b2e1f2ce9a1758843d963998ca8b7762c1950b83e0c67c1e5b00952fb5af56747373e0f132be9f9727e18dda543c41b051c74e90a26ab254bd0ceee8d67b05b3808d4ea2ff44a4bead0b03a49702856d671d38bf14aae79084f52ddba78b43f95acbb25b834804c7323a69c18d1d99b33d53cbaebfbb0f067c5d219d15c82bca16740432815ba03900e612e6d22d76f471b2b38dcfd828aa4f38beaccc9fd5a93ffa0e662a3f0635d0942bfc91c2aade4a7d2fdcd74db8564b07ddd3d5b8877fb851877e8b7572aed164d20af0b68a391b0921922eac5a5a4910b80f402ab9ac214cc0fb21ddc148fc26ccd8fb2505c2df4209c585c6073411f0b2f8cf7f7f5fbb17c65b670a0a35eb8cedf89699ce52846648ce726a179adb397363d7838f11751fae16cc679e7a79b3f1caca75003d9443c7c17e8cc16a2e11c397d37760078ed2f0c79879e406f967216bb173e0077e4f6afd037776c2d0e06c2883d8c674ed93f5780f8f09b5e54e0d240e2c4ec2632d6cf4f46c16899271a78ab143d7da4a9c5eb520618d35c2854534b4a36d2126565a36fe6d9bb0348ef5c1063997abd32d20939b996912daf441b594fffe90c7531a2413f19e8f64db5b7b401949c9a34decb93bcc67deb225264fff413428e40676619bc0d77bcb15ceb03ab3a686bf5be3ff4d3decfd32568769793887d44630727c5b15cc9ecbf53f7c47019eb9e4591a1fd3aed2bbd07ae48660cf463a76be45fbbc80054acad16b6df98cc3a29a8e523fd1d347608aaa34bb5537e4bbf65c997cba1bfaa04c72bd758b9c7be3614ee3ebad0c317053fc452bb2d9aaac56a2b5033e9622d5c15042df77f1e6436e38ef2b3867607005140fea9e603da38285dc92d5f30b241a67edccabc20655f14329764f4a4637c75f6e4933ce6fc274e6860aa48f39d7e5b6724a7e80a420e190ea158aaab4c99445a3c50065e9fe04c7541d4865c947c09203d66e1029e132c85f8d15c3d37fed8f5055e6a2cc634a8eeab9928138907851f392a9d9c058654ddd7e99d1137c0191d0cc99657bed8421ef171dc6e1fc9e39b48044c7d6ac7483276d8fbdd3d0ec3d4f287a6fd13617ddd63abc3f6943e581c62e6a46acda30c0e0156af34c992b9ea2757962a202062d76d9a44dffe8e20611c96e47f8cb81a30e334d46c7f39272a20893dce0559299ecf761af07b1ea85c43b9c183ebeb312b6e0244fbfdf568fa1758554db217c77073eeba16fb7e49691bb6ade8864dd347265feddc2684d71eee60b075c197f9f526179502218ee9fa52b2541ddbbbbc53d7cc72330e51b6e1d25d8121940895a2495fbdd99a1edd94f3cce1529f2f57d66666bbd4c90857fcd5e15e94220804efcc7739a14b5b96022bbcef9819fe34115ac7f99741c66fe460bf2d3a52a9b56e17aacf271469d2ce2e7248ff79073690ed2fed2031752a8dc95cb3f1292f14194324ec839dbc5a92e29f77d7047c876f0525dd5cf9374c8b2a64ad6d4d100d785bfc85604f2797cfb9e9cb01ff0f4c1304e47f5cd9cc356fb2614ddd01421b1c1dff5fa0289a2a63084cfc67cee995c881fcebc82f561d490532180f344a42ec7ca59b0e198871b8b8c79dbb061c245e37d70d8a89e647becacc0a066ba2bb7edc0e84ddd3fdc23044f8f1d1258cdf647fa449535d149fb051ff4831980d0b016876429a5ed318e9bbee298b1a3aba33f4277eb03a808e9e63c518bccdb7b4fe05dffa85f4f5d43e7251d7a65a938ba0fa86a973b396fed6b3c76c93eacf5d76892e306957d27250e819c008342062d6cf558bb3bf9a7806c07dcd6b6d2dffe333d10e983fb8129bfa1b230706637a36060747307e831f0eedb49673218a8c80f62b3c742bfde4074ecdecd33d969fe340e1301ba2eed2afaabd32ebe0dfce248924e6859ddb0d3b590f2a8046b89f981fbb02e84439eed756723f96ec811bf51eaf2bbb7ed8cd1812381d5768d09ca8c4c954f8fb1e94892ff9c16d0c3bf65a5858db39b2ac7962621a5682ce844642b694ed05fac1d685dd07fc529b05b8d20074470fb19434277b2b416db7cf62027318e71841c22e7787dac5c550bfeaa39be432efbf7dccfcc2fdc9c2861a2f738de4e4928a26e14195f6d10c8e1bddb5befbe583555a063209b437cdef3e2b86a290ee49738bd13477affc2d116fbb90f073daf922458acede2660de659fe80079ce14d7b00e1ba8cfb3f72e3f757362a5ac39bfeb74e3524ed17d77327c3d5005e77e750bb6bcd8dfc98fb1a34e235b4fe9230f9737f627949274891d422320901cd94d4a150aac2b436fe88550246522b0cd776d5885b235a2b4752f635ce5778b1b36bdaef3e2b794276a707bcc12ffc7244f1fb833eca38f93db4474ad9d74f2910545ddf354fafd9ab4ca3705ae2126b1723e90c985e628320ae6810908ac5cf72c5abc915e367522536da8ba04cfc9de0e0eb46da4f2bc84c1b9b5822366b8a42f452182405d0144adb5722a81d97ae8b323223a13764947e13723708226174ad902e76660f234942c6cc18eba7a7d0d55b71f3cacb75c3cf941a5984b9665ab2fdc14517c5e76f7c0fecd6c76657a2a6f82a0b3dd594ec72f8f27dac39a72be8257982da882bfca47d637c9772468a75f9322666074ac7fe1c136de6efd98f722663ace3013f82ca610e01393e389213cd12b8983287278ffec52254d3bd75735879fed0a6289449e4cc2d2b32bf1bf335aed03f5cfa9e91ce67bd06343ecc5c88c38bbcae92171778607f01031325273842506983999ba0afdadbf3112e343c5c738085969ca3abb6e5e9f80d1184a1a3d4040c19222e323a4158646a777a7c7f899194a9abaeb2bbd4dbf0f7fd0000000000000000000000000011212743";
    let encoded_signature = tyst_encdec::hex::decode(&encoded_signature_hex).unwrap();
    //let fixed_random = (0..1024*1024).into_iter().map(|i|u8::try_from(i%256).unwrap()).collect::<Vec<_>>();
    let fixed_random = vec![0u8; 1024 * 1024];
    let random: Box<dyn SecureRandom> = Box::new(FixedSecureRandom::new(&fixed_random));
    let mut se = MldsaEngine::new("ML-DSA-44", Some(random));
    let public_key = MldsaPublicKey::new(&encoded_pubkey);
    let private_key = MldsaPrivateKey::new(
        &Arc::new(MldsaParams::by_name("ML-DSA-44")),
        &&encoded_privkey,
    );
    let signature = se.sign(&private_key, message).unwrap();
    assert_eq!(signature, encoded_signature);
    let verify = se.verify(&public_key, &encoded_signature, message);
    assert!(verify);
}
/*
*/

#[test]
fn test_key_generation() {
    crate::test::common::init_logger();
    let acvp_tests = acvp::get_acvp_test_data(
        "https://github.com/usnistgov/ACVP-Server/raw/refs/tags/v1.1.0.37/gen-val/json-files/ML-DSA-keyGen-FIPS204/internalProjection.json"
    )
    .unwrap();
    let mut test_counter = 0;
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
                    test_counter += 1;
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
    log::info!(
        "Checked {test_counter} '{}' test vectors.",
        acvp_tests.get_mode()
    );
}

#[test]
fn test_signature_generation() {
    crate::test::common::init_logger();
    let acvp_tests = acvp::get_acvp_test_data(
        "https://github.com/usnistgov/ACVP-Server/raw/refs/tags/v1.1.0.37/gen-val/json-files/ML-DSA-sigGen-FIPS204/internalProjection.json"
    )
    .unwrap();
    let mut test_counter = 0;
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
                    test_counter += 1;
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
    log::info!(
        "Checked {test_counter} '{}' test vectors.",
        acvp_tests.get_mode()
    );
}

#[test]
fn test_signature_verification() {
    crate::test::common::init_logger();
    let acvp_tests = acvp::get_acvp_test_data(
        "https://github.com/usnistgov/ACVP-Server/raw/refs/tags/v1.1.0.37/gen-val/json-files/ML-DSA-sigVer-FIPS204/internalProjection.json"
    )
    .unwrap();
    let mut test_counter = 0;
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
                    test_counter += 1;
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
    log::info!(
        "Checked {test_counter} '{}' test vectors.",
        acvp_tests.get_mode()
    );
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
