use rasn::prelude::*;
use rasn::types::Integer;
use rasn::AsnType;
use rasn::Encode;

/// As defined in [RFC8017 Appendix A.2.3](https://datatracker.ietf.org/doc/html/rfc8017#appendix-A.2.3)
#[derive(AsnType, Clone, Debug, Encode, PartialEq, Eq, Hash)]
pub struct RsassaPssParams {
    #[rasn(tag(explicit(0)))]
    pub hash_algorithm: rasn_pkix::AlgorithmIdentifier,
    #[rasn(tag(explicit(1)))]
    pub mask_gen_algorithm: rasn_pkix::AlgorithmIdentifier,
    /// Should match length of hash algo
    #[rasn(tag(explicit(2)), default)]
    pub salt_length: Integer,
    /// Must be 1
    #[rasn(tag(explicit(3)), default)]
    pub trailer_field: Integer,
}
