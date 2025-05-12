/*
    Copyright 2025 MydriaTech AB

    Licensed under the Apache License 2.0 with Free world makers exception
    1.0.0 (the "License"); you may not use this file except in compliance with
    the License. You should have obtained a copy of the License with the source
    or binary distribution in file named

        LICENSE-Apache-2.0-with-FWM-Exception-1.0.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.
*/

//! Binary digest tree structure with dynamic hash algorithm support.

use tyst_encdec::hex::ToHex;
use tyst_traits::digest::Digest;

/// Proof for a member of the [BinaryDigestTree].
pub struct BinaryDigestTreeProof {
    digest_algorithm_oid: Vec<u32>,
    /// The output size of the digest
    digest_size_bytes: usize,
    /// Serialized as an array of hashes where the lenght of each depends on the
    /// used digest algorithm.
    encoded_proof: Vec<u8>,
}

impl std::fmt::Display for BinaryDigestTreeProof {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Print proof as pair of hashes
        for (i, hash) in self
            .encoded_proof
            .chunks(self.digest_size_bytes)
            .enumerate()
        {
            if i % 2 == 0 {
                writeln!(f, "{}", hash.to_hex())?;
            } else {
                write!(f, "{} ", hash.to_hex())?;
            }
        }
        Ok(())
    }
}

impl BinaryDigestTreeProof {
    /// Return a new instance.
    pub fn new(
        digest_algorithm_oid: &[u32],
        digest_size_bytes: usize,
        encoded_proof: &[u8],
    ) -> Self {
        Self {
            digest_algorithm_oid: digest_algorithm_oid.to_vec(),
            digest_size_bytes,
            encoded_proof: encoded_proof.to_vec(),
        }
    }

    /// The used digest algorithm.
    pub fn get_digest_algorithm_oid(&self) -> &[u32] {
        &self.digest_algorithm_oid
    }

    /// Encoded proof.
    pub fn get_encoded_proof(&self) -> &[u8] {
        &self.encoded_proof
    }
}

/// Simple Merkle Tree inspired binary digest tree structure with dynamic hash
/// algorithm support.
pub struct BinaryDigestTree {
    bottom_up_layers: Vec<Vec<Vec<u8>>>,
}

impl std::fmt::Display for BinaryDigestTree {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for (i, x) in self.bottom_up_layers.iter().enumerate() {
            writeln!(f, "{i}")?;
            for (j, y) in x.iter().enumerate() {
                writeln!(f, " {j}: {}", y.as_slice().to_hex())?;
            }
        }
        Ok(())
    }
}

impl BinaryDigestTree {
    /// Return a new instance.
    pub fn new(mut digest: Box<dyn Digest>, members: &[&[u8]]) -> Self {
        let layer_count = Self::layer_count_from_leaf_count(members.len());
        let mut bottom_up_layers = Vec::with_capacity(layer_count);
        bottom_up_layers.push(
            members
                .iter()
                .map(|data| Self::hash_leaf(digest.as_mut(), data))
                .collect::<Vec<_>>(),
        );
        if members.is_empty() {
            bottom_up_layers.push(vec![Self::hash_empty(digest.as_mut())]);
        } else {
            for i in 1..layer_count {
                bottom_up_layers.push(
                    bottom_up_layers
                        .get(i - 1)
                        .unwrap()
                        .chunks(2)
                        .map(|x| {
                            let left = x[0].as_slice();
                            let right = if x.len() > 1 {
                                Some(x[1].as_slice())
                            } else {
                                None
                            };
                            Self::concat_and_hash(digest.as_mut(), left, right)
                        })
                        .collect::<Vec<_>>(),
                )
            }
        }
        //let digest_algorithm_oid = digest.get_algorithm_oid().expect("Only digests with a defined OID can be used in this structure.");
        Self { bottom_up_layers }
    }

    /// Return the tree's root hash
    pub fn root_hash(&self) -> &[u8] {
        self.bottom_up_layers.last().unwrap().first().unwrap()
    }

    /// Return a proof that `member` is covered by this strucuture.
    pub fn proof(&self, digest: &mut dyn Digest, member: &[u8]) -> BinaryDigestTreeProof {
        let mut proof = vec![];
        let mut next_hash = Self::hash_leaf(digest, member);
        for layer in &self.bottom_up_layers[..self.bottom_up_layers.len() - 1] {
            if let Some(pos) = layer.iter().position(|h| next_hash.eq(h)) {
                let (left, right) = if pos % 2 == 0 {
                    (layer.get(pos).unwrap(), layer.get(pos + 1))
                } else {
                    (layer.get(pos - 1).unwrap(), layer.get(pos))
                };
                next_hash = Self::concat_and_hash(digest, left, right.map(|right| right as &[u8]));
                if let Some(right) = right {
                    proof.push(right);
                }
                //proof.push(right.unwrap_or(&none_marker));
                proof.push(left);
            } else {
                panic!("Unable to find '{}' in tree.", next_hash.to_hex());
            }
        }
        proof.push(&next_hash);
        proof.reverse();
        let encoded_proof = proof
            .into_iter()
            .flat_map(|x| x.clone())
            .collect::<Vec<_>>();
        let digest_algorithm_oid = digest
            .get_algorithm_oid()
            .expect("Only digests with a defined OID can be used in this structure.");
        BinaryDigestTreeProof {
            digest_algorithm_oid,
            digest_size_bytes: digest.get_digest_size_bits() >> 3,
            encoded_proof,
        }
    }

    /// Return the root hash if the member is present in the proof.
    pub fn root_hash_for_member(
        digest: &mut dyn Digest,
        proof: &BinaryDigestTreeProof,
        member: &[u8],
    ) -> Option<Vec<u8>> {
        let hashes_top_down = proof
            .get_encoded_proof()
            .chunks(digest.get_digest_size_bits() / 8)
            .collect::<Vec<_>>();
        let root_hash = hashes_top_down.first().cloned().unwrap();
        let mut previous_left = root_hash;
        let mut previous_right: Option<&[u8]> = None;
        let hashes = hashes_top_down.into_iter().skip(1).collect::<Vec<_>>();
        let mut skip_next = false;
        for i in 0..hashes.len() {
            if skip_next {
                skip_next = false;
                continue;
            }
            let left = hashes.get(i).unwrap();
            if let Some(potential_right) = hashes.get(i + 1) {
                let check = Self::concat_and_hash(digest, left, Some(potential_right));
                if Self::is_matched_by_either_previous(&check, previous_left, previous_right) {
                    // Potential right was correct, step over it
                    skip_next = true;
                    previous_right = Some(potential_right);
                } else {
                    let check = Self::concat_and_hash(digest, left, None);
                    if Self::is_matched_by_either_previous(&check, previous_left, previous_right) {
                        previous_right = None;
                    } else {
                        return None;
                    }
                }
            } else {
                let check = Self::concat_and_hash(digest, left, None);
                if Self::is_matched_by_either_previous(&check, previous_left, previous_right) {
                    previous_right = None;
                } else {
                    return None;
                }
            }
            previous_left = left;
        }
        let leaf_check = Self::hash_leaf(digest, member);
        if Self::is_matched_by_either_previous(&leaf_check, previous_left, previous_right) {
            Some(root_hash.to_vec())
        } else {
            None
        }
    }

    /// Return `true` if the `check` matches either `previous_left` or `previous_right`
    fn is_matched_by_either_previous(
        check: &[u8],
        previous_left: &[u8],
        previous_right: Option<&[u8]>,
    ) -> bool {
        check.eq(previous_left)
            || previous_right.is_some_and(|previous_right| check.eq(previous_right))
    }

    fn layer_count_from_leaf_count(leaf_count: usize) -> usize {
        let leaf_count = if leaf_count == 1 { 2 } else { leaf_count };
        usize::try_from(leaf_count.next_power_of_two().trailing_zeros() + 1).unwrap()
    }

    fn hash_leaf(digest: &mut dyn Digest, data: &[u8]) -> Vec<u8> {
        Self::hash(digest, &[&[0x00u8], data])
    }

    fn concat_and_hash(digest: &mut dyn Digest, left: &[u8], right: Option<&[u8]>) -> Vec<u8> {
        if let Some(right) = right {
            Self::hash(digest, &[&[0x01u8], left, right])
        } else {
            Self::hash(digest, &[&[0x01u8], left])
        }
    }

    /// Specal case for useless tree with 0 leafs.
    fn hash_empty(digest: &mut dyn Digest) -> Vec<u8> {
        Self::hash(digest, &[&[0x01u8]])
    }

    fn hash(digest: &mut dyn Digest, data: &[&[u8]]) -> Vec<u8> {
        data.iter().for_each(|data| digest.update(data));
        let mut out = vec![0u8; digest.get_digest_size_bits() / 8];
        digest.finalize(&mut out);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::digest::sha3_digest::Sha3Digest;

    const TEST_MEMBERS_1: &[&[u8]] = &[
        &[1, 2, 3],
        &[4, 5, 6],
        &[7, 8, 9],
        &[10, 11, 12],
        &[13, 14, 15],
    ];

    fn init_logger() {
        let _ = env_logger::builder()
            .is_test(true)
            .filter_level(log::LevelFilter::Debug)
            .try_init();
    }

    #[test]
    fn allow_useless_empty_tree() {
        init_logger();
        let digest = Box::new(Sha3Digest::new(512));
        let digest_algorithm_oid =
            tyst_encdec::oid::as_string(&digest.get_algorithm_oid().unwrap());
        let bdt = BinaryDigestTree::new(digest, &[]);
        log::trace!("bdt: {bdt}");
        assert_eq!(
            bdt.root_hash().to_hex(),
            "c46af35fa4594a247543c33e52e17572f94c48d2bdc42e0a2e861b805a28820e762a493b9d2660247198bae31ac510903c282ee224f15003cfdfaf402a19cb91",
            "Wrong root hash of empty tree using '{digest_algorithm_oid}'."
        );
    }

    #[test]
    #[should_panic]
    fn proof_from_non_existing_member_should_panic() {
        init_logger();
        let digest = Box::new(Sha3Digest::new(512));
        let bdt = BinaryDigestTree::new(digest, &[&[4, 5, 6]]);
        log::trace!("bdt: {bdt}");
        let mut digest = Box::new(Sha3Digest::new(512));
        bdt.proof(digest.as_mut(), &[1, 2, 3]);
    }

    #[test]
    fn count_layers() {
        init_logger();
        (0..32usize).for_each(|leaf_count| {
            log::trace!(
                "leaf_count: {leaf_count}, levels, {}",
                BinaryDigestTree::layer_count_from_leaf_count(leaf_count)
            );
        });
        let test_data = [
            (0, 1),
            (1, 2),
            (2, 2),
            (3, 3),
            (4, 3),
            (5, 4),
            (8, 4),
            (9, 5),
            (16, 5),
            (17, 6),
            (32, 6),
            (33, 7),
        ];
        for (leaf_count, expected_layer_count) in test_data {
            assert_eq!(
                BinaryDigestTree::layer_count_from_leaf_count(leaf_count),
                expected_layer_count,
                "Incorrect number of layers derived from leaf count."
            );
        }
    }

    #[test]
    fn proof_from_small_tree() {
        init_logger();
        let digest = Box::new(Sha3Digest::new(512));
        let digest_algorithm_oid =
            tyst_encdec::oid::as_string(&digest.get_algorithm_oid().unwrap());
        let bdt = BinaryDigestTree::new(digest, TEST_MEMBERS_1);
        log::trace!("bdt: {bdt}");
        log::trace!("root: {}", bdt.root_hash().to_hex());
        let expected_root = Some(bdt.root_hash().to_vec());
        let mut digest = Box::new(Sha3Digest::new(512));
        for leaf in TEST_MEMBERS_1 {
            let proof = bdt.proof(digest.as_mut(), leaf);
            log::trace!("proof:\n{proof}");
            let mut digest = Box::new(Sha3Digest::new(512));
            let actual_root = BinaryDigestTree::root_hash_for_member(digest.as_mut(), &proof, leaf);
            assert_eq!(
                actual_root, expected_root,
                "Unable to verify membership of '{leaf:x?}' using {digest_algorithm_oid}!"
            );
        }
    }
}
