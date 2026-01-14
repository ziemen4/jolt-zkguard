use bincode::Options;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::ops::Deref;

use zkguard_core::{
    MerklePath, PolicyLine, PublicCommitments, UserAction, hash_abi_encoded_user_action,
};

mod policy_engine;

/// Canonicalises a map of lists: sorts addresses ascending (dedup) and uses
/// a `BTreeMap` so keys are ordered. Returns `(canonical, bytes)` where
/// `bytes` is the bincode serialization of the canonical structure.
fn canonicalise_lists(
    raw: HashMap<String, Vec<[u8; 20]>>,
) -> (BTreeMap<String, Vec<[u8; 20]>>, Vec<u8>) {
    let mut canon: BTreeMap<String, Vec<[u8; 20]>> = BTreeMap::new();
    for (k, mut v) in raw {
        v.sort();
        v.dedup();
        canon.insert(k, v);
    }
    let bytes = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .serialize(&canon)
        .expect("canonical serialise");
    (canon, bytes)
}

/// Verifies a Merkle proof for a given leaf against a root.
fn verify_merkle_proof(root: &[u8], leaf_bytes: &[u8], proof: &MerklePath) -> bool {
    let mut computed_hash: [u8; 32] = Sha256::digest(leaf_bytes).into();
    let mut current_index = proof.leaf_index;

    for sibling_hash in proof.siblings.iter() {
        let mut combined = Vec::with_capacity(64);
        if current_index % 2 == 0 {
            combined.extend_from_slice(&computed_hash);
            combined.extend_from_slice(sibling_hash);
        } else {
            combined.extend_from_slice(sibling_hash);
            combined.extend_from_slice(&computed_hash);
        }

        computed_hash = Sha256::digest(&combined).into();
        current_index /= 2;
    }

    computed_hash.as_slice() == root
}

#[jolt::provable(memory_size = 1048576, stack_size = 65536, max_trace_length = 8388608)]
fn zkguard_policy(
    policy_merkle_root: [u8; 32],
    user_action: jolt::UntrustedAdvice<UserAction>,
    policy_line: jolt::UntrustedAdvice<PolicyLine>,
    policy_merkle_path: jolt::UntrustedAdvice<MerklePath>,
    groups: jolt::UntrustedAdvice<HashMap<String, Vec<[u8; 20]>>>,
    allow_lists: jolt::UntrustedAdvice<HashMap<String, Vec<[u8; 20]>>>,
) -> PublicCommitments {
    let user_action = user_action.deref();
    let policy_line = policy_line.deref();
    let policy_merkle_path = policy_merkle_path.deref();

    let bytes_policy_line = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .serialize(policy_line)
        .expect("serialize PolicyLine");

    let (groups_canon, groups_bytes) = canonicalise_lists(groups.deref().clone());
    let groups_sets: HashMap<String, HashSet<[u8; 20]>> = groups_canon
        .iter()
        .map(|(k, v)| (k.clone(), v.iter().copied().collect()))
        .collect();

    let (allow_canon, allow_bytes) = canonicalise_lists(allow_lists.deref().clone());
    let allow_sets: HashMap<String, HashSet<[u8; 20]>> = allow_canon
        .iter()
        .map(|(k, v)| (k.clone(), v.iter().copied().collect()))
        .collect();

    let proof_is_valid =
        verify_merkle_proof(&policy_merkle_root, &bytes_policy_line, policy_merkle_path);
    assert!(proof_is_valid, "merkle-proof-invalid");

    let allowed = policy_engine::run_policy_checks(
        policy_line,
        &groups_sets,
        &allow_sets,
        user_action,
    );
    assert!(allowed, "policy-violation");

    let call_hash: [u8; 32] = hash_abi_encoded_user_action(user_action);
    let groups_hash: [u8; 32] = Sha256::digest(&groups_bytes).into();
    let allow_hash: [u8; 32] = Sha256::digest(&allow_bytes).into();

    PublicCommitments {
        action_hash: call_hash,
        policy_root: policy_merkle_root,
        groups_hash,
        allow_hash,
    }
}
