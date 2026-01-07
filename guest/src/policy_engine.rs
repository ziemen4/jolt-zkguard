// SPDX-License-Identifier: Apache-2.0
// A minimal policy engine that evaluates on-chain user actions against a
// single, pre-verified policy line.

use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
use std::collections::{HashMap, HashSet};
use tiny_keccak::{Hasher, Keccak};
use zkguard_core::{
    AssetPattern, DestinationPattern, PolicyLine, SignerPattern, TxType, UserAction, ETH_ASSET,
    hash_user_action_for_signing,
};

/*───────────────────────────────────────────────────────────────────────────*
 * Helper utilities                          *
 *───────────────────────────────────────────────────────────────────────────*/

/// ERC-20 `transfer(address,uint256)` function selector (big-endian).
const TRANSFER_SELECTOR: [u8; 4] = [0xa9, 0x05, 0x9c, 0xbb];

/// Returns `true` if the calldata encodes an ERC-20 `transfer`.
fn is_erc20_transfer(data: &[u8]) -> bool {
    data.len() >= 4 && data[..4] == TRANSFER_SELECTOR
}

/// Attempts to parse an ERC-20 `transfer` call.
/// Returns `(to, amount)` on success.
fn parse_erc20_transfer(data: &[u8]) -> Option<([u8; 20], u128)> {
    if !is_erc20_transfer(data) || data.len() < 4 + 32 + 32 {
        return None;
    }

    let mut to = [0u8; 20];
    to.copy_from_slice(&data[4 + 12..4 + 32]);

    let mut amt_bytes = [0u8; 16];
    amt_bytes.copy_from_slice(&data[4 + 32 + 16..4 + 64]);
    let amount = u128::from_be_bytes(amt_bytes);

    Some((to, amount))
}

/// Evaluate an address against a *destination* pattern.
fn match_destination(
    pattern: &DestinationPattern,
    addr: &[u8; 20],
    groups: &HashMap<String, HashSet<[u8; 20]>>,
    lists: &HashMap<String, HashSet<[u8; 20]>>,
) -> bool {
    match pattern {
        DestinationPattern::Any => true,
        DestinationPattern::Exact(required_addr) => required_addr == addr,
        DestinationPattern::Group(name) => groups.get(name).map_or(false, |set| set.contains(addr)),
        DestinationPattern::Allowlist(name) => lists.get(name).map_or(false, |set| set.contains(addr)),
    }
}

/// Recovers the signer's address from a 65-byte (r||s||v) Ethereum-style
/// signature. Returns `None` on failure.
fn recover_signer(digest: &[u8; 32], signature: &[u8]) -> Option<[u8; 20]> {
    if signature.len() != 65 {
        return None;
    }
    let (rs, v_byte) = signature.split_at(64);
    let sig = Signature::try_from(rs).ok()?;

    let v = match v_byte[0] {
        27 => 0,
        28 => 1,
        v_val => v_val,
    };

    let rec_id = RecoveryId::try_from(v).ok()?;

    let vk = VerifyingKey::recover_from_prehash(digest, &sig, rec_id).ok()?;
    let pk = vk.to_encoded_point(false);

    let mut hasher = Keccak::v256();
    let mut keccak_hash = [0u8; 32];
    hasher.update(&pk.as_bytes()[1..]);
    hasher.finalize(&mut keccak_hash);

    let mut addr = [0u8; 20];
    addr.copy_from_slice(&keccak_hash[12..]);
    Some(addr)
}

/// Evaluate the signer against the signer pattern.
fn match_signer(
    pattern: &SignerPattern,
    ua: &UserAction,
    groups: &HashMap<String, HashSet<[u8; 20]>>,
) -> bool {
    let digest = hash_user_action_for_signing(ua);

    match pattern {
        SignerPattern::Any => !ua.signatures.is_empty(),
        SignerPattern::Exact(required_signer) => {
            if ua.signatures.len() != 1 {
                return false;
            }
            recover_signer(&digest, &ua.signatures[0])
                .map_or(false, |signer| &signer == required_signer)
        }
        SignerPattern::Group(name) => {
            if ua.signatures.len() != 1 {
                return false;
            }
            let group = groups.get(name).expect("missing group");
            recover_signer(&digest, &ua.signatures[0])
                .map_or(false, |signer| group.contains(&signer))
        }
        SignerPattern::Threshold { group, threshold } => {
            let required_group = groups.get(group).expect("missing group for threshold");
            let mut valid_signers = HashSet::new();

            for sig in &ua.signatures {
                if let Some(signer) = recover_signer(&digest, sig) {
                    if required_group.contains(&signer) {
                        valid_signers.insert(signer);
                    }
                }
            }
            valid_signers.len() >= *threshold as usize
        }
    }
}

fn match_asset(pattern: &AssetPattern, asset: &[u8; 20]) -> bool {
    match pattern {
        AssetPattern::Any => true,
        AssetPattern::Exact(addr) => addr == asset,
    }
}

fn classify_user_action(user_action: &UserAction) -> (TxType, [u8; 20], [u8; 20], u128) {
    if user_action.value > 0 || is_erc20_transfer(&user_action.data) {
        if user_action.value > 0 && user_action.data.is_empty() {
            (
                TxType::Transfer,
                user_action.to,
                ETH_ASSET,
                user_action.value,
            )
        } else {
            match parse_erc20_transfer(&user_action.data) {
                Some((to, amount)) => (TxType::Transfer, to, user_action.to, amount),
                None => panic!("malformed ERC-20 transfer data"),
            }
        }
    } else {
        (TxType::ContractCall, user_action.to, ETH_ASSET, 0)
    }
}

/*───────────────────────────────────────────────────────────────────────────*
 * The Policy Engine (Refactored)                                           *
 *───────────────────────────────────────────────────────────────────────────*/

/// Evaluates a `UserAction` against a single `PolicyLine`. Returns `true` if
/// the action is fully compliant with the rule.
pub fn run_policy_checks(
    rule: &PolicyLine,
    groups: &HashMap<String, HashSet<[u8; 20]>>,
    allowlists: &HashMap<String, HashSet<[u8; 20]>>,
    user_action: &UserAction,
) -> bool {
    let (tx_type, dest_addr, asset_addr, amount) = classify_user_action(user_action);

    if rule.tx_type != tx_type {
        return false;
    }

    if !match_destination(&rule.destination, &dest_addr, groups, allowlists) {
        return false;
    }

    if !match_signer(&rule.signer, user_action, groups) {
        return false;
    }

    if !match_asset(&rule.asset, &asset_addr) {
        return false;
    }

    if tx_type == TxType::Transfer {
        if let Some(max_amount) = rule.amount_max {
            if amount > max_amount {
                return false;
            }
        }
    }

    if tx_type == TxType::ContractCall {
        if let Some(function_selector) = rule.function_selector {
            if user_action.data.len() < 4 || user_action.data[..4] != function_selector {
                return false;
            }
        }
    }

    if tx_type == TxType::ContractCall && !matches!(rule.asset, AssetPattern::Any) {
        return false;
    }

    true
}
