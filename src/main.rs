use anyhow::Result;
use dotenv::dotenv;
use jolt_sdk::UntrustedAdvice;
use k256::ecdsa::SigningKey;
use k256::elliptic_curve::rand_core::OsRng;
use rs_merkle::MerkleTree;
use std::collections::HashMap;
use tiny_keccak::{Hasher, Keccak};
use zkguard_core::{
    hash_policy_line_for_merkle_tree, AssetPattern, DestinationPattern, HexDecodeExt, MerklePath,
    PolicyLine, Sha256MerkleHasher, SignerPattern, TxType, UserAction,
    hash_user_action_for_signing,
};

// Build policy rules and Merkle tree from inputs and index. Returns (rules, merkle_path, merkle_root).
fn build_policy_and_merkle(
    usdt_addr: [u8; 20],
    usdc_addr: [u8; 20],
    from_addr: [u8; 20],
    amount: u128,
    leaf_index: usize,
) -> anyhow::Result<(Vec<PolicyLine>, MerklePath, [u8; 32])> {
    let rule_0 = PolicyLine {
        id: 1,
        tx_type: TxType::Transfer,
        destination: DestinationPattern::Any,
        signer: SignerPattern::Threshold {
            group: "Admins".to_string(),
            threshold: 1,
        },
        asset: AssetPattern::Exact(usdt_addr),
        amount_max: Some(amount),
        function_selector: None,
    };

    let rule_1 = PolicyLine {
        id: 2,
        tx_type: TxType::Transfer,
        destination: DestinationPattern::Allowlist("USDC-Allowlist".into()),
        signer: SignerPattern::Any,
        asset: AssetPattern::Exact(usdc_addr),
        amount_max: None,
        function_selector: None,
    };

    let rule_2 = PolicyLine {
        id: 3,
        tx_type: TxType::ContractCall,
        destination: DestinationPattern::Any,
        signer: SignerPattern::Exact(from_addr),
        asset: AssetPattern::Any,
        amount_max: None,
        function_selector: Some([0x7f, 0xf3, 0x6a, 0xb5]),
    };

    let rules = vec![rule_0, rule_1, rule_2];

    let hashed_leaves = rules
        .iter()
        .map(hash_policy_line_for_merkle_tree)
        .collect::<Vec<[u8; 32]>>();

    let tree: MerkleTree<Sha256MerkleHasher> = MerkleTree::from_leaves(&hashed_leaves);
    let proof = tree.proof(&[leaf_index]);
    let path_hashes: Vec<[u8; 32]> = proof.proof_hashes().to_vec();

    let merkle_path = MerklePath {
        leaf_index: leaf_index as u64,
        siblings: path_hashes.clone(),
    };

    let merkle_root: [u8; 32] = tree.root().expect("Merkle tree should have a root");

    Ok((rules, merkle_path, merkle_root))
}

/// ERC-20 transfer(address,uint256) function selector (big-endian).
const TRANSFER_SELECTOR: [u8; 4] = [0xa9, 0x05, 0x9c, 0xbb];

fn main() -> Result<()> {
    dotenv().ok();

    let sk = SigningKey::random(&mut OsRng);
    let pk_bytes = sk.verifying_key().to_encoded_point(false).as_bytes()[1..].to_vec();

    let mut hasher = Keccak::v256();
    let mut pk_hash = [0u8; 32];
    hasher.update(&pk_bytes);
    hasher.finalize(&mut pk_hash);
    let from_addr: [u8; 20] = pk_hash[12..].try_into()?;

    let to_addr = "12f3a2b4cC21881f203818aA1F78851Df974Bcc2".hex_decode()?;
    let usdt_addr = "dAC17F958D2ee523a2206206994597C13D831ec7".hex_decode()?;
    let usdc_addr = "A0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48".hex_decode()?;

    let amount: u128 = 1_000_000;
    let mut data = TRANSFER_SELECTOR.to_vec();
    data.extend([0u8; 12]);
    data.extend(&to_addr);
    data.extend([0u8; 16]);
    data.extend(&amount.to_be_bytes());

    let mut user_action = UserAction {
        from: from_addr,
        to: usdt_addr,
        value: 0,
        data,
        nonce: 0,
        signatures: vec![],
    };

    let message_hash = hash_user_action_for_signing(&user_action);
    let (signature, recovery_id) = sk.sign_prehash_recoverable(&message_hash)?;

    let mut sig_bytes = signature.to_bytes().to_vec();
    sig_bytes.push(recovery_id.to_byte());
    user_action.signatures = vec![sig_bytes];

    let selected_index = 0;
    let (rules, merkle_path, merkle_root) =
        build_policy_and_merkle(usdt_addr, usdc_addr, from_addr, amount, selected_index)?;
    let selected_rule = rules[selected_index].clone();

    let mut groups: HashMap<String, Vec<[u8; 20]>> = HashMap::new();
    groups.insert("Admins".to_string(), vec![from_addr]);

    let allows: HashMap<String, Vec<[u8; 20]>> = HashMap::new();

    let target_dir = "./target/jolt-guest";
    let mut program = guest::compile_zkguard_policy(target_dir);

    let shared_preprocessing = guest::preprocess_shared_zkguard_policy(&mut program);
    let prover_preprocessing = guest::preprocess_prover_zkguard_policy(shared_preprocessing.clone());
    let verifier_preprocessing = guest::preprocess_verifier_zkguard_policy(
        shared_preprocessing,
        prover_preprocessing.generators.to_verifier_setup(),
    );

    let prove_zkguard_policy = guest::build_prover_zkguard_policy(program, prover_preprocessing);
    let verify_zkguard_policy = guest::build_verifier_zkguard_policy(verifier_preprocessing);

    println!("Proving...");
    let (output, proof, program_io) = prove_zkguard_policy(
        merkle_root,
        UntrustedAdvice::new(user_action),
        UntrustedAdvice::new(selected_rule),
        UntrustedAdvice::new(merkle_path),
        UntrustedAdvice::new(groups),
        UntrustedAdvice::new(allows),
    );
    println!("Proved!");

    println!("Verifying...");
    let is_valid = verify_zkguard_policy(merkle_root, output, program_io.panic, proof);
    println!("Verified: {is_valid}");

    Ok(())
}
