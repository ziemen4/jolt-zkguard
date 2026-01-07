use anyhow::Result;
use clap::Parser;
use dotenv::dotenv;
use jolt_sdk::UntrustedAdvice;
use k256::ecdsa::SigningKey;
use rs_merkle::MerkleTree;
use std::collections::HashMap;
use std::fs::File;
use std::io::BufReader;
use zkguard_core::{
    hash_policy_line_for_merkle_tree, hash_user_action_for_signing, MerklePath, PolicyLine,
    Sha256MerkleHasher, UserAction,
};

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    #[clap(long)]
    policy_file: String,
    #[clap(long)]
    groups_file: String,
    #[clap(long)]
    allowlists_file: String,
    #[clap(long)]
    rule_id: u32,
    #[clap(long)]
    from: String,
    #[clap(long)]
    to: String,
    #[clap(long)]
    value: u128,
    #[clap(long)]
    data: String,
    #[clap(long, num_args = 1..)]
    private_keys: Vec<String>,
    #[clap(long)]
    nonce: u64,
    #[clap(long)]
    trace_dir: Option<String>,
}

fn parse_hex_address(hex_str: &str) -> Result<[u8; 20]> {
    let stripped = hex_str.strip_prefix("0x").unwrap_or(hex_str);
    let bytes = hex::decode(stripped)?;
    let mut arr = [0u8; 20];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

fn main() -> Result<()> {
    dotenv().ok();
    let args = Args::parse();

    let policy_file = File::open(args.policy_file)?;
    let reader = BufReader::new(policy_file);
    let policy: Vec<PolicyLine> = serde_json::from_reader(reader)?;

    let groups_file = File::open(args.groups_file)?;
    let reader = BufReader::new(groups_file);
    let json_groups: HashMap<String, Vec<String>> = serde_json::from_reader(reader)?;
    let groups: HashMap<String, Vec<[u8; 20]>> = json_groups
        .into_iter()
        .map(|(k, v)| {
            let addresses = v
                .into_iter()
                .map(|s| parse_hex_address(&s).unwrap())
                .collect();
            (k, addresses)
        })
        .collect();

    let allowlists_file = File::open(args.allowlists_file)?;
    let reader = BufReader::new(allowlists_file);
    let json_allowlists: HashMap<String, Vec<String>> = serde_json::from_reader(reader)?;
    let allowlists: HashMap<String, Vec<[u8; 20]>> = json_allowlists
        .into_iter()
        .map(|(k, v)| {
            let addresses = v
                .into_iter()
                .map(|s| parse_hex_address(&s).unwrap())
                .collect();
            (k, addresses)
        })
        .collect();

    let policy_index = policy
        .iter()
        .position(|p| p.id == args.rule_id)
        .ok_or_else(|| anyhow::anyhow!("Policy line with id {} not found", args.rule_id))?;
    let policy_line = policy[policy_index].clone();

    let from = parse_hex_address(&args.from)?;
    let to = parse_hex_address(&args.to)?;
    let data = hex::decode(args.data.strip_prefix("0x").unwrap_or(&args.data))?;
    let mut user_action = UserAction {
        from,
        to,
        value: args.value,
        nonce: args.nonce,
        data,
        signatures: vec![],
    };

    let message_hash = hash_user_action_for_signing(&user_action);

    let mut signatures: Vec<Vec<u8>> = Vec::new();
    for pk_hex in &args.private_keys {
        let sk =
            SigningKey::from_slice(&hex::decode(pk_hex.strip_prefix("0x").unwrap_or(pk_hex))?)?;
        let (signature, recovery_id) = sk.sign_prehash_recoverable(&message_hash)?;
        let mut sig_bytes = signature.to_bytes().to_vec();
        sig_bytes.push(recovery_id.to_byte() + 27);
        signatures.push(sig_bytes);
    }

    user_action.signatures = signatures;

    let mut hashed_leaves = policy
        .iter()
        .map(|pl| hash_policy_line_for_merkle_tree(pl))
        .collect::<Vec<[u8; 32]>>();

    let n = hashed_leaves.len();
    let pow2 = n.next_power_of_two();
    if pow2 > n {
        let last = *hashed_leaves.last().expect("at least one leaf");
        hashed_leaves.extend(std::iter::repeat(last).take(pow2 - n));
    }

    let tree: MerkleTree<Sha256MerkleHasher> = MerkleTree::from_leaves(&hashed_leaves);
    let root = tree.root().expect("Merkle tree should have a root");
    let proof = tree.proof(&[policy_index]);
    let path_hashes: Vec<[u8; 32]> = proof.proof_hashes().to_vec();

    let merkle_path = MerklePath {
        leaf_index: policy_index as u64,
        siblings: path_hashes.clone(),
    };

    if let Some(trace_dir) = args.trace_dir.as_deref() {
        guest::trace_zkguard_policy_to_file(
            trace_dir,
            root,
            UntrustedAdvice::new(user_action.clone()),
            UntrustedAdvice::new(policy_line.clone()),
            UntrustedAdvice::new(merkle_path.clone()),
            UntrustedAdvice::new(groups.clone()),
            UntrustedAdvice::new(allowlists.clone()),
        );
        println!("Trace written under {trace_dir}");
        return Ok(());
    }

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

    println!("[{}] Proving...", policy_line.id);
    let (output, proof, program_io) = prove_zkguard_policy(
        root,
        UntrustedAdvice::new(user_action),
        UntrustedAdvice::new(policy_line),
        UntrustedAdvice::new(merkle_path),
        UntrustedAdvice::new(groups),
        UntrustedAdvice::new(allowlists),
    );
    println!("[{}] Proved!", args.rule_id);

    println!("[{}] Verifying...", args.rule_id);
    let is_valid = verify_zkguard_policy(root, output.clone(), program_io.panic, proof);
    println!("[{}] Verified: {is_valid}", args.rule_id);
    println!("Action hash: 0x{}", hex::encode(output.action_hash));
    println!("Policy root: 0x{}", hex::encode(output.policy_root));
    println!("Groups hash: 0x{}", hex::encode(output.groups_hash));
    println!("Allow hash: 0x{}", hex::encode(output.allow_hash));

    Ok(())
}
