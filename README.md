# jolt-zkguard

This repository contains a Jolt-based port of the ZKGuard policy engine. The original
RISC Zero guest has been reworked to run inside the Jolt zkVM, while keeping the
policy verification logic and Merkle proof checks intact.

## Workspace layout

- `core/` — Shared policy types, hashing helpers, and Merkle utilities.
- `guest/` — The Jolt guest program (`zkguard_policy`) that verifies policy compliance.
- `src/main.rs` — Host harness that constructs a sample policy + user action and
  produces/verifies a Jolt proof.

## Running the host example

```bash
cargo run
```

The host will:
1. Build a sample policy and Merkle proof.
2. Compile the Jolt guest.
3. Prove the policy compliance execution.
4. Verify the proof.
