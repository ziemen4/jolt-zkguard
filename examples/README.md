# ZKGuard Jolt examples

These examples mirror the original ZKGuard `risc0/examples` inputs, but use the
Jolt-based host/guest flow.

## Prover example

```bash
cargo run --example prover \
  --policy-file examples/policy.json \
  --groups-file examples/groups.json \
  --allowlists-file examples/allowlists.json \
  --rule-id 2 \
  --from 0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266 \
  --to 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48 \
  --value 0 \
  --data 0xa9059cbb000000000000000000000000111111111111111111111111111111111111111100000000000000000000000000000000000000000000000000000000000f4240 \
  --private-keys 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80 \
  --nonce 0
```

## Generating a trace

Use the `--trace-dir` flag to generate a Jolt execution trace in the provided directory.
When this flag is set, the example exits after writing the trace instead of running
the full proof:

```bash
cargo run --example prover -- \
  --trace-dir ./target/jolt-trace \
  --policy-file examples/policy.json \
  --groups-file examples/groups.json \
  --allowlists-file examples/allowlists.json \
  --rule-id 2 \
  --from 0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266 \
  --to 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48 \
  --value 0 \
  --data 0xa9059cbb000000000000000000000000111111111111111111111111111111111111111100000000000000000000000000000000000000000000000000000000000f4240 \
  --private-keys 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80 \
  --nonce 0
```
