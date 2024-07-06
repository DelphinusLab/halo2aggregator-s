# halo2aggregator-s

Aggregator for halo2 plonk circuits, including:
1. Provide aggregation circuit for target circuit verification.
2. Provide solidity code for aggregation circuit verification.

## Prerequisite
1. truffle

## Try it on the local testnet
```
cargo test test_solidity_render --release -- --nocapture
```

In terminal 1:
```
cd sol
yarn
yarn start
```

In terminal 2:
```
cd sol
truffle test
```

## Try it on Goerli
```
cargo test test_solidity_render --release -- --nocapture

cd sol
yarn

# add INFURA_PROJECT_ID, MNEMONIC in .env file

# NOTICE!!! This command would spend about 0.025 GoerliETH for deployment
# This command is a little bit slow in my test env, please wait for several minutes
truffle test --goerli
```

## Use as lib
The solidity code generation depends on the `sol` folder. You can download it from the source code or release it according to the version.

1. call `run_circuit_unsafe_full_pass()` for target circuit with `TranscriptHash::Poseidon` to get aggregation circuit and its instances.
2. call `run_circuit_unsafe_full_pass()` for aggregation circuit with `TranscriptHash::Sha` or `TranscriptHash::Keccak` to create aggregation circuit proof.
3. call `solidity_render()` with `TranscriptHash::Sha` or `TranscriptHash::Keccak` to generate solidity code.
4. call `solidity_aux_gen()` to prepare aux input for solidity verify. It will prepare scalar division results used by the verification to reduce gas.

See test `test_solidity_render` for sample.

## Gnark Verifier
See test_gnark_render as an example.

```
cargo test test_gnark_render --release
cd gnark
go build && ./gnark-halo2-verify
mkdir -p sol/contracts
cp gnark_setup/contract_groth16.sol sol/contracts
cd sol
yarn
yarn start
```

Spawn a terminal under folder `gnark/sol`
```
npx truffle test
```

Notice
1. The instance of the gnark circuit is the keccak hash of the shadow instance, so compute it in your contract.
2. The transcript hash of the gnark circuit only supports sha256.
