# halo2aggregator-s

Aggregator for halo2 plonk circuits, including:
1. Provide aggregation circuit for target circuit verification.
2. Provide solidity code for aggregation circuit verification.

## Prerequisite
1. truffle

## Try it on local testnet
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
truffle test
```

## Try it on Goerli
```
cargo test test_solidity_render --release -- --nocapture

cd sol
yarn

# add INFURA_PROJECT_ID, MNEMONIC in .env file

# NOTICE!!! This command would spend about 0.025 Goerli ETH for deployment
truffle test --goerli
```

## Use as lib
The solidity code generation depends on the `sol` folder. You can download it from `https://github.com/DelphinusLab/halo2aggregator-s/releases/download/0.0.2-alpha/halo2aggregator-s.sol-template.zip`.

1. call `run_circuit_unsafe_full_pass()` for target circuit with `TranscriptHash::Poseidon` to get aggregation circuit and its instances.
2. call `run_circuit_unsafe_full_pass()` for aggregation circuit with `TranscriptHash::Sha` to create aggregation circuit proof.
3. call `solidity_render()` with `TranscriptHash::Sha` to generate solidity code.
4. call `solidity_aux_gen()` to prepare aux input for solidity verify. It will prepare scalar division result used by the verification to reduce gas.

See test `test_solidity_render` for sample.
