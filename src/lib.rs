pub mod api;
pub mod circuit_verifier;
pub mod circuits;
pub mod gnark_verifier;
pub mod native_verifier;
pub mod solidity_verifier;
pub mod transcript;

pub use halo2ecc_s::circuit::pairing_chip::PairingChipOnProvePairingOps;
pub use halo2ecc_s::circuit::pairing_chip::PairingChipOps;
pub use halo2ecc_s::context::NativeScalarEccContext;

#[test]
fn test_batch_no_rec() {
    use circuits::samples::simple::SimpleCircuit;
    use circuits::utils::run_circuit_unsafe_full_pass_no_rec;
    use circuits::utils::TranscriptHash;
    use halo2_proofs::pairing::bn256::Bn256;
    use halo2_proofs::pairing::bn256::Fr;
    use std::fs::DirBuilder;
    use std::path::Path;

    let path = "./output";
    DirBuilder::new().recursive(true).create(path).unwrap();

    let path = Path::new(path);
    let (circuit1, instance1) = SimpleCircuit::<Fr>::random_new_with_instance();
    let (circuit2, instance2) = SimpleCircuit::<Fr>::random_new_with_instance();
    let (circuit, instances, shadow_instances, _) =
        run_circuit_unsafe_full_pass_no_rec::<Bn256, _>(
            path,
            "simple-circuit",
            8,
            vec![circuit1, circuit2],
            vec![instance1, instance2],
            vec![],
            TranscriptHash::Poseidon,
            vec![],
            vec![],
            vec![vec![1], vec![1]],
            true,
        )
        .unwrap();
    let circuit = circuit.circuit_without_select_chip.unwrap();

    run_circuit_unsafe_full_pass_no_rec::<Bn256, _>(
        path,
        "verify-circuit",
        22,
        vec![circuit],
        vec![vec![instances]],
        vec![vec![shadow_instances]],
        TranscriptHash::Blake2b,
        vec![],
        vec![],
        vec![vec![1]],
        true,
    );
}

#[test]
fn test_single_rec() {
    use crate::circuits::utils::calc_hash;
    use crate::circuits::utils::load_or_build_unsafe_params;
    use crate::circuits::utils::load_or_build_vkey;
    use crate::circuits::utils::load_proof;
    use crate::circuits::utils::AggregatorConfig;
    use crate::solidity_verifier::codegen::solidity_aux_gen;
    use crate::solidity_verifier::solidity_render;
    use ark_std::end_timer;
    use ark_std::start_timer;
    use circuits::samples::simple::SimpleCircuit;
    use circuits::utils::run_circuit_unsafe_full_pass;
    use circuits::utils::run_circuit_with_agg_unsafe_full_pass;
    use circuits::utils::TranscriptHash;
    use halo2_proofs::pairing::bn256;
    use halo2_proofs::pairing::bn256::Bn256;
    use halo2_proofs::pairing::bn256::Fr;
    use halo2_proofs::poly::commitment::ParamsVerifier;
    use sha3::Keccak256;
    use std::fs::DirBuilder;
    use std::path::Path;

    let path = "./output";
    DirBuilder::new().recursive(true).create(path).unwrap();

    let path = Path::new(path);
    let k = 22;

    let (circuit, target_instances) = SimpleCircuit::<Fr>::default_with_instance();

    println!("build agg 0");
    let mut config =
        AggregatorConfig::default_aggregator_config(TranscriptHash::Poseidon, vec![vec![1]], false);

    let (agg_l0, agg_l0_instances, agg_l0_shadow_instances, hash) =
        run_circuit_unsafe_full_pass::<Bn256, _>(
            path,
            "simple-circuit",
            k,
            vec![circuit.clone()],
            vec![target_instances.clone()],
            vec![],
            false,
            &config,
        )
        .unwrap();
    println!(
        "build agg 0 done, hash is {:?}, instance is {:?}",
        hash, agg_l0_instances
    );

    let mut hashes = vec![hash];
    let mut final_hashes = vec![agg_l0_instances[0]];

    let mut last_agg = agg_l0;
    let mut last_agg_instances = agg_l0_instances;
    let mut last_agg_shadow_instances = agg_l0_shadow_instances;

    let end_of_non_final_agg_idx = 2;
    for i in 0..=end_of_non_final_agg_idx {
        config.target_aggregator_constant_hash_instance_offset =
            vec![(1, 0, last_agg_instances[0])];
        config.absorb_instance = vec![(0, 0, 1, 1)];

        if i == end_of_non_final_agg_idx {
            config.is_final_aggregator = true;
            config.prev_aggregator_skip_instance = vec![(1, 7)];
            config.target_proof_max_instance = vec![vec![1], vec![7]];
            config.use_select_chip = false;
        }

        let last_agg_circuit = last_agg.circuit_with_select_chip.unwrap();
        let (agg, instances, shadow_instance, hash) =
            run_circuit_with_agg_unsafe_full_pass::<Bn256, _>(
                path,
                "simple-circuit",
                k,
                vec![circuit.clone()],
                vec![target_instances.clone()],
                last_agg_instances.clone(),
                last_agg_circuit,
                i,
                false,
                &config,
            )
            .unwrap();
        println!(
            "build agg {} done, hash is {:?}, instance is {:?}",
            i, hash, instances
        );

        if i != end_of_non_final_agg_idx {
            hashes.push(hash);
            final_hashes.push(instances[0]);
        }

        last_agg = agg;
        last_agg_instances = instances;
        last_agg_shadow_instances = shadow_instance;
    }

    let last_agg_circuit = last_agg.circuit_without_select_chip.unwrap();
    config.hash = TranscriptHash::Keccak;
    let final_agg_file_prex = format!("simple-circuit.agg.final");
    run_circuit_unsafe_full_pass::<Bn256, _>(
        path,
        &final_agg_file_prex,
        k,
        vec![last_agg_circuit.clone()],
        vec![vec![last_agg_instances.clone()]],
        vec![vec![last_agg_shadow_instances]],
        false,
        &config,
    );

    let params =
        load_or_build_unsafe_params::<Bn256>(k, Some(&path.join(format!("K{}.params", k))));
    let params_verifier: ParamsVerifier<Bn256> = params.verifier(1).unwrap();

    let vkey = load_or_build_vkey::<Bn256, _>(
        &params,
        &last_agg_circuit,
        Some(&path.join(format!("{}.0.vkey.data", final_agg_file_prex))),
    );

    let proof = load_proof(&path.join(format!("{}.0.transcript.data", final_agg_file_prex)));
    solidity_render::<_, Keccak256>(
        "sol/templates/*",
        "sol/contracts",
        vec![(
            "AggregatorConfig.sol.tera".to_owned(),
            "AggregatorConfig.sol".to_owned(),
        )],
        "AggregatorVerifierStepStart.sol.tera",
        "AggregatorVerifierStepEnd.sol.tera",
        |i| format!("AggregatorVerifierStep{}.sol", i + 1),
        config.hash,
        &params_verifier,
        &vkey,
        &last_agg_instances,
        proof.clone(),
    );

    solidity_aux_gen::<_, Keccak256>(
        &params_verifier,
        &vkey,
        &last_agg_instances,
        proof,
        &path.join(format!("{}.0.aux.data", final_agg_file_prex)),
    );

    let timer = start_timer!(|| "calc final hashes");
    let final_hashes_expected = calc_hash::<bn256::G1Affine>(
        hashes[0..3].try_into().unwrap(),
        hashes[0..3].try_into().unwrap(),
        1024,
    );
    end_timer!(timer);

    //println!("final_hashes_expected is {:?}", final_hashes_expected);
    assert_eq!(
        final_hashes_expected[0..final_hashes.len()],
        final_hashes[..]
    );
}
