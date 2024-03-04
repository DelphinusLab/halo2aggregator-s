pub mod api;
pub mod circuit_verifier;
pub mod circuits;
pub mod native_verifier;
pub mod solidity_verifier;
pub mod transcript;

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
    let (circuit, instances, _) = run_circuit_unsafe_full_pass_no_rec::<Bn256, _>(
        path,
        "simple-circuit",
        8,
        vec![circuit1, circuit2],
        vec![instance1, instance2],
        TranscriptHash::Poseidon,
        vec![],
        vec![],
        true,
    ).unwrap();

    run_circuit_unsafe_full_pass_no_rec::<Bn256, _>(
        path,
        "verify-circuit",
        22,
        vec![circuit],
        vec![vec![instances]],
        TranscriptHash::Blake2b,
        vec![],
        vec![],
        true,
    );
}

#[test]
fn test_single_rec() {
    use crate::circuits::utils::calc_hash;
    use crate::circuits::utils::AggregatorConfig;
    use ark_std::end_timer;
    use ark_std::start_timer;
    use circuits::samples::simple::SimpleCircuit;
    use circuits::utils::run_circuit_unsafe_full_pass;
    use circuits::utils::run_circuit_with_agg_unsafe_full_pass;
    use circuits::utils::TranscriptHash;
    use halo2_proofs::pairing::bn256;
    use halo2_proofs::pairing::bn256::Bn256;
    use halo2_proofs::pairing::bn256::Fr;
    use std::fs::DirBuilder;
    use std::path::Path;

    let path = "./output";
    DirBuilder::new().recursive(true).create(path).unwrap();

    let path = Path::new(path);
    let k = 22;

    let (circuit, target_instances) = SimpleCircuit::<Fr>::default_with_instance();

    println!("build agg 0");
    let mut config =
        AggregatorConfig::new_for_non_rec(TranscriptHash::Poseidon, vec![[0, 0, 0, 0]], vec![]);
    let (agg_l0, agg_l0_instances, hash) = run_circuit_unsafe_full_pass::<Bn256, _>(
        path,
        "simple-circuit",
        k,
        vec![circuit.clone()],
        vec![target_instances.clone()],
        false,
        &config,
    )
    .unwrap();
    println!(
        "build agg 0 done, hash is {:?}, instance is {:?}",
        hash, agg_l0_instances
    );

    let mut hashes = vec![hash];
    let mut final_hashes = vec![hash];

    let mut last_agg = agg_l0;
    let mut last_agg_instances = agg_l0_instances;
    for i in 1..5 {
        config.target_aggregator_constant_hash_instance_offset =
            vec![(1, 0, *final_hashes.last().unwrap())];
        let (agg, instances, hash) = run_circuit_with_agg_unsafe_full_pass::<Bn256, _>(
            path,
            "simple-circuit",
            k,
            vec![circuit.clone()],
            vec![target_instances.clone()],
            last_agg_instances,
            last_agg,
            i - 1,
            false,
            &config,
        )
        .unwrap();
        println!(
            "build agg {} done, hash is {:?}, instance is {:?}",
            i, hash, instances
        );
        hashes.push(hash);
        final_hashes.push(instances[0]);
        last_agg = agg;
        last_agg_instances = instances;
    }

    let t0_hash = hashes[0];
    let t1_hash = hashes[0];
    let t0_a0_hash = hashes[1];
    let t1_a0_hash = hashes[1];
    let t0_a1_hash = hashes[2];
    let t1_a1_hash = hashes[2];

    let timer = start_timer!(|| "calc final hashes");
    let final_hashes_expected = calc_hash::<bn256::G1Affine>(
        t1_hash, t0_hash, t1_a0_hash, t0_a0_hash, t1_a1_hash, t0_a1_hash, 1024,
    );
    end_timer!(timer);

    println!("final_hashes_expected is {:?}", final_hashes_expected);
    assert_eq!(final_hashes_expected[0..5], final_hashes[0..5]);
}
