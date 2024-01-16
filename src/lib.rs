#[macro_use]
extern crate lazy_static;

pub mod api;
pub mod circuits;
pub mod transcript;

pub mod circuit_verifier;
pub mod native_verifier;
pub mod solidity_verifier;

#[test]
fn test_single_one_pass() {
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
    let (circuit, instances) = SimpleCircuit::<Fr>::random_new_with_instance();
    run_circuit_unsafe_full_pass_no_rec::<Bn256, _>(
        path,
        "simple-circuit",
        8,
        vec![circuit],
        vec![instances],
        TranscriptHash::Blake2b,
        vec![],
        vec![],
        true,
    );
}

#[test]
fn test_single_one_pass_with_verify_circuit() {
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
    let (circuit, instances) = SimpleCircuit::<Fr>::random_new_with_instance();
    let (circuit, instances, _) = run_circuit_unsafe_full_pass_no_rec::<Bn256, _>(
        path,
        "simple-circuit",
        8,
        vec![circuit],
        vec![instances],
        TranscriptHash::Poseidon,
        vec![[0, 0, 0, 0]],
        vec![],
        true,
    )
    .unwrap();

    run_circuit_unsafe_full_pass_no_rec::<Bn256, _>(
        path,
        "verify-circuit",
        20,
        vec![circuit],
        vec![vec![instances]],
        TranscriptHash::Blake2b,
        vec![],
        vec![],
        true,
    );
}

#[test]
fn test_single_one_pass_poseidon() {
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
    let (circuit, instances) = SimpleCircuit::<Fr>::random_new_with_instance();
    run_circuit_unsafe_full_pass_no_rec::<Bn256, _>(
        path,
        "simple-circuit",
        8,
        vec![circuit],
        vec![instances],
        TranscriptHash::Poseidon,
        vec![[0, 0, 0, 0]],
        vec![],
        true,
    );
}

#[test]
fn test_multi_one_pass() {
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
    run_circuit_unsafe_full_pass_no_rec::<Bn256, _>(
        path,
        "simple-circuit",
        8,
        vec![circuit1, circuit2],
        vec![instance1, instance2],
        TranscriptHash::Blake2b,
        vec![],
        vec![],
        true,
    );
}

#[test]
fn test_multi_one_pass_poseidon() {
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
    run_circuit_unsafe_full_pass_no_rec::<Bn256, _>(
        path,
        "simple-circuit",
        8,
        vec![circuit1, circuit2],
        vec![instance1, instance2],
        TranscriptHash::Poseidon,
        vec![],
        vec![],
        true,
    );
}

#[test]
fn test_rec_aggregator() {
    use circuits::samples::simple::SimpleCircuit;
    use circuits::utils::run_circuit_unsafe_full_pass;
    use circuits::utils::run_circuit_with_agg_unsafe_full_pass;
    use circuits::utils::TranscriptHash;
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
    let (agg_l0, agg_l0_instances, hash) = run_circuit_unsafe_full_pass::<Bn256, _>(
        path,
        "simple-circuit",
        k,
        vec![circuit.clone()],
        vec![target_instances.clone()],
        TranscriptHash::Poseidon,
        vec![[0, 0, 0, 0]],
        vec![],
        vec![],
        false,
        &vec![],
    )
    .unwrap();
    println!(
        "build agg 0 done, hash is {:?}, instance is {:?}",
        hash, agg_l0_instances
    );

    println!("build agg 1");
    let (agg_l1_jump, agg_l1_jump_instances, hash) =
        run_circuit_with_agg_unsafe_full_pass::<Bn256, _>(
            path,
            "simple-circuit",
            k,
            vec![circuit.clone()],
            vec![target_instances.clone()],
            agg_l0,
            agg_l0_instances,
            TranscriptHash::Poseidon,
            vec![[0, 0, 0, 0]],
            vec![],
            vec![],
            false,
            &vec![(1, 0, hash)],
            1,
        )
        .unwrap();

    println!("build agg 2");
    let (agg_l1_non_jump0, agg_l1_non_jump_instances0, hash) =
        run_circuit_with_agg_unsafe_full_pass::<Bn256, _>(
            path,
            "simple-circuit",
            k,
            vec![circuit.clone()],
            vec![target_instances.clone()],
            agg_l1_jump,
            agg_l1_jump_instances,
            TranscriptHash::Poseidon,
            vec![[0, 0, 0, 0]],
            vec![],
            vec![],
            false,
            &vec![(1, 0, hash)],
            2,
        )
        .unwrap();

    println!("build agg 3");
    let (agg_l1_non_jump1, agg_l1_non_jump_instances1, hash) =
        run_circuit_with_agg_unsafe_full_pass::<Bn256, _>(
            path,
            "simple-circuit",
            k,
            vec![circuit.clone()],
            vec![target_instances.clone()],
            agg_l1_non_jump0,
            agg_l1_non_jump_instances0,
            TranscriptHash::Poseidon,
            vec![[0, 0, 0, 0]],
            vec![],
            vec![],
            false,
            &vec![(1, 0, hash)],
            3,
        )
        .unwrap();

    println!("build agg 4");
    let (_, _, hash) =
        run_circuit_with_agg_unsafe_full_pass::<Bn256, _>(
            path,
            "simple-circuit",
            k,
            vec![circuit.clone()],
            vec![target_instances.clone()],
            agg_l1_non_jump1,
            agg_l1_non_jump_instances1,
            TranscriptHash::Poseidon,
            vec![[0, 0, 0, 0]],
            vec![],
            vec![],
            false,
            &vec![(1, 0, hash)],
            4,
        )
        .unwrap();

    println!("constant hash {:?}", hash);
}
