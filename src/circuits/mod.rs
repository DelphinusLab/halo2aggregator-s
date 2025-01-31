pub mod samples;
pub mod utils;

#[test]
fn test_sample_circuit() {
    use crate::circuits::samples::simple::SimpleCircuit;
    use crate::circuits::utils::run_circuit_unsafe_full_pass_no_rec;
    use crate::circuits::utils::TranscriptHash;
    use halo2_proofs::pairing::bn256::Bn256;
    use halo2_proofs::pairing::bn256::Fr;
    use std::fs::DirBuilder;
    use std::path::Path;

    let target_circuit_k = 16;
    let path = "./output";

    DirBuilder::new().recursive(true).create(path).unwrap();

    let (circuit, instances) = SimpleCircuit::<Fr>::random_new_with_instance();

    let path = Path::new(path);
    let _ = run_circuit_unsafe_full_pass_no_rec::<Bn256, _>(
        path,
        "simple-circuit",
        target_circuit_k,
        vec![circuit],
        vec![instances],
        vec![],
        TranscriptHash::Poseidon,
        vec![],
        vec![],
        vec![vec![1]],
        true,
    )
    .unwrap();
}

#[test]
fn test_two_sample_circuits() {
    use crate::circuits::samples::simple::SimpleCircuit;
    use crate::circuits::utils::run_circuit_unsafe_full_pass_no_rec;
    use crate::circuits::utils::TranscriptHash;
    use halo2_proofs::pairing::bn256::Bn256;
    use halo2_proofs::pairing::bn256::Fr;
    use std::fs::DirBuilder;
    use std::path::Path;

    let target_circuit_k = 16;
    let path = "./output";

    DirBuilder::new().recursive(true).create(path).unwrap();

    let (circuit, instances) = SimpleCircuit::<Fr>::random_new_with_instance();

    let path = Path::new(path);
    let _ = run_circuit_unsafe_full_pass_no_rec::<Bn256, _>(
        path,
        "simple-circuit",
        target_circuit_k,
        vec![circuit.clone(), circuit],
        vec![instances.clone(), instances],
        vec![],
        TranscriptHash::Poseidon,
        vec![[0, 0, 1, 0]],
        vec![],
        vec![vec![1], vec![1]],
        true,
    )
    .unwrap();
}
