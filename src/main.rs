#[macro_use]

pub mod api;
pub mod circuits;
pub mod native_verifier;
pub mod transcript;

pub fn main() {}

#[test]
fn test_single_one_pass() {
    use circuits::samples::simple::SimpleCircuit;
    use circuits::utils::run_circuit_unsafe_full_pass;
    use circuits::utils::TranscriptHash;
    use halo2_proofs::pairing::bn256::Bn256;
    use halo2_proofs::pairing::bn256::Fr;
    use std::fs::DirBuilder;
    use std::path::Path;

    let path = "./output";
    DirBuilder::new().recursive(true).create(path).unwrap();

    let path = Path::new(path);
    let (circuit, instances) = SimpleCircuit::<Fr>::random_new_with_instance();
    run_circuit_unsafe_full_pass::<Bn256, _>(
        path,
        "simple-circuit",
        8,
        vec![circuit],
        vec![instances],
        TranscriptHash::Blake2b,
        vec![],
    );
}

#[test]
fn test_single_one_pass_poseidon() {
    use circuits::samples::simple::SimpleCircuit;
    use circuits::utils::run_circuit_unsafe_full_pass;
    use circuits::utils::TranscriptHash;
    use halo2_proofs::pairing::bn256::Bn256;
    use halo2_proofs::pairing::bn256::Fr;
    use std::fs::DirBuilder;
    use std::path::Path;

    let path = "./output";
    DirBuilder::new().recursive(true).create(path).unwrap();

    let path = Path::new(path);
    let (circuit, instances) = SimpleCircuit::<Fr>::random_new_with_instance();
    run_circuit_unsafe_full_pass::<Bn256, _>(
        path,
        "simple-circuit",
        8,
        vec![circuit],
        vec![instances],
        TranscriptHash::Poseidon,
        vec![],
    );
}

#[test]
fn test_multi_one_pass() {
    use circuits::samples::simple::SimpleCircuit;
    use circuits::utils::run_circuit_unsafe_full_pass;
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
    run_circuit_unsafe_full_pass::<Bn256, _>(
        path,
        "simple-circuit",
        8,
        vec![circuit1, circuit2],
        vec![instance1, instance2],
        TranscriptHash::Blake2b,
        vec![],
    );
}

#[test]
fn test_multi_one_pass_poseidon() {
    use circuits::samples::simple::SimpleCircuit;
    use circuits::utils::run_circuit_unsafe_full_pass;
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
    run_circuit_unsafe_full_pass::<Bn256, _>(
        path,
        "simple-circuit",
        8,
        vec![circuit1, circuit2],
        vec![instance1, instance2],
        TranscriptHash::Poseidon,
        vec![],
    );
}