use circuits::samples::simple::SimpleCircuit;
use circuits::utils::run_circuit_unsafe_full_pass;
use circuits::utils::TranscriptHash;
use halo2_proofs::pairing::bn256::Bn256;
use halo2_proofs::pairing::bn256::Fr;
use std::fs::DirBuilder;
use std::path::Path;

#[macro_use]

pub mod api;
pub mod circuits;
pub mod native_verifier;

fn main() {
    let path = "./output";
    DirBuilder::new().recursive(true).create(path).unwrap();

    let path = Path::new(path);
    let (circuit, instances) = SimpleCircuit::<Fr>::random_new_with_instance();
    run_circuit_unsafe_full_pass::<Bn256, _>(
        path,
        "simple-circuit",
        8,
        circuit,
        instances,
        TranscriptHash::Blake2b,
    );
}
