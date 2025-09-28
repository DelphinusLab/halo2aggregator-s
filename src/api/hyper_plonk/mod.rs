use self::builder::VerifierParamsBuilder;
use super::arith::AstPointRc;
use super::format_circuit_key;
use super::halo2::verifier::MultiOpenProof;
use super::transcript::AstTranscript;
use halo2_proofs::arithmetic::MultiMillerLoop;
use halo2_proofs::poly::commitment::ParamsVerifier;
use plonkish_backend::backend::hyperplonk::HyperPlonkVerifierParam;
use std::rc::Rc;

pub mod builder;

pub fn verify_single_proof_no_eval<E: MultiMillerLoop>(
    _params: &ParamsVerifier<E>,
    vk: &HyperPlonkVerifierParam<E::G1Affine>,
    index: usize,
    instances: &Vec<Vec<E::Scalar>>,
) -> (
    MultiOpenProof<E::G1Affine>,
    Vec<AstPointRc<E::G1Affine>>,
    Vec<(usize, AstPointRc<E::G1Affine>)>,
    Rc<AstTranscript<E::G1Affine>>,
) {
    let params_builder = VerifierParamsBuilder::<E> {
        vk,
        key: format_circuit_key(index),
        proof_index: index,
    };

    params_builder.build(instances)
}
