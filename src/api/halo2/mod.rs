use self::builder::VerifierParamsBuilder;
use self::verifier::MultiOpenProof;
use super::arith::AstPointRc;
use super::format_circuit_key;
use super::transcript::AstTranscript;
use halo2_proofs::arithmetic::MultiMillerLoop;
use halo2_proofs::plonk::VerifyingKey;
use halo2_proofs::poly::commitment::ParamsVerifier;
use std::rc::Rc;

pub mod builder;
pub mod protocols;
pub mod query;
pub mod verifier;

pub fn verify_single_proof_no_eval<E: MultiMillerLoop>(
    params: &ParamsVerifier<E>,
    vk: &VerifyingKey<E::G1Affine>,
    index: usize,
    use_gwc: bool,
) -> (
    MultiOpenProof<E::G1Affine>,
    Vec<AstPointRc<E::G1Affine>>,
    Vec<(usize, AstPointRc<E::G1Affine>)>,
    Rc<AstTranscript<E::G1Affine>>,
) {
    let params_builder = VerifierParamsBuilder {
        vk,
        params,
        key: format_circuit_key(index),
        proof_index: index,
        use_gwc,
    };

    let (verifier_params, transcript) = params_builder.build();
    (
        if use_gwc {
            verifier_params.batch_multi_open_proofs_gwc()
        } else {
            verifier_params.batch_multi_open_proofs_shplonk()
        },
        verifier_params.advice_commitments,
        vec![],
        transcript,
    )
}
