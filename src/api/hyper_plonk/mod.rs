use self::builder::VerifierParamsBuilder;
use super::halo2::verifier::MultiOpenProof;
use super::arith::AstPointRc;
use super::transcript::AstTranscript;
use super::transcript::AstTranscriptReader;
use super::format_circuit_key;
use crate::api::arith::AstPoint;
use crate::api::halo2::query::replace_commitment;
use crate::api::halo2::query::EvaluationQuerySchemaRc;
use crate::pcheckpoint;
use crate::scalar;
use halo2_proofs::arithmetic::MultiMillerLoop;
use halo2_proofs::plonk::VerifyingKey;
use halo2_proofs::poly::commitment::ParamsVerifier;
use halo2_proofs::arithmetic::CurveAffine;
use plonkish_backend::backend::hyperplonk::HyperPlonkVerifierParam;
use plonkish_backend::pcs::PolynomialCommitmentScheme;
use std::collections::HashMap;
use std::rc::Rc;

pub mod builder;


pub fn verify_single_proof_no_eval<E: MultiMillerLoop>(
    params: &ParamsVerifier<E>,
    vk: &HyperPlonkVerifierParam<E::G1Affine>,
    index: usize,
    instances: &Vec<Vec<E::Scalar>>
) -> (
    MultiOpenProof<E::G1Affine>,
    Vec<AstPointRc<E::G1Affine>>,
    Rc<AstTranscript<E::G1Affine>>,
) {
    let params_builder = VerifierParamsBuilder {
        vk,
        params,
        key: format_circuit_key(index),
        proof_index: index,
    };

    params_builder.build(instances)
}

