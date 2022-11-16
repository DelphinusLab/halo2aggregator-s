use self::builder::VerifierParamsBuilder;
use self::verifier::MultiOpenProof;
use super::arith::AstPointRc;
use super::transcript::AstTranscript;
use super::transcript::AstTranscriptReader;
use crate::api::arith::AstPoint;
use crate::api::halo2::query::EvaluationQuerySchemaRc;
use crate::pcheckpoint;
use crate::scalar;
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
) -> (
    MultiOpenProof<E::G1Affine>,
    Vec<AstPointRc<E::G1Affine>>,
    Rc<AstTranscript<E::G1Affine>>,
) {
    let params_builder = VerifierParamsBuilder {
        vk,
        params,
        key: format!("circuit {}", index),
        proof_index: index,
    };

    let (verifier_params, transcript) = params_builder.build();
    (
        verifier_params.batch_multi_open_proofs(),
        verifier_params.advice_commitments,
        transcript,
    )
}

pub fn verify_aggregation_proofs<E: MultiMillerLoop>(
    params: &ParamsVerifier<E>,
    vks: &[&VerifyingKey<E::G1Affine>],
) -> (
    AstPointRc<E::G1Affine>,           // w_x
    AstPointRc<E::G1Affine>,           // w_g
    Vec<Vec<AstPointRc<E::G1Affine>>>, // advice commitments
) {
    let mut transcript = Rc::new(AstTranscript::Init(vks.len()));

    let mut pairs = vec![];
    let mut advice_commitments = vec![];

    for (i, vk) in vks.into_iter().enumerate() {
        let (p, a, mut t) = verify_single_proof_no_eval(params, vk, i);
        transcript.common_scalar(t.squeeze_challenge());
        advice_commitments.push(a);
        pairs.push(p);
    }

    let s = transcript.squeeze_challenge();

    let pair = pairs
        .into_iter()
        .reduce(|acc, p| MultiOpenProof {
            w_x: acc.w_x * scalar!(s.clone()) + p.w_x,
            w_g: acc.w_g * scalar!(s.clone()) + p.w_g,
        })
        .unwrap();

    let w_x = pcheckpoint!("w_x".to_owned(), pair.w_x.eval(params.g1));
    let w_g = pcheckpoint!("w_g".to_owned(), pair.w_g.eval(-params.g1));

    (w_x, w_g, advice_commitments)
}
