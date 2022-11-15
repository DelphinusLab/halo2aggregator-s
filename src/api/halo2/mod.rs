use self::builder::VerifierParamsBuilder;
use self::verifier::MultiOpenProof;
use super::arith::AstPointRc;
use super::arith::AstScalarRc;
use super::transcript::AstTranscript;
use super::transcript::AstTranscriptReader;
use crate::api::arith::AstScalar;
use crate::api::halo2::query::EvaluationQuerySchemaRc;
use crate::scalar;
use crate::sconst;
use halo2_proofs::arithmetic::Field;
use halo2_proofs::arithmetic::MultiMillerLoop;
use halo2_proofs::plonk::VerifyingKey;
use halo2_proofs::poly::commitment::ParamsVerifier;
use std::rc::Rc;

pub mod builder;
pub mod protocols;
pub mod query;
pub mod verifier;

pub fn verify_single_proof_no_eval<E: MultiMillerLoop>(
    key: String,
    params: &ParamsVerifier<E>,
    vk: &VerifyingKey<E::G1Affine>,
) -> (
    MultiOpenProof<E::G1Affine>,
    Vec<AstPointRc<E::G1Affine>>,
    Rc<AstTranscript<E::G1Affine>>,
) {
    let params_builder = VerifierParamsBuilder { vk, params, key };

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
    let mut transcript = Rc::new(AstTranscript::Init);

    let mut pairs = vec![];
    let mut advice_commitments = vec![];

    for (i, vk) in vks.into_iter().enumerate() {
        let (p, a, mut t) = verify_single_proof_no_eval(format!("circuit_{}", i), params, vk);
        transcript = transcript.common_scalar(t.squeeze_challenge());
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

    let w_x = pair.w_x.eval(sconst!(E::Scalar::one()));
    let w_g = pair.w_g.eval(sconst!(-E::Scalar::one()));

    (w_x, w_g, advice_commitments)
}
