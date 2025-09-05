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


pub fn verify_single_proof_no_eval<E: MultiMillerLoop,PCS:PolynomialCommitmentScheme<E::Scalar,CommitmentChunk=E::G1Affine>>(
    params: &ParamsVerifier<E>,
    vk: &HyperPlonkVerifierParam<E::Scalar,PCS>,
    index: usize,
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

    params_builder.build()
}

pub fn verify_hyper_aggregation_proofs<E: MultiMillerLoop,PCS:PolynomialCommitmentScheme<E::Scalar,CommitmentChunk=E::G1Affine>>(
    params: &ParamsVerifier<E>,
    vks: &[&HyperPlonkVerifierParam<E::Scalar,PCS>],
    commitment_check: &Vec<[usize; 4]>,
) -> (
    AstPointRc<E::G1Affine>,           // w_x
    AstPointRc<E::G1Affine>,           // w_g
    Vec<Vec<AstPointRc<E::G1Affine>>>, // advice commitments
) {
    let mut transcript = Rc::new(AstTranscript::Init(vks.len()));

    let mut pairs = vec![];
    let mut advice_commitments:Vec<_> = vec![];

    // replace commitment to reduce msm len
    let mut commitment_map = HashMap::new();
    for checks in commitment_check {
        if checks[0] < checks[2] {
            commitment_map.insert((checks[2], checks[3]), (checks[0], checks[1]));
        } else {
            commitment_map.insert((checks[0], checks[1]), (checks[2], checks[3]));
        }
    }

    for (i, vk) in vks.into_iter().enumerate() {
        // let use_shplonk = use_shplonk_as_default || proofs_with_shplonk.contains(&i);
        let (p,_, mut t) = verify_single_proof_no_eval(params, vk, i);
        transcript.common_scalar(t.squeeze_challenge());
        // advice_commitments.push(a);
        pairs.push(p);
    }

    let s = transcript.squeeze_challenge();

    let mut pair = pairs
        .into_iter()
        .reduce(|acc, p| MultiOpenProof {
            w_x: acc.w_x * scalar!(s.clone()) + p.w_x,
            w_g: acc.w_g * scalar!(s.clone()) + p.w_g,
        })
        .unwrap();

    // replace same commitments to singleton to reduce msm size
    // for (from, to) in commitment_map {
    //     let w_x_replace_res = replace_commitment(
    //         pair.w_x.0,
    //         &format_advice_commitment_key(&format_circuit_key(from.0), from.1),
    //         &format_advice_commitment_key(&format_circuit_key(to.0), to.1),
    //         &advice_commitments[to.0][to.1],
    //     );
    //     pair.w_x = EvaluationQuerySchemaRc(w_x_replace_res.0);
    //
    //     let w_g_replace_res = replace_commitment(
    //         pair.w_g.0,
    //         &format_advice_commitment_key(&format_circuit_key(from.0), from.1),
    //         &format_advice_commitment_key(&format_circuit_key(to.0), to.1),
    //         &advice_commitments[to.0][to.1],
    //     );
    //     pair.w_g = EvaluationQuerySchemaRc(w_g_replace_res.0);
    // }

    let w_x = pcheckpoint!("w_x".to_owned(), pair.w_x.eval(params.g1, 0));
    let w_g = pcheckpoint!("w_g".to_owned(), pair.w_g.eval(-params.g1, 1));

    (w_x, w_g, advice_commitments)
}
