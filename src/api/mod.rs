use halo2_proofs::arithmetic::MultiMillerLoop;
use halo2_proofs::plonk::VerifyingKey;
use halo2_proofs::poly::commitment::ParamsVerifier;
use arith::AstPointRc;
use arith::AstPoint;
use halo2::verifier::MultiOpenProof;
use transcript::AstTranscript;
use transcript::AstTranscriptReader;
use halo2::query::{replace_commitment,EvaluationQuerySchemaRc};
use halo2::verify_single_proof_no_eval as verify_halo2_single_proof_no_eval;
use hyper_plonk::verify_single_proof_no_eval as verify_hyper_plonk_single_proof_no_eval;
use crate::pcheckpoint;
use crate::scalar;
use plonkish_backend::backend::hyperplonk::HyperPlonkVerifierParam;
use std::collections::HashMap;
use std::rc::Rc;

pub mod arith;
pub mod ast_eval;
pub mod halo2;
pub mod transcript;
pub mod hyper_plonk;

pub fn format_circuit_key(proof_index: usize) -> String {
    format!("circuit_{}", proof_index)
}

pub fn format_advice_commitment_key(circuit_key: &str, column: usize) -> String {
    format!("{}_advice_commitments_{}", circuit_key, column)
}

pub fn format_instance_commitment_key(circuit_key: &str, column: usize) -> String {
    format!("{}_instance_commitments_{}", circuit_key, column)
}

pub fn format_fixed_commitment_key(circuit_key: &str, column: usize) -> String {
    format!("{}_fixed_commitments_{}", circuit_key, column)
}

// #[derive(Debug, Clone)]
// pub enum VerifierKey<E>
//     where
//         E: MultiMillerLoop,
// {
//     Halo2(VerifyingKey<E::G1Affine>),
//     HyperPlonk {
//         inner: HyperPlonkVerifierParam<
//             E::Scalar,
//             Box<dyn PolynomialCommitmentScheme<E::Scalar,
//                 Param=<UnivariateKzg<M> as PolynomialCommitmentScheme<E::Scalar>>::Param,
//          ProverParam = ZeromorphKzgProverParam<E>,
//          VerifierParam = ZeromorphKzgVerifierParam<E>,
//          Polynomial = MultilinearPolynomial<E::Scalar>,
//          Commitment = <UnivariateKzg<E> as PolynomialCommitmentScheme<E::Scalar>>::Commitment,
//
//         CommitmentChunk = E::G1Affine>>,
//         >,
//     },
// }

//
// pub fn verify_aggregation_proofs<E: MultiMillerLoop>(
//     params: &ParamsVerifier<E>,
//     vks: &[&VerifyingKey<E::G1Affine>],
//     commitment_check: &Vec<[usize; 4]>,
//     use_shplonk_as_default: bool,
//     proofs_with_shplonk: &Vec<usize>,
// ) -> (
//     AstPointRc<E::G1Affine>,           // w_x
//     AstPointRc<E::G1Affine>,           // w_g
//     Vec<Vec<AstPointRc<E::G1Affine>>>, // advice commitments
// ) {
//     let mut transcript = Rc::new(AstTranscript::Init(vks.len()));
//
//     let mut pairs = vec![];
//     let mut advice_commitments = vec![];
//
//     // replace commitment to reduce msm len
//     let mut commitment_map = HashMap::new();
//     for checks in commitment_check {
//         if checks[0] < checks[2] {
//             commitment_map.insert((checks[2], checks[3]), (checks[0], checks[1]));
//         } else {
//             commitment_map.insert((checks[0], checks[1]), (checks[2], checks[3]));
//         }
//     }
//
//     for (i, vk) in vks.into_iter().enumerate() {
//         let use_shplonk = use_shplonk_as_default || proofs_with_shplonk.contains(&i);
//         let (p, a, mut t) = verify_halo2_single_proof_no_eval(params, vk, i, !use_shplonk);
//         // let (p, a, mut t) = match vk {
//             // VerifierKey::Halo2(vk)=>{
//             //     let use_shplonk = use_shplonk_as_default || proofs_with_shplonk.contains(&i);
//             //     verify_halo2_single_proof_no_eval(params, vk, i, !use_shplonk)
//             // }
//             // VerifierKey::HyperPlonk(vk)=>{
//             //     verify_hyper_plonk_single_proof_no_eval(params, vk, i)
//             // }
//         // };
//         transcript.common_scalar(t.squeeze_challenge());
//         advice_commitments.push(a);
//         pairs.push(p);
//     }
//
//     let s = transcript.squeeze_challenge();
//
//     let mut pair = pairs
//         .into_iter()
//         .reduce(|acc, p| MultiOpenProof {
//             w_x: acc.w_x * scalar!(s.clone()) + p.w_x,
//             w_g: acc.w_g * scalar!(s.clone()) + p.w_g,
//         })
//         .unwrap();
//
//     // replace same commitments to singleton to reduce msm size
//     for (from, to) in commitment_map {
//         let w_x_replace_res = replace_commitment(
//             pair.w_x.0,
//             &format_advice_commitment_key(&format_circuit_key(from.0), from.1),
//             &format_advice_commitment_key(&format_circuit_key(to.0), to.1),
//             &advice_commitments[to.0][to.1],
//         );
//         pair.w_x = EvaluationQuerySchemaRc(w_x_replace_res.0);
//
//         let w_g_replace_res = replace_commitment(
//             pair.w_g.0,
//             &format_advice_commitment_key(&format_circuit_key(from.0), from.1),
//             &format_advice_commitment_key(&format_circuit_key(to.0), to.1),
//             &advice_commitments[to.0][to.1],
//         );
//         pair.w_g = EvaluationQuerySchemaRc(w_g_replace_res.0);
//     }
//
//     let w_x = pcheckpoint!("w_x".to_owned(), pair.w_x.eval(params.g1, 0));
//     let w_g = pcheckpoint!("w_g".to_owned(), pair.w_g.eval(-params.g1, 1));
//
//     (w_x, w_g, advice_commitments)
// }