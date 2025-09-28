use crate::pcheckpoint;
use crate::scalar;
use arith::AstPoint;
use arith::AstPointRc;
use halo2::query::replace_commitment;
use halo2::query::EvaluationQuerySchemaRc;
use halo2::verifier::MultiOpenProof;
use halo2::verify_single_proof_no_eval as verify_halo2_single_proof_no_eval;
use halo2_proofs::arithmetic::CurveAffine;
use halo2_proofs::arithmetic::MultiMillerLoop;
use halo2_proofs::helpers::Serializable;
use halo2_proofs::plonk::VerifyingKey;
use halo2_proofs::poly::commitment::ParamsVerifier;
use hyper_plonk::verify_single_proof_no_eval as verify_hyper_plonk_single_proof_no_eval;
use plonkish_backend::backend::hyperplonk::HyperPlonkVerifierParam;
use std::collections::HashMap;
use std::io;
use std::rc::Rc;
use transcript::AstTranscript;
use transcript::AstTranscriptReader;

pub mod arith;
pub mod ast_eval;
pub mod halo2;
pub mod hyper_plonk;
pub mod transcript;

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

#[derive(Debug, Clone)]
pub enum VerifierKey<C: CurveAffine> {
    Halo2(VerifyingKey<C>),
    HyperPlonk(HyperPlonkVerifierParam<C>),
}

impl<C: CurveAffine> VerifierKey<C> {
    pub fn as_halo2(&self) -> Option<&VerifyingKey<C>> {
        if let VerifierKey::Halo2(vk) = self {
            Some(vk)
        } else {
            None
        }
    }

    pub fn as_hyper_plonk(&self) -> Option<&HyperPlonkVerifierParam<C>> {
        if let VerifierKey::HyperPlonk(vk) = self {
            Some(vk)
        } else {
            None
        }
    }

    pub fn write<W: io::Write>(&self, writer: &mut W) -> io::Result<()> {
        match self {
            VerifierKey::Halo2(vk) => vk.write(writer),
            VerifierKey::HyperPlonk(vk) => vk.store(writer),
        }
    }

    pub fn get_name_advices(&self) -> &Vec<(String, u32)> {
        match self {
            VerifierKey::Halo2(vk) => &vk.cs.named_advices,
            VerifierKey::HyperPlonk(vk) => &vk.named_advices,
        }
    }
}

pub fn verify_aggregation_proofs<E: MultiMillerLoop>(
    params: &ParamsVerifier<E>,
    vks: &[&VerifierKey<E::G1Affine>],
    commitment_check: &Vec<[usize; 4]>,
    use_shplonk_as_default: bool,
    proofs_with_shplonk: &Vec<usize>,
    instances: &Vec<Vec<Vec<E::Scalar>>>,
) -> (
    AstPointRc<E::G1Affine>,                    // w_x
    AstPointRc<E::G1Affine>,                    // w_g
    Vec<Vec<AstPointRc<E::G1Affine>>>,          // advice commitments
    Vec<Vec<(usize, AstPointRc<E::G1Affine>)>>, // advice cross item commitments
) {
    let mut transcript = Rc::new(AstTranscript::Init(vks.len()));

    let mut pairs = vec![];
    let mut advice_commitments = vec![];
    let mut advice_bilinear_terms_commitments = vec![];

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
        let (p, a, bilinear, mut t) = match vk {
            VerifierKey::Halo2(vk) => {
                let use_shplonk = use_shplonk_as_default || proofs_with_shplonk.contains(&i);
                verify_halo2_single_proof_no_eval(params, vk, i, !use_shplonk)
            }
            VerifierKey::HyperPlonk(vk) => {
                verify_hyper_plonk_single_proof_no_eval(params, vk, i, &instances[i])
            }
        };
        transcript.common_scalar(t.squeeze_challenge());
        advice_commitments.push(a);
        advice_bilinear_terms_commitments.push(bilinear);
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
    for (from, to) in commitment_map {
        let w_x_replace_res = replace_commitment(
            pair.w_x.0,
            &format_advice_commitment_key(&format_circuit_key(from.0), from.1),
            &format_advice_commitment_key(&format_circuit_key(to.0), to.1),
            &advice_commitments[to.0][to.1],
        );
        pair.w_x = EvaluationQuerySchemaRc(w_x_replace_res.0);

        let w_g_replace_res = replace_commitment(
            pair.w_g.0,
            &format_advice_commitment_key(&format_circuit_key(from.0), from.1),
            &format_advice_commitment_key(&format_circuit_key(to.0), to.1),
            &advice_commitments[to.0][to.1],
        );
        pair.w_g = EvaluationQuerySchemaRc(w_g_replace_res.0);
    }

    let w_x = pcheckpoint!("w_x".to_owned(), pair.w_x.eval(params.g1, 0));
    let w_g = pcheckpoint!("w_g".to_owned(), pair.w_g.eval(-params.g1, 1));
    (
        w_x,
        w_g,
        advice_commitments,
        advice_bilinear_terms_commitments,
    )
}
