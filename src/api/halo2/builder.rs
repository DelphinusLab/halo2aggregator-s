use super::verifier::VerifierParams;
use crate::api::arith::*;
use crate::api::transcript::AstTranscript;
use crate::common_point;
use crate::common_scalar;
use crate::pinstance;
use crate::ptranscript;
use crate::sconst;
use halo2_proofs::arithmetic::BaseExt;
use halo2_proofs::arithmetic::CurveAffine;
use halo2_proofs::arithmetic::MultiMillerLoop;
use halo2_proofs::plonk::VerifyingKey;
use halo2_proofs::poly::commitment::ParamsVerifier;
use std::rc::Rc;

pub struct VerifierParamsBuilder<'a, E: MultiMillerLoop> {
    vk: &'a VerifyingKey<E::G1Affine>,
    params: &'a ParamsVerifier<E>,
    key: String,
    transcript: Rc<AstTranscript<E::G1Affine>>,
    instances: Vec<E::G1Affine>,
}

impl<'a, C: CurveAffine, E: MultiMillerLoop<G1Affine = C, Scalar = C::ScalarExt>>
    VerifierParamsBuilder<'a, E>
{
    fn init_transcript(&mut self) {
        let mut hasher = blake2b_simd::Params::new()
            .hash_length(64)
            .personal(b"Halo2-Verify-Key")
            .to_state();

        let s = format!("{:?}", self.vk.pinned());

        hasher.update(&(s.len() as u64).to_le_bytes());
        hasher.update(s.as_bytes());

        let scalar = E::Scalar::from_bytes_wide(hasher.finalize().as_array());
        let scalar = sconst!(scalar);

        let mut transcript = self.transcript.clone();
        transcript = common_scalar!(transcript, scalar);
        for (i, _) in self.instances.iter().enumerate() {
            transcript = common_point!(transcript, pinstance!(i));
        }

        self.transcript = transcript;
    }

    fn read_point(&mut self) -> Rc<AstPoint<C>> {
        let (p, t) = ptranscript!(self.transcript.clone());
        self.transcript = t;
        p
    }

    pub fn build(&mut self) -> VerifierParams<C> {
        let n_advice = self.vk.cs.num_advice_columns;
        let advice_commitments = (0..n_advice)
            .into_iter()
            .map(|_| self.read_point())
            .collect();
            
        VerifierParams {
            key: todo!(),
            gates: todo!(),
            common: todo!(),
            lookup_evaluated: todo!(),
            permutation_evaluated: todo!(),
            instance_commitments: todo!(),
            instance_evals: todo!(),
            instance_queries: todo!(),
            advice_commitments,
            advice_evals: todo!(),
            advice_queries: todo!(),
            fixed_commitments: todo!(),
            fixed_evals: todo!(),
            fixed_queries: todo!(),
            permutation_commitments: todo!(),
            permutation_evals: todo!(),
            vanish_commitments: todo!(),
            random_commitment: todo!(),
            w: todo!(),
            random_eval: todo!(),
            beta: todo!(),
            gamma: todo!(),
            theta: todo!(),
            delta: todo!(),
            x: todo!(),
            x_next: todo!(),
            x_last: todo!(),
            x_inv: todo!(),
            xn: todo!(),
            y: todo!(),
            u: todo!(),
            v: todo!(),
            omega: todo!(),
        }
    }
}
