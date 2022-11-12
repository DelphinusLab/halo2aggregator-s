use super::lookup::PermutationCommitments;
use super::permutation;
use super::verifier::VerifierParams;
use crate::api::arith::*;
use crate::api::transcript;
use crate::api::transcript::AstTranscript;
use crate::api::transcript::AstTranscriptReader;
use crate::common_point;
use crate::common_scalar;
use crate::pinstance;
use crate::sconst;
use halo2_proofs::arithmetic::BaseExt;
use halo2_proofs::arithmetic::CurveAffine;
use halo2_proofs::arithmetic::MultiMillerLoop;
use halo2_proofs::plonk::VerifyingKey;
use halo2_proofs::poly::commitment::ParamsVerifier;
use halo2_proofs::transcript::Transcript;
use std::rc::Rc;

pub struct VerifierParamsBuilder<'a, E: MultiMillerLoop> {
    vk: &'a VerifyingKey<E::G1Affine>,
    params: &'a ParamsVerifier<E>,
    key: String,
    instances: Vec<E::G1Affine>,
}

impl<'a, C: CurveAffine, E: MultiMillerLoop<G1Affine = C, Scalar = C::ScalarExt>>
    VerifierParamsBuilder<'a, E>
{
    fn init_transcript(&self) -> Rc<AstTranscript<C>> {
        let mut hasher = blake2b_simd::Params::new()
            .hash_length(64)
            .personal(b"Halo2-Verify-Key")
            .to_state();

        let s = format!("{:?}", self.vk.pinned());

        hasher.update(&(s.len() as u64).to_le_bytes());
        hasher.update(s.as_bytes());

        let scalar = E::Scalar::from_bytes_wide(hasher.finalize().as_array());
        let scalar = sconst!(scalar);

        let mut transcript = Rc::new(AstTranscript::Init);
        transcript = common_scalar!(transcript, scalar);
        for (i, _) in self.instances.iter().enumerate() {
            transcript = common_point!(transcript, pinstance!(i));
        }
        transcript
    }

    pub fn build(&mut self) -> VerifierParams<C> {
        let l = self.vk.cs.blinding_factors() as u32 + 1;
        let n = self.params.n as u32;
        let omega = self.vk.domain.get_omega();
        let n_advice = self.vk.cs.num_advice_columns;

        let mut transcript = self.init_transcript();
        let advice_commitments = transcript.read_n_points(n_advice);
        let theta = transcript.squeeze_challenge();
        let lookup_permuted = (0..self.vk.cs.lookups.len())
            .map(|_| {
                let permuted_input_commitment = transcript.read_point();
                let permuted_table_commitment = transcript.read_point();

                PermutationCommitments {
                    permuted_input_commitment,
                    permuted_table_commitment,
                }
            })
            .collect::<Vec<_>>();

        let beta = transcript.squeeze_challenge();
        let gamma = transcript.squeeze_challenge();

        let permutation_commitments = transcript.read_n_points(
            self.vk
                .cs
                .permutation
                .columns
                .chunks(self.vk.cs.degree() - 2)
                .len(),
        );
        let lookup_commitments = transcript.read_n_points(self.vk.cs.lookups.len());

        let random_commitment = transcript.read_point();
        let y = transcript.squeeze_challenge();
        let h_commitments = transcript.read_n_points(self.vk.domain.get_quotient_poly_degree());
        let x = transcript.squeeze_challenge();

        let instance_evals = transcript.read_n_scalars(self.vk.cs.instance_queries.len());
        let advice_evals = transcript.read_n_scalars(self.vk.cs.advice_queries.len());
        let fixed_evals = transcript.read_n_scalars(self.vk.cs.fixed_queries.len());
        let random_eval = transcript.read_scalar();

        let permutation_evals = transcript.read_n_scalars(self.vk.permutation.commitments.len());
        let permutation_evaluated = permutation::Evaluated::build_from_transcript(
            permutation_commitments,
            &self.key,
            &self.vk,
            &mut transcript,
            &x,
            &instance_evals,
            &advice_evals,
            &fixed_evals,
        );

        VerifierParams {
            key: self.key.clone(),
            gates: todo!(),
            common: todo!(),
            lookup_evaluated: todo!(),
            permutation_evaluated,
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
            theta,
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
