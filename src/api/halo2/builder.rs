use super::lookup;
use super::permutation;
use super::verifier::PlonkCommonSetup;
use super::verifier::VerifierParams;
use crate::api::arith::*;
use crate::api::transcript::AstTranscript;
use crate::api::transcript::AstTranscriptReader;
use crate::common_point;
use crate::common_scalar;
use crate::pconst;
use crate::pinstance;
use crate::sconst;
use crate::spow;
use halo2_proofs::arithmetic::BaseExt;
use halo2_proofs::arithmetic::CurveAffine;
use halo2_proofs::arithmetic::Field;
use halo2_proofs::arithmetic::FieldExt;
use halo2_proofs::arithmetic::MultiMillerLoop;
use halo2_proofs::plonk::VerifyingKey;
use halo2_proofs::poly::commitment::ParamsVerifier;
use std::collections::HashSet;
use std::iter;
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
    fn init_transcript(&self) -> (Vec<Rc<AstPoint<C>>>, Rc<AstTranscript<C>>) {
        let mut hasher = blake2b_simd::Params::new()
            .hash_length(64)
            .personal(b"Halo2-Verify-Key")
            .to_state();

        let s = format!("{:?}", self.vk.pinned());

        hasher.update(&(s.len() as u64).to_le_bytes());
        hasher.update(s.as_bytes());

        let scalar = E::Scalar::from_bytes_wide(hasher.finalize().as_array());
        let scalar = sconst!(scalar);

        let instance_commitments = self
            .instances
            .iter()
            .enumerate()
            .map(|(i, _)| pinstance!(i))
            .collect::<Vec<_>>();

        let mut transcript = Rc::new(AstTranscript::Init);
        transcript = common_scalar!(transcript, scalar);
        transcript = instance_commitments
            .iter()
            .fold(transcript, |transcript, instance| {
                common_point!(transcript, instance.clone())
            });

        (instance_commitments, transcript)
    }

    pub fn build(&self) -> VerifierParams<C> {
        let cs = &self.vk.cs;
        let raw_omega = self.vk.domain.get_omega();
        let poly_degree = self.vk.domain.get_quotient_poly_degree();

        // Prepare ast for constants.
        let l = cs.blinding_factors() as u32 + 1;
        let n = self.params.n as u32;
        let n_advice = self.vk.cs.num_advice_columns;
        let instance_queries = cs
            .instance_queries
            .iter()
            .map(|column| (column.0.index, column.1 .0 as i32))
            .collect::<Vec<_>>();
        let advice_queries = cs
            .advice_queries
            .iter()
            .map(|column| (column.0.index, column.1 .0 as i32))
            .collect::<Vec<_>>();
        let fixed_queries = cs
            .fixed_queries
            .iter()
            .map(|column| (column.0.index, column.1 .0 as i32))
            .collect::<Vec<_>>();
        let permutation_commitments = self
            .vk
            .permutation
            .commitments
            .iter()
            .map(|commit| pconst!(*commit))
            .collect::<Vec<_>>();
        let gates = cs
            .gates
            .iter()
            .map(|x| x.polys.clone())
            .collect::<Vec<_>>()
            .concat();

        let rotations = HashSet::<i32>::from_iter(
            iter::empty()
                .chain(instance_queries.iter().map(|x| x.1))
                .chain(advice_queries.iter().map(|x| x.1))
                .chain(fixed_queries.iter().map(|x| x.1))
                .chain(vec![0, 1, -1, -((cs.blinding_factors() + 1) as i32)].into_iter()),
        );

        // Prepare ast for transcript.
        let (instance_commitments, mut transcript) = self.init_transcript();
        let advice_commitments = transcript.read_n_points(n_advice);
        let theta = transcript.squeeze_challenge();
        let lookup_permuted = (0..self.vk.cs.lookups.len())
            .map(|_| {
                let permuted_input_commitment = transcript.read_point();
                let permuted_table_commitment = transcript.read_point();

                lookup::PermutedCommitments {
                    permuted_input_commitment,
                    permuted_table_commitment,
                }
            })
            .collect::<Vec<_>>();

        let beta = transcript.squeeze_challenge();
        let gamma = transcript.squeeze_challenge();

        let permutation_product_commitments = transcript.read_n_points(
            self.vk
                .cs
                .permutation
                .columns
                .chunks(self.vk.cs.degree() - 2)
                .len(),
        );
        let lookup_product_commitments = transcript.read_n_points(self.vk.cs.lookups.len());

        let random_commitment = transcript.read_point();
        let y = transcript.squeeze_challenge();
        let vanish_commitments = transcript.read_n_points(poly_degree);
        let x = transcript.squeeze_challenge();

        let instance_evals = transcript.read_n_scalars(self.vk.cs.instance_queries.len());
        let advice_evals = transcript.read_n_scalars(self.vk.cs.advice_queries.len());
        let fixed_evals = transcript.read_n_scalars(self.vk.cs.fixed_queries.len());
        let random_eval = transcript.read_scalar();

        let permutation_evals = transcript.read_n_scalars(self.vk.permutation.commitments.len());
        let permutation_evaluated = permutation::Evaluated::build_from_transcript(
            permutation_product_commitments,
            &self.key,
            &self.vk,
            &mut transcript,
            &x,
            &instance_evals,
            &advice_evals,
            &fixed_evals,
        );
        let lookup_evaluated = lookup_permuted
            .into_iter()
            .zip(lookup_product_commitments.into_iter())
            .enumerate()
            .map(
                |(index, (lookup_permuted_commitment, lookup_product_commitment))| {
                    lookup::Evaluated::build_from_transcript(
                        index,
                        lookup_permuted_commitment,
                        lookup_product_commitment,
                        &self.key,
                        &self.vk,
                        &mut transcript,
                    )
                },
            )
            .collect();

        let fixed_commitments = self
            .vk
            .fixed_commitments
            .iter()
            .map(|&p| pconst!(p))
            .collect::<Vec<_>>();

        let v = transcript.squeeze_challenge();
        let u = transcript.squeeze_challenge();
        let w = transcript.read_n_points(rotations.len());

        // Prepare ast for calculation.
        let omega = sconst!(raw_omega);
        let omega_neg_l = sconst!(raw_omega.pow_vartime([l as u64]).invert().unwrap());
        let omega_neg = sconst!(raw_omega.invert().unwrap());
        let x_next = omega.as_ref() * x.clone();
        let x_last = omega_neg_l.as_ref() * x.clone();
        let x_inv = omega_neg.as_ref() * x.clone();
        let xn = spow!(x.clone(), n);

        VerifierParams {
            key: self.key.clone(),
            gates,
            n,
            l,
            lookup_evaluated,
            permutation_evaluated,
            instance_commitments,
            instance_evals,
            instance_queries,
            advice_commitments,
            advice_evals,
            advice_queries,
            fixed_commitments,
            fixed_evals,
            fixed_queries,
            permutation_commitments,
            permutation_evals,
            vanish_commitments,
            random_commitment,
            w,
            random_eval,
            beta,
            gamma,
            theta,
            delta: sconst!(C::ScalarExt::DELTA),
            x,
            x_next,
            x_last,
            x_inv,
            xn,
            y,
            u,
            v,
            omega,
        }
    }
}
