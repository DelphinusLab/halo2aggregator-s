use super::protocols::logup as lookup;
use super::protocols::permutation;
use super::protocols::shuffle;
use super::verifier::VerifierParams;
use crate::api::arith::*;
use crate::api::transcript::AstTranscript;
use crate::api::transcript::AstTranscriptReader;
use crate::pcheckpoint;
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
    pub(crate) key: String,
    pub(crate) proof_index: usize,
    pub(crate) params: &'a ParamsVerifier<E>,
    pub(crate) vk: &'a VerifyingKey<E::G1Affine>,
    pub(crate) use_gwc: bool,
}

impl<'a, C: CurveAffine, E: MultiMillerLoop<G1Affine = C, Scalar = C::ScalarExt>>
    VerifierParamsBuilder<'a, E>
{
    fn init_transcript(&self, proof_index: usize) -> (Vec<AstPointRc<C>>, Rc<AstTranscript<C>>) {
        let mut hasher = blake2b_simd::Params::new()
            .hash_length(64)
            .personal(b"Halo2-Verify-Key")
            .to_state();

        let s = format!("{:?}", self.vk.pinned());

        hasher.update(&(s.len() as u64).to_le_bytes());
        hasher.update(s.as_bytes());

        let scalar = E::Scalar::from_bytes_wide(hasher.finalize().as_array());
        let scalar = sconst!(scalar);

        let instance_commitments = (0..self.vk.cs.num_instance_columns)
            .into_iter()
            .map(|i| pinstance!(proof_index, i.try_into().unwrap()))
            .collect::<Vec<_>>();

        let mut transcript = Rc::new(AstTranscript::Init(proof_index));
        transcript.common_scalar(scalar);
        instance_commitments
            .iter()
            .for_each(|instance_commitment| transcript.common_point(instance_commitment.clone()));

        (instance_commitments, transcript)
    }

    pub fn build(&self) -> (VerifierParams<C>, Rc<AstTranscript<C>>) {
        let one = C::ScalarExt::one();
        let cs = &self.vk.cs;
        let omega = self.vk.domain.get_omega();
        let poly_degree = self.vk.domain.get_quotient_poly_degree();
        let n_permutation_product_commitments = self
            .vk
            .cs
            .permutation
            .columns
            .chunks(self.vk.cs.degree() - 2)
            .len();
        let shuffle_groups = cs
            .shuffles
            .iter()
            .map(|v| {
                v.0.iter()
                    .map(|v| (v.input_expressions.clone(), v.shuffle_expressions.clone()))
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
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
            .map(|commit| {
                let is_zero: bool = commit.is_identity().into();
                assert!(!is_zero);
                pconst!(*commit)
            })
            .collect::<Vec<_>>();
        let gates = cs
            .gates
            .iter()
            .map(|x| x.polys.clone())
            .collect::<Vec<_>>()
            .concat();
        let delta = sconst!(C::ScalarExt::DELTA);

        let mut rotations = HashSet::<i32>::new();
        for i in iter::empty()
            .chain(instance_queries.iter().map(|x| x.1))
            .chain(advice_queries.iter().map(|x| x.1))
            .chain(fixed_queries.iter().map(|x| x.1))
            .chain(vec![0, 1].into_iter())
        {
            rotations.insert(i);
        }

        // more than 1 input_sets need extra z poly like as permutation, and need last_z rotation
        let n_lookup_sets = cs
            .lookups
            .iter()
            .map(|set| set.input_expressions_sets.len())
            .max()
            .unwrap_or_default();

        if n_permutation_product_commitments > 1 || n_lookup_sets > 1 {
            rotations.insert(-((cs.blinding_factors() + 1) as i32));
        }

        // Prepare ast for transcript.
        let (instance_commitments, mut transcript) = self.init_transcript(self.proof_index);
        let advice_commitments = transcript
            .read_n_points(n_advice)
            .into_iter()
            .enumerate()
            .map(|(i, x)| pcheckpoint!(format!("advice commitment {} {}", self.proof_index, i), x))
            .collect();
        let theta = transcript.squeeze_challenge();
        let lookup_multiplicities = (0..self.vk.cs.lookups.len())
            .map(|_| {
                let multiplicity_commitment = transcript.read_point();
                lookup::MultiplicityCommitment(multiplicity_commitment)
            })
            .collect::<Vec<_>>();

        let beta = transcript.squeeze_challenge();
        let gamma = transcript.squeeze_challenge();

        let permutation_product_commitments =
            transcript.read_n_points(n_permutation_product_commitments);
        let lookup_z_commitments = self
            .vk
            .cs
            .lookups
            .iter()
            .map(|arg| transcript.read_n_points(arg.input_expressions_sets.len()))
            .collect::<Vec<_>>();
        let shuffle_product_commitments = transcript.read_n_points(shuffle_groups.len());

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
        let lookup_evaluated = lookup_multiplicities
            .into_iter()
            .zip(lookup_z_commitments.into_iter())
            .enumerate()
            .map(
                |(index, (lookup_multiplicity_commitment, lookup_z_commitment_set))| {
                    lookup::Evaluated::build_from_transcript(
                        index,
                        lookup_multiplicity_commitment,
                        lookup_z_commitment_set,
                        &self.key,
                        &self.vk,
                        &mut transcript,
                    )
                },
            )
            .collect();

        let shuffle_evaluated = shuffle_product_commitments
            .into_iter()
            .zip(shuffle_groups.into_iter())
            .enumerate()
            .map(|(index, (shuffle_product_commitment, shuffle_group))| {
                shuffle::Evaluated::build_from_transcript(
                    index,
                    shuffle_product_commitment,
                    &self.key,
                    shuffle_group,
                    &mut transcript,
                )
            })
            .collect();

        let fixed_commitments = self
            .vk
            .fixed_commitments
            .iter()
            .map(|&p| {
                let _is_zero: bool = p.is_identity().into();
                pconst!(p)
            })
            .collect::<Vec<_>>();

        let (multiopen_commitments, multiopen_challenges) = if self.use_gwc {
            // gwc
            let v = transcript.squeeze_challenge();
            let u = transcript.squeeze_challenge();
            (transcript.read_n_points(rotations.len()), vec![v, u])
        } else {
            // shplonk
            let y = transcript.squeeze_challenge();
            let v = transcript.squeeze_challenge();
            let h1 = transcript.read_point();
            let u = transcript.squeeze_challenge();
            let h2 = transcript.read_point();
            (vec![h1, h2], vec![y, v, u])
        };

        // Prepare ast for calculation.
        let omega_neg_l = sconst!(omega.pow_vartime([l as u64]).invert().unwrap());
        let omega_neg = sconst!(omega.invert().unwrap());
        let x_next = sconst!(omega) * x.clone();
        let x_last = omega_neg_l * x.clone();
        let x_inv = omega_neg * x.clone();
        let xn = spow!(x.clone(), n);

        let ls = {
            let mut ws = vec![sconst!(one)];
            let omega_inv = omega.invert().unwrap();
            let mut acc = omega_inv;
            for _ in 1..=l {
                ws.push(sconst!(acc));
                acc = acc * omega_inv;
            }
            (0..=l as usize)
                .map(|i| {
                    let wi = &ws[i];
                    ((wi / sconst!(C::ScalarExt::from(n as u64))) * (xn.clone() - sconst!(one)))
                        / (x.clone() - wi.clone())
                })
                .rev()
                .collect::<Vec<_>>()
        };
        let l_blind = ls[1..l as usize]
            .into_iter()
            .map(|x| x.clone())
            .reduce(|acc, x| acc + x)
            .unwrap();

        (
            VerifierParams {
                key: self.key.clone(),
                gates,
                n,
                l,
                lookup_evaluated,
                shuffle_evaluated,
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
                multiopen_commitments,
                random_eval,
                beta,
                gamma,
                theta,
                delta,
                x,
                x_next,
                x_last,
                x_inv,
                xn,
                y,
                multiopen_challenges,
                omega,
                ls,
                l_blind,
            },
            transcript,
        )
    }
}
