use crate::api::ast_eval::EvalContext;
use crate::api::ast_eval::EvalOps;
use crate::api::ast_eval::EvalPos;
use crate::api::halo2::verify_aggregation_proofs;
use crate::circuits::utils::instance_to_instance_commitment;
use crate::circuits::utils::TranscriptHash;
use halo2_proofs::arithmetic::Field;
use halo2_proofs::arithmetic::MillerLoopResult;
use halo2_proofs::arithmetic::MultiMillerLoop;
use halo2_proofs::pairing::group::Curve;
use halo2_proofs::pairing::group::Group;
use halo2_proofs::plonk::VerifyingKey;
use halo2_proofs::poly::commitment::ParamsVerifier;
use halo2_proofs::transcript::Blake2bRead;
use halo2_proofs::transcript::Challenge255;
use halo2_proofs::transcript::EncodedChallenge;
use halo2_proofs::transcript::TranscriptRead;

fn context_eval<E: MultiMillerLoop, T: TranscriptRead<E::G1Affine, Challenge255<E::G1Affine>>>(
    c: EvalContext<E::G1Affine>,
    instance_commitments: &[E::G1Affine],
    t: &mut T,
) -> Vec<E::G1Affine> {
    let mut it: Vec<(Option<E::G1Affine>, Option<E::Scalar>)> = vec![];

    macro_rules! eval_scalar_pos {
        ($pos:expr) => {
            match $pos {
                EvalPos::Constant(i) => c.const_scalars[i],
                EvalPos::Ops(i) => it[i].1.unwrap(),
                _ => unreachable!(),
            }
        };
    }

    macro_rules! eval_point_pos {
        ($pos:expr) => {
            match $pos {
                EvalPos::Constant(i) => c.const_points[i],
                EvalPos::Ops(i) => it[i].0.unwrap(),
                EvalPos::Instance(i) => instance_commitments[i],
                _ => unreachable!(),
            }
        };
    }

    for op in c.ops {
        it.push(match op {
            EvalOps::TranscriptReadScalar(_) => (None, Some(t.read_scalar().unwrap())),
            EvalOps::TranscriptReadPoint(_) => (Some(t.read_point().unwrap()), None),
            EvalOps::TranscriptCommonScalar(_, s) => {
                println!("{:?}",s);
                t.common_scalar(eval_scalar_pos!(s)).unwrap();
                (None, None)
            }
            EvalOps::TranscriptCommonPoint(_, p) => {
                t.common_point(eval_point_pos!(p)).unwrap();
                (None, None)
            }
            EvalOps::TranscriptSqueeze(_) => (None, Some(t.squeeze_challenge().get_scalar())),
            EvalOps::ScalarAdd(a, b) => (None, Some(eval_scalar_pos!(a) + eval_scalar_pos!(b))),
            EvalOps::ScalarSub(a, b) => (None, Some(eval_scalar_pos!(a) - eval_scalar_pos!(b))),
            EvalOps::ScalarMul(a, b) => (None, Some(eval_scalar_pos!(a) * eval_scalar_pos!(b))),
            EvalOps::ScalarDiv(a, b) => (
                None,
                Some(eval_scalar_pos!(a) * eval_scalar_pos!(b).invert().unwrap()),
            ),
            EvalOps::ScalarPow(a, n) => (None, Some(eval_scalar_pos!(a).pow_vartime([n as u64]))),
            EvalOps::MSM(psl) => (
                psl.iter()
                    .map(|(p, s)| (eval_point_pos!(*p) * eval_scalar_pos!(*s)).to_affine())
                    .reduce(|acc, p| (acc + p).to_affine()),
                None,
            ),
        });
    }

    c.finals.iter().map(|x| it[*x].0.unwrap()).collect()
}

pub fn verify_single_proof<E: MultiMillerLoop>(
    params: &ParamsVerifier<E>,
    vkey: &VerifyingKey<E::G1Affine>,
    instances: &[&[E::Scalar]],
    proof: Vec<u8>,
    hash: TranscriptHash,
) {
    let (w_x, w_g, _) = verify_aggregation_proofs(params, &[vkey]);

    let instance_commitments = instance_to_instance_commitment(params, vkey, instances);

    let pl = match hash {
        TranscriptHash::Blake2b => {
            let mut t = Blake2bRead::<_, E::G1Affine, Challenge255<_>>::init(&proof[..]);
            context_eval::<E, _>(
                EvalContext::translate(&[w_x.0, w_g.0]),
                &instance_commitments,
                &mut t,
            )
        }
    };

    let s_g2_prepared = E::G2Prepared::from(params.s_g2);
    let n_g2_prepared = E::G2Prepared::from(-params.g2);
    let success = bool::from(
        E::multi_miller_loop(&[(&pl[0], &s_g2_prepared), (&pl[1], &n_g2_prepared)])
            .final_exponentiation()
            .is_identity(),
    );

    assert!(success);
}
