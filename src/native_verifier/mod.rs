use crate::api::ast_eval::EvalContext;
use crate::api::ast_eval::EvalOps;
use crate::api::ast_eval::EvalPos;
use crate::api::halo2::verify_aggregation_proofs;
use crate::circuits::utils::instance_to_instance_commitment;
use crate::circuits::utils::TranscriptHash;
use crate::transcript::poseidon::PoseidonRead;
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

fn context_eval<
    E: MultiMillerLoop,
    EC: EncodedChallenge<E::G1Affine>,
    T: TranscriptRead<E::G1Affine, EC>,
>(
    c: EvalContext<E::G1Affine>,
    instance_commitments: &[&[E::G1Affine]],
    t: &mut [&mut T],
) -> Vec<E::G1Affine> {
    let mut it: Vec<(Option<E::G1Affine>, Option<E::Scalar>)> = vec![];

    macro_rules! eval_scalar_pos {
        ($pos:expr) => {
            match $pos {
                EvalPos::Constant(i) => c.const_scalars[*i],
                EvalPos::Ops(i) => it[*i].1.unwrap(),
                _ => unreachable!(),
            }
        };
    }

    macro_rules! eval_point_pos {
        ($pos:expr) => {
            match $pos {
                EvalPos::Constant(i) => c.const_points[*i],
                EvalPos::Ops(i) => it[*i].0.unwrap(),
                EvalPos::Instance(i, j) => instance_commitments[*i][*j],
                _ => unreachable!(),
            }
        };
    }

    macro_rules! eval_any_pos {
        ($pos:expr) => {
            match $pos {
                EvalPos::Ops(i) => it[*i],
                _ => unreachable!(),
            }
        };
    }

    for (_, op) in c.ops.iter().enumerate() {
        it.push(match op {
            EvalOps::TranscriptReadScalar(i, _) => (None, Some(t[*i].read_scalar().unwrap())),
            EvalOps::TranscriptReadPoint(i, _) => (Some(t[*i].read_point().unwrap()), None),
            EvalOps::TranscriptCommonScalar(i, _, s) => {
                t[*i].common_scalar(eval_scalar_pos!(s)).unwrap();
                (None, None)
            }
            EvalOps::TranscriptCommonPoint(i, _, p) => {
                t[*i].common_point(eval_point_pos!(p)).unwrap();
                (None, None)
            }
            EvalOps::TranscriptSqueeze(i, _) => {
                (None, Some(t[*i].squeeze_challenge().get_scalar()))
            }
            EvalOps::ScalarAdd(a, b) => (None, Some(eval_scalar_pos!(a) + eval_scalar_pos!(b))),
            EvalOps::ScalarSub(a, b) => (None, Some(eval_scalar_pos!(a) - eval_scalar_pos!(b))),
            EvalOps::ScalarMul(a, b) => (None, Some(eval_scalar_pos!(a) * eval_scalar_pos!(b))),
            EvalOps::ScalarDiv(a, b) => (
                None,
                Some(eval_scalar_pos!(a) * eval_scalar_pos!(b).invert().unwrap()),
            ),
            EvalOps::ScalarPow(a, n) => (None, Some(eval_scalar_pos!(a).pow_vartime([*n as u64]))),
            EvalOps::MSM(psl) => (
                psl.into_iter()
                    .map(|(p, s)| (eval_point_pos!(p) * eval_scalar_pos!(s)).to_affine())
                    .reduce(|acc, p| (acc + p).to_affine()),
                None,
            ),
            EvalOps::CheckPoint(tag, v) => {
                if false {
                    println!("checkpoint {}: {:?}", tag, eval_any_pos!(v));
                }
                eval_any_pos!(v)
            }
        });
    }

    c.finals.iter().map(|x| it[*x].0.unwrap()).collect()
}

pub fn verify_single_proof<E: MultiMillerLoop>(
    params: &ParamsVerifier<E>,
    vkey: &VerifyingKey<E::G1Affine>,
    instances: &Vec<Vec<E::Scalar>>,
    proof: Vec<u8>,
    hash: TranscriptHash,
) {
    verify_proofs(params, &[vkey], vec![instances], vec![proof], hash, vec![])
}

pub fn verify_proofs<E: MultiMillerLoop>(
    params: &ParamsVerifier<E>,
    vkey: &[&VerifyingKey<E::G1Affine>],
    instances: Vec<&Vec<Vec<E::Scalar>>>,
    proofs: Vec<Vec<u8>>,
    hash: TranscriptHash,
    commitment_check: Vec<[usize; 4]>,
) {
    let (w_x, w_g, advices) = verify_aggregation_proofs(params, vkey);

    let instance_commitments = instance_to_instance_commitment(params, vkey, instances);

    let mut targets = vec![w_x.0, w_g.0];
    for idx in commitment_check {
        targets.push(advices[idx[0]][idx[1]].0.clone());
        targets.push(advices[idx[2]][idx[3]].0.clone());
    }

    let c = EvalContext::translate(&targets[..]);

    let pl = match hash {
        TranscriptHash::Blake2b => {
            let mut t = vec![];
            for i in 0..proofs.len() {
                t.push(Blake2bRead::<_, E::G1Affine, Challenge255<_>>::init(
                    &proofs[i][..],
                ));
            }
            let empty = vec![];
            t.push(Blake2bRead::<_, E::G1Affine, Challenge255<_>>::init(
                &empty[..],
            ));
            context_eval::<E, _, _>(
                c,
                &instance_commitments
                    .iter()
                    .map(|x| &x[..])
                    .collect::<Vec<_>>()[..],
                &mut t.iter_mut().collect::<Vec<_>>(),
            )
        }
        TranscriptHash::Poseidon => {
            let mut t = vec![];
            for i in 0..proofs.len() {
                t.push(PoseidonRead::init(&proofs[i][..]));
            }
            let empty = vec![];
            t.push(PoseidonRead::init(&empty[..]));
            context_eval::<E, _, _>(
                c,
                &instance_commitments
                    .iter()
                    .map(|x| &x[..])
                    .collect::<Vec<_>>()[..],
                &mut t.iter_mut().collect::<Vec<_>>(),
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

    for c in pl.chunks(2).skip(1) {
        assert_eq!(c[0], c[1]);
    }
}
