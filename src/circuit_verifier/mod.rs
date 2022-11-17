use self::circuit::AggregatorCircuit;
use self::transcript::PoseidonChipRead;
use crate::api::ast_eval::EvalContext;
use crate::api::ast_eval::EvalOps;
use crate::api::ast_eval::EvalPos;
use crate::api::halo2::verify_aggregation_proofs;
use crate::circuits::utils::instance_to_instance_commitment;
use crate::circuits::utils::TranscriptHash;
use crate::transcript::poseidon::PoseidonRead;
use halo2_proofs::arithmetic::CurveAffine;
use halo2_proofs::arithmetic::Field;
use halo2_proofs::arithmetic::MillerLoopResult;
use halo2_proofs::arithmetic::MultiMillerLoop;
use halo2_proofs::pairing::group::prime::PrimeCurveAffine;
use halo2_proofs::pairing::group::Group;
use halo2_proofs::plonk::VerifyingKey;
use halo2_proofs::poly::commitment::ParamsVerifier;
use halo2ecc_s::assign::AssignedPoint;
use halo2ecc_s::assign::AssignedValue;
use halo2ecc_s::circuit::base_chip::BaseChipOps;
use halo2ecc_s::circuit::integer_chip::IntegerChipOps;
use halo2ecc_s::circuit::native_ecc_chip::EccChipOps;
use halo2ecc_s::context::Context;
use halo2ecc_s::context::EccContext;
use std::io;
use std::rc::Rc;
use std::sync::Arc;

pub mod circuit;
pub mod transcript;

fn context_eval<E: MultiMillerLoop, R: io::Read>(
    c: EvalContext<E::G1Affine>,
    instance_commitments: &[&[E::G1Affine]],
    t: &mut [&mut PoseidonChipRead<R, E::G1Affine>],
    circuit: &mut EccContext<E::G1Affine>,
) -> (
    Vec<AssignedPoint<E::G1Affine, E::Scalar>>,
    Vec<Vec<AssignedPoint<E::G1Affine, E::Scalar>>>,
) {
    let mut it: Vec<(
        Option<AssignedPoint<E::G1Affine, E::Scalar>>,
        Option<AssignedValue<E::Scalar>>,
    )> = vec![];

    let const_scalars = {
        c.const_scalars
            .iter()
            .map(|c| circuit.assign_constant(*c))
            .collect::<Vec<_>>()
    };

    let const_points = {
        c.const_points
            .iter()
            .map(|c| circuit.assign_constant_point(&c.to_curve()))
            .collect::<Vec<_>>()
    };

    let instance_commitments = {
        instance_commitments
            .iter()
            .map(|cl| {
                cl.iter()
                    .map(|instance_commitment| {
                        circuit.assign_point(&instance_commitment.to_curve())
                    })
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>()
    };

    let mut commitments = vec![vec![]; instance_commitments.len()];

    macro_rules! eval_scalar_pos {
        ($pos:expr) => {
            match $pos {
                EvalPos::Constant(i) => &const_scalars[*i],
                EvalPos::Ops(i) => it[*i].1.as_ref().unwrap(),
                _ => unreachable!(),
            }
        };
    }

    macro_rules! eval_point_pos {
        ($pos:expr) => {
            match $pos {
                EvalPos::Constant(i) => &const_points[*i],
                EvalPos::Ops(i) => it[*i].0.as_ref().unwrap(),
                EvalPos::Instance(i, j) => &instance_commitments[*i][*j],
                _ => unreachable!(),
            }
        };
    }

    macro_rules! eval_any_pos {
        ($pos:expr) => {
            match $pos {
                EvalPos::Ops(i) => it[*i].clone(),
                _ => unreachable!(),
            }
        };
    }

    for (_, op) in c.ops.iter().enumerate() {
        it.push(match op {
            EvalOps::TranscriptReadScalar(i, _) => {
                let s = t[*i].read_scalar(circuit);
                (None, Some(s))
            }
            EvalOps::TranscriptReadPoint(i, _) => {
                let p = t[*i].read_point(circuit);
                commitments[*i].push(p.clone());
                (Some(p), None)
            }
            EvalOps::TranscriptCommonScalar(i, _, s) => {
                t[*i].common_scalar(circuit, eval_scalar_pos!(s));
                (None, None)
            }
            EvalOps::TranscriptCommonPoint(i, _, p) => {
                t[*i].common_point(circuit, eval_point_pos!(p));
                //assert!(false);
                (None, None)
            }
            EvalOps::TranscriptSqueeze(i, _) => (None, Some(t[*i].squeeze(circuit))),
            EvalOps::ScalarAdd(a, b) => (
                None,
                Some(circuit.add(eval_scalar_pos!(a), eval_scalar_pos!(b))),
            ),
            EvalOps::ScalarSub(a, b) => (
                None,
                Some(circuit.sub(eval_scalar_pos!(a), eval_scalar_pos!(b))),
            ),
            EvalOps::ScalarMul(a, b) => (
                None,
                Some(circuit.mul(eval_scalar_pos!(a), eval_scalar_pos!(b))),
            ),
            EvalOps::ScalarDiv(a, b) => (
                None,
                Some(circuit.div_unsafe(eval_scalar_pos!(a), eval_scalar_pos!(b))),
            ),
            EvalOps::ScalarPow(a, n) => {
                let mut p = *n;
                let mut c = vec![];
                let mut acc = eval_scalar_pos!(a).clone();
                while p > 0 {
                    if p & 1 == 1 {
                        c.push(acc);
                    }
                    acc = circuit.mul(&acc, &acc);
                    p >>= 1;
                }
                let s = c
                    .into_iter()
                    .reduce(|acc, x| circuit.mul(&acc, &x))
                    .unwrap();
                (None, Some(s))
            }
            EvalOps::MSM(psl) => {
                let pl = psl
                    .iter()
                    .map(|(p, _)| eval_point_pos!(p).clone())
                    .collect();
                let sl = psl
                    .iter()
                    .map(|(_, s)| eval_scalar_pos!(s).clone())
                    .collect();
                (Some(circuit.msm(&pl, &sl)), None)
            }
            EvalOps::CheckPoint(tag, v) => {
                if false {
                    println!("checkpoint {}: {:?}", tag, eval_any_pos!(v));
                }
                eval_any_pos!(v)
            }
        });
    }

    (
        vec![
            c.finals
                .iter()
                .map(|x| circuit.ecc_reduce(it[*x].0.as_ref().unwrap()))
                .collect(),
            instance_commitments.concat(),
        ]
        .concat(),
        commitments,
    )
}

pub fn build_single_proof_verify_circuit<E: MultiMillerLoop>(
    params: &ParamsVerifier<E>,
    vkey: &VerifyingKey<E::G1Affine>,
    instances: &Vec<Vec<E::Scalar>>,
    proof: Vec<u8>,
    hash: TranscriptHash,
) -> (AggregatorCircuit<E::G1Affine>, Vec<E::Scalar>) {
    build_aggregate_verify_circuit(params, &[vkey], vec![instances], vec![proof], hash, vec![])
}

pub fn build_aggregate_verify_circuit<E: MultiMillerLoop>(
    params: &ParamsVerifier<E>,
    vkey: &[&VerifyingKey<E::G1Affine>],
    instances: Vec<&Vec<Vec<E::Scalar>>>,
    proofs: Vec<Vec<u8>>,
    hash: TranscriptHash,
    commitment_check: Vec<[usize; 4]>,
) -> (AggregatorCircuit<E::G1Affine>, Vec<E::Scalar>) {
    let mut ctx = Context::<_, E::Scalar>::new_with_range_info();

    let (w_x, w_g, _) = verify_aggregation_proofs(params, vkey);

    let instance_commitments = instance_to_instance_commitment(params, vkey, instances);

    let c = EvalContext::translate(&[w_x.0, w_g.0]);

    let (pl, cl) = match hash {
        TranscriptHash::Poseidon => {
            let mut t = vec![];
            for i in 0..proofs.len() {
                let it = PoseidonRead::init(&proofs[i][..]);
                t.push(PoseidonChipRead::init(it, &mut ctx));
            }
            let empty = vec![];
            let it = PoseidonRead::init(&empty[..]);
            t.push(PoseidonChipRead::init(it, &mut ctx));

            context_eval::<E, _>(
                c,
                &instance_commitments
                    .iter()
                    .map(|x| &x[..])
                    .collect::<Vec<_>>()[..],
                &mut t.iter_mut().collect::<Vec<_>>(),
                &mut ctx,
            )
        }
        _ => unreachable!(),
    };

    for check in commitment_check {
        ctx.ecc_assert_equal(&cl[check[0]][check[1]], &cl[check[2]][check[3]]);
    }

    assert!(pl[0].z.0.val == E::Scalar::zero());
    assert!(pl[1].z.0.val == E::Scalar::zero());

    let w_x = E::G1Affine::from_xy(ctx.get_w(&pl[0].x), ctx.get_w(&pl[0].y)).unwrap();
    let w_g = E::G1Affine::from_xy(ctx.get_w(&pl[1].x), ctx.get_w(&pl[1].y)).unwrap();

    let s_g2_prepared = E::G2Prepared::from(params.s_g2);
    let n_g2_prepared = E::G2Prepared::from(-params.g2);
    let success = bool::from(
        E::multi_miller_loop(&[(&w_x, &s_g2_prepared), (&w_g, &n_g2_prepared)])
            .final_exponentiation()
            .is_identity(),
    );

    assert!(success);

    let assigned_instances = pl
        .iter()
        .map(|p| ctx.ecc_encode(p))
        .collect::<Vec<_>>()
        .concat();

    for ai in assigned_instances.iter() {
        ctx.records.lock().unwrap().enable_permute(&ai.cell);
    }

    let instances = assigned_instances.iter().map(|x| x.val).collect::<Vec<_>>();

    (
        AggregatorCircuit::new(
            Rc::new(Arc::try_unwrap(ctx.records).unwrap().into_inner().unwrap()),
            assigned_instances,
        ),
        instances,
    )
}
