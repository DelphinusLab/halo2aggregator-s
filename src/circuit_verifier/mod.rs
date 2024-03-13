use self::transcript::PoseidonChipRead;
use crate::api::ast_eval::EvalContext;
use crate::api::ast_eval::EvalOps;
use crate::api::ast_eval::EvalPos;
use crate::api::halo2::verify_aggregation_proofs;
use crate::circuit_verifier::circuit::AggregatorCircuit;
use crate::circuit_verifier::circuit::AggregatorCircuitOption;
use crate::circuit_verifier::circuit::AggregatorNoSelectCircuit;
use crate::circuits::utils::instance_to_instance_commitment;
use crate::circuits::utils::AggregatorConfig;
use crate::circuits::utils::TranscriptHash;
use crate::transcript::poseidon::PoseidonRead;
use halo2_proofs::arithmetic::CurveAffine;
use halo2_proofs::arithmetic::Field;
use halo2_proofs::arithmetic::MillerLoopResult;
use halo2_proofs::arithmetic::MultiMillerLoop;
use halo2_proofs::pairing::bn256::Bn256;
use halo2_proofs::pairing::bn256::Fq;
use halo2_proofs::pairing::bn256::Fq2;
use halo2_proofs::pairing::group::prime::PrimeCurveAffine;
use halo2_proofs::pairing::group::Group;
use halo2_proofs::plonk::VerifyingKey;
use halo2_proofs::poly::commitment::ParamsVerifier;
use halo2ecc_s::assign::AssignedPoint;
use halo2ecc_s::assign::AssignedValue;
use halo2ecc_s::circuit::ecc_chip::EccBaseIntegerChipWrapper;
use halo2ecc_s::circuit::ecc_chip::EccChipBaseOps;
use halo2ecc_s::circuit::ecc_chip::EccChipScalarOps;
use halo2ecc_s::circuit::ecc_chip::UnsafeError;
use halo2ecc_s::circuit::keccak_chip::KeccakChipOps;
use halo2ecc_s::circuit::pairing_chip::PairingChipOps;
use halo2ecc_s::context::Context;
use halo2ecc_s::context::IntegerContext;
use halo2ecc_s::context::NativeScalarEccContext;
use std::cell::RefCell;
use std::io;
use std::rc::Rc;
use std::sync::Arc;

pub mod circuit;
pub mod transcript;

fn context_eval<E: MultiMillerLoop, R: io::Read>(
    c: EvalContext<E::G1Affine>,
    instance_commitments: &[&[E::G1Affine]],
    t: &mut [&mut PoseidonChipRead<R, E::G1Affine>],
    circuit: &mut NativeScalarEccContext<E::G1Affine>,
    // Expose hash of constant value to instance to uniform the aggregator circuit
    constants_hasher: &mut PoseidonChipRead<R, E::G1Affine>,
) -> Result<
    (
        Vec<AssignedPoint<E::G1Affine, E::Scalar>>,
        Vec<Vec<AssignedPoint<E::G1Affine, E::Scalar>>>,
        AssignedValue<E::Scalar>,
    ),
    UnsafeError,
> {
    let mut it: Vec<(
        Option<AssignedPoint<E::G1Affine, E::Scalar>>,
        Option<AssignedValue<E::Scalar>>,
    )> = vec![];
    let const_scalars = {
        c.const_scalars
            .iter()
            .map(|c| circuit.base_integer_chip().base_chip().assign(*c))
            .collect::<Vec<_>>()
    };

    for c in const_scalars.iter() {
        constants_hasher.common_scalar(circuit, c);
    }

    let const_points = {
        c.const_points
            .iter()
            .map(|c| circuit.assign_point(&c.to_curve()))
            .collect::<Vec<_>>()
    };

    for c in const_points.iter() {
        constants_hasher.common_point(circuit, c);
    }

    let constants_hash = constants_hasher.squeeze(circuit);

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
                (Some(p), None)
            }
            EvalOps::TranscriptCommonScalar(i, _, s) => {
                t[*i].common_scalar(circuit, eval_scalar_pos!(s));
                (None, None)
            }
            EvalOps::TranscriptCommonPoint(i, _, p) => {
                t[*i].common_point(circuit, eval_point_pos!(p));
                (None, None)
            }
            EvalOps::TranscriptSqueeze(i, _) => (None, Some(t[*i].squeeze(circuit))),
            EvalOps::ScalarAdd(a, b) => (
                None,
                Some(
                    circuit
                        .base_integer_chip()
                        .base_chip()
                        .add(eval_scalar_pos!(a), eval_scalar_pos!(b)),
                ),
            ),
            EvalOps::ScalarSub(a, b) => (
                None,
                Some(
                    circuit
                        .base_integer_chip()
                        .base_chip()
                        .sub(eval_scalar_pos!(a), eval_scalar_pos!(b)),
                ),
            ),
            EvalOps::ScalarMul(a, b, _) => (
                None,
                Some(
                    circuit
                        .base_integer_chip()
                        .base_chip()
                        .mul(eval_scalar_pos!(a), eval_scalar_pos!(b)),
                ),
            ),
            EvalOps::ScalarDiv(a, b) => (
                None,
                Some(
                    circuit
                        .base_integer_chip()
                        .base_chip()
                        .div_unsafe(eval_scalar_pos!(a), eval_scalar_pos!(b)),
                ),
            ),
            EvalOps::ScalarPow(a, n) => {
                let mut p = *n;
                let mut c = vec![];
                let mut acc = eval_scalar_pos!(a).clone();
                while p > 0 {
                    if p & 1 == 1 {
                        c.push(acc);
                    }
                    acc = circuit.base_integer_chip().base_chip().mul(&acc, &acc);
                    p >>= 1;
                }
                let s = c
                    .into_iter()
                    .reduce(|acc, x| circuit.base_integer_chip().base_chip().mul(&acc, &x))
                    .unwrap();
                (None, Some(s))
            }
            EvalOps::MSM(psl, _) => {
                let pl = psl
                    .iter()
                    .map(|(p, _)| eval_point_pos!(p).clone())
                    .collect();
                let sl = psl
                    .iter()
                    .map(|(_, s)| eval_scalar_pos!(s).clone())
                    .collect();

                #[cfg(feature = "unsafe")]
                let res = (Some(circuit.msm_unsafe(&pl, &sl)?), None);

                #[cfg(not(feature = "unsafe"))]
                let res = (Some(circuit.msm(&pl, &sl)), None);

                res
            }
            EvalOps::CheckPoint(tag, v) => {
                if false {
                    println!("checkpoint {}: {:?}", tag, eval_any_pos!(v));
                }
                eval_any_pos!(v)
            }
            EvalOps::MSMSlice(_, _, _) => {
                // ignore MSMSlice in circuit
                (None, None)
            }
        });
    }
    Ok((
        c.finals
            .iter()
            .map(|x| circuit.ecc_reduce(it[*x].0.as_ref().unwrap()))
            .collect(),
        instance_commitments,
        constants_hash,
    ))
}

pub fn build_single_proof_verify_circuit<E: MultiMillerLoop + G2AffineBaseHelper>(
    params: &ParamsVerifier<E>,
    vkey: &VerifyingKey<E::G1Affine>,
    instances: &Vec<Vec<E::Scalar>>,
    proof: Vec<u8>,
    config: &AggregatorConfig<E::Scalar>,
) -> (
    AggregatorCircuitOption<E::G1Affine>,
    Vec<E::Scalar>,
    Vec<E::Scalar>,
    E::Scalar,
)
where
    NativeScalarEccContext<E::G1Affine>: PairingChipOps<E::G1Affine, E::Scalar>,
{
    build_aggregate_verify_circuit(params, &[vkey], vec![instances], vec![proof], config)
}

pub fn build_aggregate_verify_circuit<E: MultiMillerLoop + G2AffineBaseHelper>(
    params: &ParamsVerifier<E>,
    vkey: &[&VerifyingKey<E::G1Affine>],
    instances: Vec<&Vec<Vec<E::Scalar>>>,
    proofs: Vec<Vec<u8>>,
    config: &AggregatorConfig<E::Scalar>,
) -> (
    AggregatorCircuitOption<E::G1Affine>,
    Vec<E::Scalar>,
    Vec<E::Scalar>,
    E::Scalar,
)
where
    NativeScalarEccContext<E::G1Affine>: PairingChipOps<E::G1Affine, E::Scalar>,
{
    let mut rest_tries = 100;
    let mut res = None;

    while rest_tries > 0 && res.is_none() {
        res =
            _build_aggregate_verify_circuit(params, vkey, instances.clone(), &proofs, config).ok();
        rest_tries -= 1;
    }

    res.unwrap()
}

pub trait G2AffineBaseHelper: MultiMillerLoop {
    fn decode(
        b: <Self::G2Affine as CurveAffine>::Base,
    ) -> (
        <Self::G1Affine as CurveAffine>::Base,
        <Self::G1Affine as CurveAffine>::Base,
    );
}

impl G2AffineBaseHelper for Bn256 {
    fn decode(b: Fq2) -> (Fq, Fq) {
        (b.c0, b.c1)
    }
}

/* expose: expose target circuits' commitments to current aggregator circuits' instance
 * absorb: absorb target circuits' commitments to target aggregator circuits' instance
 * target_aggregator_constant_hash_instance: instance_offset of target_aggregator for constant_hash
 * prev_constant_hash: all previous constant_hash (hash of all circuits' constant values) of aggregators layer
 * layer_idx: current aggregator's layer index
 */
pub fn _build_aggregate_verify_circuit<E: MultiMillerLoop + G2AffineBaseHelper>(
    params: &ParamsVerifier<E>,
    vkey: &[&VerifyingKey<E::G1Affine>],
    instances: Vec<&Vec<Vec<E::Scalar>>>,
    proofs: &Vec<Vec<u8>>,
    config: &AggregatorConfig<E::Scalar>,
) -> Result<
    (
        AggregatorCircuitOption<E::G1Affine>,
        Vec<E::Scalar>,
        Vec<E::Scalar>,
        E::Scalar,
    ),
    UnsafeError,
>
where
    NativeScalarEccContext<E::G1Affine>: PairingChipOps<E::G1Affine, E::Scalar>,
{
    let ctx = Rc::new(RefCell::new(Context::new()));
    let ctx = IntegerContext::<<E::G1Affine as CurveAffine>::Base, E::Scalar>::new(ctx);
    let mut ctx = if config.use_select_chip {
        NativeScalarEccContext::<E::G1Affine>::new_with_select_chip(ctx)
    } else {
        NativeScalarEccContext::<E::G1Affine>::new_without_select_chip(ctx)
    };

    let (w_x, w_g, advices) = verify_aggregation_proofs(
        params,
        vkey,
        &config.commitment_check,
        config.target_proof_with_shplonk_as_default,
        &config.target_proof_with_shplonk,
    );

    let instance_commitments = instance_to_instance_commitment(params, vkey, instances.clone());

    let mut targets = vec![w_x.0, w_g.0];

    for idx in &config.commitment_check {
        targets.push(advices[idx[0]][idx[1]].0.clone());
        targets.push(advices[idx[2]][idx[3]].0.clone());
    }

    let absorb_start_idx = targets.len();

    for abs in &config.absorb {
        targets.push(advices[abs.1[0]][abs.1[1]].0.clone());
    }

    let expose_start_idx = targets.len();

    for idx in &config.expose {
        targets.push(advices[idx[0]][idx[1]].0.clone());
    }

    let c = EvalContext::translate(&targets[..]);
    let (pl, mut il, assigned_constant_hash) = match config.hash {
        TranscriptHash::Poseidon => {
            let mut t = vec![];
            for i in 0..proofs.len() {
                let it = PoseidonRead::init(&proofs[i][..]);
                t.push(PoseidonChipRead::init(it, &mut ctx));
            }
            let empty = vec![];
            let it = PoseidonRead::init(&empty[..]);
            t.push(PoseidonChipRead::init(it, &mut ctx));

            let mut constant_hasher =
                PoseidonChipRead::init(PoseidonRead::init(&empty[..]), &mut ctx);

            context_eval::<E, _>(
                c,
                &instance_commitments
                    .iter()
                    .map(|x| &x[..])
                    .collect::<Vec<_>>()[..],
                &mut t.iter_mut().collect::<Vec<_>>(),
                &mut ctx,
                &mut constant_hasher,
            )?
        }
        _ => unreachable!(),
    };

    for check in pl[0..absorb_start_idx].chunks(2).skip(1) {
        ctx.ecc_assert_equal(&check[0], &check[1]);
    }

    for (proof_idx_of_target, columns, proof_idx_of_prev_agg, expose_row) in
        config.absorb_instance.iter()
    {
        let encoded_c = ctx.ecc_encode(&il[*proof_idx_of_target][*columns]);
        let instance_commit = il[*proof_idx_of_prev_agg][0].clone();
        let g0 = ctx.assign_constant_point(&params.g_lagrange[*expose_row].to_curve());
        let g1 = ctx.assign_constant_point(&params.g_lagrange[*expose_row + 1].to_curve());
        let g2 = ctx.assign_constant_point(&params.g_lagrange[*expose_row + 2].to_curve());
        let msm_c = ctx.msm_unsafe(&vec![g0, g1, g2], &encoded_c)?;
        let diff_commit = ctx.ecc_neg(&msm_c);
        let instance_commit_curv = ctx.to_point_with_curvature(instance_commit);
        let update_commit = ctx.ecc_add(&instance_commit_curv, &diff_commit);
        il[*proof_idx_of_prev_agg][0] = update_commit;
    }

    let assigned_final_hash = {
        let empty = vec![];
        let mut hasher = PoseidonChipRead::init(PoseidonRead::init(&empty[..]), &mut ctx);

        // il[target_aggregator_circuit's hash instance col] -= params[0] * hash
        for (proof_index, instance_col, hash) in
            &config.target_aggregator_constant_hash_instance_offset
        {
            let assigned_hash = ctx.base_integer_chip().base_chip().assign(*hash);
            hasher.common_scalar(&mut ctx, &assigned_hash);

            let mut points = vec![];
            let mut scalars = vec![];
            points.push(ctx.assign_constant_point(&(-params.g_lagrange[0]).to_curve()));
            scalars.push(assigned_hash);

            let diff_commitment = ctx.msm(&points, &scalars);
            let instance_commit = il[*proof_index][*instance_col].clone();
            let instance_commit_curv = ctx.to_point_with_curvature(instance_commit);
            let update_commit = ctx.ecc_add(&instance_commit_curv, &diff_commitment);
            il[*proof_index][*instance_col] = update_commit;
        }

        hasher.common_scalar(&mut ctx, &assigned_constant_hash);

        hasher.squeeze(&mut ctx)
    };

    for (i, c) in pl[absorb_start_idx..expose_start_idx].iter().enumerate() {
        let encoded_c = ctx.ecc_encode(c);
        let [proof_index, instance_offset, g_index] = config.absorb[i].0;

        assert_eq!(
            instances[proof_index][instance_offset][g_index],
            encoded_c[0].val
        );
        assert_eq!(
            instances[proof_index][instance_offset][g_index + 1],
            encoded_c[1].val
        );
        assert_eq!(
            instances[proof_index][instance_offset][g_index + 2],
            encoded_c[2].val
        );

        let instance_commit = il[proof_index][instance_offset].clone();
        let g0 = ctx.assign_constant_point(&params.g_lagrange[g_index].to_curve());
        let g1 = ctx.assign_constant_point(&params.g_lagrange[g_index + 1].to_curve());
        let g2 = ctx.assign_constant_point(&params.g_lagrange[g_index + 2].to_curve());
        let msm_c = ctx.msm_unsafe(&vec![g0, g1, g2], &encoded_c)?;
        let diff_commit = ctx.ecc_neg(&msm_c);
        let instance_commit_curv = ctx.to_point_with_curvature(instance_commit);
        let update_commit = ctx.ecc_add(&instance_commit_curv, &diff_commit);
        il[proof_index][instance_offset] = update_commit;
    }

    assert!(pl[0].z.0.val == E::Scalar::zero());
    assert!(pl[1].z.0.val == E::Scalar::zero());

    let w_x = E::G1Affine::from_xy(
        ctx.base_integer_chip().get_w(&pl[0].x),
        ctx.base_integer_chip().get_w(&pl[0].y),
    )
    .unwrap();
    let w_g = E::G1Affine::from_xy(
        ctx.base_integer_chip().get_w(&pl[1].x),
        ctx.base_integer_chip().get_w(&pl[1].y),
    )
    .unwrap();

    let s_g2_prepared = E::G2Prepared::from(params.s_g2);
    let n_g2_prepared = E::G2Prepared::from(-params.g2);
    let success = bool::from(
        E::multi_miller_loop(&[(&w_x, &s_g2_prepared), (&w_g, &n_g2_prepared)])
            .final_exponentiation()
            .is_identity(),
    );

    assert!(success);

    {
        use halo2ecc_s::assign::AssignedCondition;
        use halo2ecc_s::assign::AssignedG2Affine;
        use halo2ecc_s::circuit::fq12::Fq2ChipOps;

        let s_g2 = params.s_g2.coordinates().unwrap();
        let s_g2_x = *s_g2.x();
        let s_g2_y = *s_g2.y();
        let assigned_s_g2_x = ctx.fq2_assign_constant(E::decode(s_g2_x));
        let assigned_s_g2_y = ctx.fq2_assign_constant(E::decode(s_g2_y));

        let g2 = (-params.g2).coordinates().unwrap();
        let g2_x = *g2.x();
        let g2_y = *g2.y();
        let assigned_g2_x = ctx.fq2_assign_constant(E::decode(g2_x));
        let assigned_g2_y = ctx.fq2_assign_constant(E::decode(g2_y));

        let z = AssignedCondition(
            ctx.base_integer_chip()
                .base_chip()
                .assign_constant(E::Scalar::zero()),
        );

        let assigned_s_g2 = AssignedG2Affine::new(assigned_s_g2_x, assigned_s_g2_y, z);
        let assigned_g2 = AssignedG2Affine::new(assigned_g2_x, assigned_g2_y, z);
        ctx.check_pairing(&[(&pl[0], &assigned_s_g2), (&pl[1], &assigned_g2)]);
    }

    // Fake instance is not the real instance of the final aggregator.
    // The final aggregator should hash all fake instance and target circuit instance to get the real instance.
    let (assigned_instances, instances, shadow_instances) = if !config.is_final_aggregator {
        let mut assigned_instances = vec![assigned_final_hash];
        assigned_instances.append(
            &mut vec![&il.concat()[..], &pl[expose_start_idx..pl.len()]]
                .concat()
                .iter()
                .map(|p| ctx.ecc_encode(p))
                .collect::<Vec<_>>()
                .concat(),
        );

        for ai in assigned_instances.iter() {
            ctx.0
                .ctx
                .borrow()
                .records
                .lock()
                .unwrap()
                .enable_permute(&ai.cell);
        }

        let instances = assigned_instances.iter().map(|x| x.val).collect::<Vec<_>>();

        (assigned_instances, instances, vec![])
    } else {
        let mut hash_list = vec![];
        for (proof_idx, max_row_of_cols) in config.target_proof_max_instance.iter().enumerate() {
            for (column_idx, max_row) in max_row_of_cols.iter().enumerate() {
                let mut start_row = 0;
                let end_row = *max_row;

                if let Some((_, skips)) = config
                    .prev_aggregator_skip_instance
                    .iter()
                    .find(|(pi, _)| *pi == proof_idx)
                {
                    // aggregagtor only has one instance column
                    assert!(column_idx == 0);
                    start_row += skips;
                }

                let instance_commitment = if end_row > start_row {
                    let mut sl = vec![];
                    for row_idx in start_row..end_row {
                        let assigned_s = ctx.base_integer_chip().base_chip().assign(
                            instances[proof_idx][column_idx]
                                .get(row_idx)
                                .cloned()
                                .unwrap_or(E::Scalar::zero()),
                        );
                        hash_list.push(assigned_s.clone());
                        sl.push(assigned_s)
                    }

                    let mut pl = vec![];
                    for row_idx in start_row..end_row {
                        let assigned_p =
                            ctx.assign_constant_point(&params.g_lagrange[row_idx].to_curve());
                        pl.push(assigned_p);
                    }

                    #[cfg(feature = "unsafe")]
                    let instance_commitment = ctx.msm_unsafe(&pl, &sl)?;

                    #[cfg(not(feature = "unsafe"))]
                    let instance_commitment = ctx.msm(&pl, &sl);

                    instance_commitment
                } else {
                    let instance_commitment =
                        ctx.assign_constant_point(&E::G1Affine::identity().to_curve());

                    instance_commitment
                };

                ctx.ecc_assert_equal(&instance_commitment, &il[proof_idx][column_idx]);
            }
        }

        let mut assigned_shadow_instances = vec![assigned_final_hash];

        assigned_shadow_instances.append(
            &mut vec![&pl[expose_start_idx..pl.len()]]
                .concat()
                .iter()
                .map(|p| ctx.ecc_encode(p))
                .collect::<Vec<_>>()
                .concat(),
        );

        let shadow_instances = assigned_shadow_instances
            .iter()
            .map(|x| x.val)
            .collect::<Vec<_>>();

        println!(
            "hash_list before fake instance {:?}",
            assigned_shadow_instances
                .iter()
                .map(|x| x.val)
                .collect::<Vec<_>>()
        );

        hash_list.append(&mut assigned_shadow_instances);

        let assigned_instances = vec![ctx.0.ctx.borrow_mut().hash(&hash_list[..])];

        for ai in assigned_instances.iter() {
            ctx.0
                .ctx
                .borrow()
                .records
                .lock()
                .unwrap()
                .enable_permute(&ai.cell);
        }

        let instances = assigned_instances.iter().map(|x| x.val).collect::<Vec<_>>();

        (assigned_instances, instances, shadow_instances)
    };

    let ctx: Context<_> = ctx.into();
    println!("offset {} {} {}", ctx.base_offset, ctx.range_offset, ctx.select_offset);

    let circuit = if config.use_select_chip {
        AggregatorCircuit::new(
            Rc::new(Arc::try_unwrap(ctx.records).unwrap().into_inner().unwrap()),
            assigned_instances,
        )
        .into()
    } else {
        AggregatorNoSelectCircuit::new(
            Rc::new(Arc::try_unwrap(ctx.records).unwrap().into_inner().unwrap()),
            assigned_instances,
        )
        .into()
    };

    Ok((
        circuit,
        instances,
        shadow_instances,
        assigned_constant_hash.val,
    ))
}
