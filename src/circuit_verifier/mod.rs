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
        Vec<AssignedPoint<E::G1Affine, E::Scalar>>,
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
            EvalOps::MSM(psl) => {
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
        });
    }
    Ok((
        c.finals
            .iter()
            .map(|x| circuit.ecc_reduce(it[*x].0.as_ref().unwrap()))
            .collect(),
        instance_commitments.concat(),
        constants_hash,
    ))
}

pub fn build_single_proof_verify_circuit<E: MultiMillerLoop + G2AffineBaseHelper>(
    params: &ParamsVerifier<E>,
    vkey: &VerifyingKey<E::G1Affine>,
    instances: &Vec<Vec<E::Scalar>>,
    proof: Vec<u8>,
    hash: TranscriptHash,
    expose: Vec<[usize; 2]>,
    absorb: Vec<([usize; 3], [usize; 2])>, // the index of instance + the index of advices
    target_aggregator_constant_hash_instance_offset: Vec<([usize; 2])>, // (proof_index, instance_col)
    all_constant_hash: &mut Vec<E::Scalar>,
    layer_idx: usize,
    jump_agg_idx: usize,
    agg_idx: usize,
    max_layer: usize,
) -> (AggregatorCircuit<E::G1Affine>, Vec<E::Scalar>)
where
    NativeScalarEccContext<E::G1Affine>: PairingChipOps<E::G1Affine, E::Scalar>,
{
    build_aggregate_verify_circuit(
        params,
        &[vkey],
        vec![instances],
        vec![proof],
        hash,
        vec![],
        expose,
        absorb,
        target_aggregator_constant_hash_instance_offset,
        all_constant_hash,
        layer_idx,
        jump_agg_idx,
        agg_idx,
        max_layer,
    )
}

pub fn build_aggregate_verify_circuit<E: MultiMillerLoop + G2AffineBaseHelper>(
    params: &ParamsVerifier<E>,
    vkey: &[&VerifyingKey<E::G1Affine>],
    instances: Vec<&Vec<Vec<E::Scalar>>>,
    proofs: Vec<Vec<u8>>,
    hash: TranscriptHash,
    commitment_check: Vec<[usize; 4]>,
    expose: Vec<[usize; 2]>,
    absorb: Vec<([usize; 3], [usize; 2])>, // the index of instance + the index of advices,
    target_aggregator_constant_hash_instance_offset: Vec<([usize; 2])>, // (proof_index, instance_col)
    all_constant_hash: &mut Vec<E::Scalar>,
    layer_idx: usize,
    jump_agg_idx: usize,
    agg_idx: usize,
    max_layer: usize,
) -> (AggregatorCircuit<E::G1Affine>, Vec<E::Scalar>)
where
    NativeScalarEccContext<E::G1Affine>: PairingChipOps<E::G1Affine, E::Scalar>,
{
    let mut rest_tries = 100;
    let mut res = None;

    while rest_tries > 0 && res.is_none() {
        res = _build_aggregate_verify_circuit(
            params,
            vkey,
            instances.clone(),
            &proofs,
            hash,
            &commitment_check,
            &expose,
            &absorb,
            &target_aggregator_constant_hash_instance_offset,
            all_constant_hash,
            layer_idx,
            jump_agg_idx,
            agg_idx,
            max_layer,
        )
        .ok();
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
    hash: TranscriptHash,
    commitment_check: &Vec<[usize; 4]>,
    expose: &Vec<[usize; 2]>,
    absorb: &Vec<([usize; 3], [usize; 2])>, // the index of instance + the index of advices
    target_aggregator_constant_hash_instance_offset: &Vec<([usize; 2])>, // (proof_index, instance_col)
    all_constant_hash: &mut Vec<E::Scalar>,
    layer_idx: usize,
    jump_agg_idx: usize,
    agg_idx: usize,
    max_layer: usize,
) -> Result<(AggregatorCircuit<E::G1Affine>, Vec<E::Scalar>), UnsafeError>
where
    NativeScalarEccContext<E::G1Affine>: PairingChipOps<E::G1Affine, E::Scalar>,
{
    let ctx = Rc::new(RefCell::new(Context::new()));
    let ctx = IntegerContext::<<E::G1Affine as CurveAffine>::Base, E::Scalar>::new(ctx);
    let mut ctx = NativeScalarEccContext::<E::G1Affine>(ctx, 0);
    let (w_x, w_g, advices) = verify_aggregation_proofs(params, vkey, commitment_check);

    let instance_commitments = instance_to_instance_commitment(params, vkey, instances.clone());

    let mut targets = vec![w_x.0, w_g.0];

    for idx in commitment_check {
        targets.push(advices[idx[0]][idx[1]].0.clone());
        targets.push(advices[idx[2]][idx[3]].0.clone());
    }

    let absorb_start_idx = targets.len();

    for abs in absorb {
        targets.push(advices[abs.1[0]][abs.1[1]].0.clone());
    }

    let expose_start_idx = targets.len();

    for idx in expose {
        targets.push(advices[idx[0]][idx[1]].0.clone());
    }

    let c = EvalContext::translate(&targets[..]);
    let (pl, mut il, assigned_constant_hash) = match hash {
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

    all_constant_hash.resize(max_layer, E::Scalar::zero());

    let assigned_agg_idx = ctx
        .base_integer_chip()
        .base_chip()
        .assign(E::Scalar::from(agg_idx as u64));

    let mut hashes = vec![];
    // assign for constant_hashes
    for h in all_constant_hash.iter() {
        let v = ctx.base_integer_chip().base_chip().assign(*h);
        hashes.push(v);
    }

    if layer_idx == 0 {
        ctx.base_integer_chip()
            .base_chip()
            .assert_equal(&hashes[layer_idx], &assigned_constant_hash);
    } else {
        let candidate_hash0 = hashes[layer_idx - 1];
        let candidate_hash1 = hashes[layer_idx];

        let diff = ctx.base_integer_chip().base_chip().sum_with_constant(
            vec![(&assigned_agg_idx, E::Scalar::one())],
            Some(-E::Scalar::from(jump_agg_idx as u64)),
        );

        let is_jump = ctx.base_integer_chip().base_chip().is_zero(&diff);
        let expected_hash =
            ctx.base_integer_chip()
                .base_chip()
                .bisec(&is_jump, &candidate_hash0, &candidate_hash1);
        ctx.base_integer_chip()
            .base_chip()
            .assert_equal(&expected_hash, &assigned_constant_hash);
    }

    for check in pl[0..absorb_start_idx].chunks(2).skip(1) {
        ctx.ecc_assert_equal(&check[0], &check[1]);
    }

    /* il[target_aggregator_circuit's hash instance col] -= msm(
     *  [agg_idx - 1, hash[..]],
     *  params[?..]
     * )
     */
    for [proof_index, instance_col] in target_aggregator_constant_hash_instance_offset {
        let mut instance_index = *instance_col;
        for i in instances[0..*proof_index].iter() {
            instance_index += i.len()
        }

        let mut points = vec![];
        let mut scalars = vec![];

        let last_agg_idx = ctx.base_integer_chip().base_chip().sum_with_constant(
            vec![(&assigned_agg_idx, E::Scalar::one())],
            Some(-E::Scalar::one()),
        );

        points.push(ctx.assign_constant_point(&params.g_lagrange[0].to_curve()));
        scalars.push(last_agg_idx);
        for i in 0..max_layer {
            points.push(ctx.assign_constant_point(&params.g_lagrange[i + 1].to_curve()));
            scalars.push(hashes[i]);
        }

        let msm_c = ctx.msm(&points, &scalars);
        let diff_commit = ctx.ecc_neg(&msm_c);
        let instance_commit = il[instance_index].clone();
        let instance_commit_curv = ctx.to_point_with_curvature(instance_commit);
        let update_commit = ctx.ecc_add(&instance_commit_curv, &diff_commit);
        il[instance_index] = update_commit;
    }

    for (i, c) in pl[absorb_start_idx..expose_start_idx].iter().enumerate() {
        let encoded_c = ctx.ecc_encode(c);
        let [proof_index, instance_offset, g_index] = absorb[i].0;
        let mut instance_index = instance_offset;
        for i in instances[0..proof_index].iter() {
            instance_index += i.len()
        }

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

        let instance_commit = il[instance_index].clone();
        let g0 = ctx.assign_constant_point(&params.g_lagrange[g_index].to_curve());
        let g1 = ctx.assign_constant_point(&params.g_lagrange[g_index + 1].to_curve());
        let g2 = ctx.assign_constant_point(&params.g_lagrange[g_index + 2].to_curve());
        let msm_c = ctx.msm(&vec![g0, g1, g2], &encoded_c);
        let diff_commit = ctx.ecc_neg(&msm_c);
        let instance_commit_curv = ctx.to_point_with_curvature(instance_commit);
        let update_commit = ctx.ecc_add(&instance_commit_curv, &diff_commit);
        il[instance_index] = update_commit;
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

    let mut assigned_instances = vec![assigned_agg_idx];
    assigned_instances.append(&mut hashes);
    assigned_instances.append(
        &mut vec![&il[..], &pl[expose_start_idx..pl.len()]]
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
    let ctx: Context<_> = ctx.into();
    println!(
        "offset {} {} {}",
        ctx.base_offset, ctx.range_offset, ctx.select_offset
    );

    Ok((
        AggregatorCircuit::new(
            Rc::new(Arc::try_unwrap(ctx.records).unwrap().into_inner().unwrap()),
            assigned_instances,
        ),
        instances,
    ))
}
