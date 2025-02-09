use super::GtHelper;
use crate::api::ast_eval::EvalContext;
use crate::api::ast_eval::EvalOps;
use crate::api::ast_eval::EvalPos;
use crate::api::halo2::verify_aggregation_proofs;
use crate::circuit_verifier::transcript::PoseidonChipRead;
use crate::circuit_verifier::G2AffineBaseHelper;
use crate::circuits::utils::instance_to_instance_commitment;
use crate::circuits::utils::miller_loop_compute_c_wi;
use crate::circuits::utils::AggregatorConfig;
use crate::circuits::utils::TranscriptHash;
use crate::transcript::poseidon::PoseidonPure;
use crate::transcript::poseidon::*;
use crate::utils::bn_to_field;
use ark_std::end_timer;
use ark_std::start_timer;
use halo2_proofs::arithmetic::CurveAffine;
use halo2_proofs::arithmetic::MillerLoopResult;
use halo2_proofs::arithmetic::MultiMillerLoop;
use halo2_proofs::arithmetic::MultiMillerLoopOnProvePairing;
use halo2_proofs::circuit::floor_planner::FlatFloorPlanner;
use halo2_proofs::circuit::Layouter;
use halo2_proofs::pairing::group::prime::PrimeCurveAffine;
use halo2_proofs::pairing::group::Group;
use halo2_proofs::plonk::Circuit;
use halo2_proofs::plonk::Column;
use halo2_proofs::plonk::ConstraintSystem;
use halo2_proofs::plonk::Error;
use halo2_proofs::plonk::Instance;
use halo2_proofs::plonk::VerifyingKey;
use halo2_proofs::poly::commitment::ParamsVerifier;
use halo2ecc_o::assign::*;
use halo2ecc_o::chips::ecc_chip::EccChipBaseOps;
use halo2ecc_o::chips::ecc_chip::EccUnsafeError;
use halo2ecc_o::chips::keccak_chip::KeccakChipOps;
use halo2ecc_o::chips::msm_chip::EccChipMSMOps;
use halo2ecc_o::chips::native_chip::NativeChipOps;
use halo2ecc_o::chips::pairing_chip::fq::Fq12ChipOps;
use halo2ecc_o::chips::pairing_chip::fq::Fq2ChipOps;
use halo2ecc_o::chips::pairing_chip::PairingChipOnProvePairingOps;
use halo2ecc_o::chips::pairing_chip::PairingChipOps;
use halo2ecc_o::context::NativeScalarEccContext;
use halo2ecc_o::context::ParallelClone;
use halo2ecc_o::NativeScalarEccConfig;
use std::borrow::Borrow;
use std::io;
use std::sync::Arc;

#[derive(Clone)]
pub struct AggregatorChipConfig {
    ecc_chip_config: NativeScalarEccConfig,
    instance_col: Column<Instance>,
}

#[derive(Clone)]
pub struct AggregatorCircuit<E: MultiMillerLoop> {
    pub(crate) params: Arc<ParamsVerifier<E>>,
    pub(crate) vkey: Vec<Arc<VerifyingKey<E::G1Affine>>>,
    pub(crate) config: Arc<AggregatorConfig<E::Scalar>>,
    pub(crate) instances: Vec<Vec<Vec<E::Scalar>>>,
    pub(crate) proofs: Vec<Vec<u8>>,
}

impl<E: MultiMillerLoop> AggregatorCircuit<E> {
    pub fn new(
        params: Arc<ParamsVerifier<E>>,
        vkey: Vec<Arc<VerifyingKey<E::G1Affine>>>,
        config: Arc<AggregatorConfig<E::Scalar>>,
        instances: Vec<Vec<Vec<E::Scalar>>>,
        proofs: Vec<Vec<u8>>,
    ) -> Self {
        Self {
            params,
            vkey,
            config,
            instances,
            proofs,
        }
    }
}

impl<E: MultiMillerLoop + MultiMillerLoopOnProvePairing + GtHelper + G2AffineBaseHelper>
    Circuit<E::Scalar> for AggregatorCircuit<E>
{
    type Config = AggregatorChipConfig;
    type FloorPlanner = FlatFloorPlanner;

    fn without_witnesses(&self) -> Self {
        self.clone()
    }

    fn configure(meta: &mut ConstraintSystem<E::Scalar>) -> Self::Config {
        let instance_col = meta.instance_column();
        meta.enable_equality(instance_col);

        AggregatorChipConfig {
            ecc_chip_config: NativeScalarEccConfig::configure::<E::G1Affine>(meta),
            instance_col,
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        layouter: impl Layouter<E::Scalar>,
    ) -> Result<(), Error> {
        let timer = start_timer!(|| "synthesize");

        let assigned_instances = layouter.assign_region(
            || "base",
            |region| {
                let timer = start_timer!(|| "assign");
                let mut context = config.ecc_chip_config.to_context(region);

                let (instances, _, _) = synthesize_aggregate_verify_circuit(
                    &mut context,
                    &self.params,
                    &self.vkey.iter().map(|x| x.borrow()).collect::<Vec<_>>()[..],
                    self.instances.clone(),
                    &self.proofs,
                    &self.config,
                )
                .unwrap();
                end_timer!(timer);

                let timer = start_timer!(|| "finalize int mul");
                context.integer_context().finalize_int_mul()?;
                end_timer!(timer);

                context.get_range_region_context().init()?;
                let timer = start_timer!(|| "finalize compact cells");
                context
                    .get_range_region_context()
                    .finalize_compact_cells()?;
                end_timer!(timer);

                Ok(instances)
            },
        )?;

        for (i, assigned_instance) in assigned_instances.into_iter().enumerate() {
            layouter.constrain_instance(assigned_instance.cell(), config.instance_col, i)?;
        }

        end_timer!(timer);

        Ok(())
    }
}

/* expose: expose target circuits' commitments to current aggregator circuits' instance
 * absorb: absorb target circuits' commitments to target aggregator circuits' instance
 * target_aggregator_constant_hash_instance: instance_offset of target_aggregator for constant_hash
 * prev_constant_hash: all previous constant_hash (hash of all circuits' constant values) of aggregators layer
 * layer_idx: current aggregator's layer index
 */
pub fn synthesize_aggregate_verify_circuit<
    E: MultiMillerLoop + MultiMillerLoopOnProvePairing + GtHelper + G2AffineBaseHelper,
>(
    ctx: &mut NativeScalarEccContext<'_, E::G1Affine>,
    params: &ParamsVerifier<E>,
    vkey: &[&VerifyingKey<E::G1Affine>],
    instances: Vec<Vec<Vec<E::Scalar>>>,
    proofs: &Vec<Vec<u8>>,
    config: &AggregatorConfig<E::Scalar>,
) -> Result<
    (
        Vec<AssignedValue<E::Scalar>>,
        Vec<AssignedValue<E::Scalar>>,
        AssignedValue<E::Scalar>,
    ),
    EccUnsafeError,
> {
    let instance_commitments =
        instance_to_instance_commitment(&params, vkey, instances.iter().collect());

    // Build AST tree.
    let (w_x, w_g, advices) = verify_aggregation_proofs(
        params,
        vkey,
        &config.commitment_check,
        config.target_proof_with_shplonk_as_default,
        &config.target_proof_with_shplonk,
    );

    // Push commitment ast entry to targets vector.
    // Then context_eval can return their coresponding cells in circuit.
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

    // The translate() apply typological sorting for entries in targets vector.
    let c = EvalContext::translate(&targets[..]);
    let poseidon = PoseidonPure::default();

    let (pl, mut il, assigned_constant_hash) = match config.hash {
        TranscriptHash::Poseidon => {
            let mut t = vec![];
            // Prepare Transcript Chip for each proof.
            for i in 0..proofs.len() {
                let it = PoseidonRead::init_with_poseidon(&proofs[i][..], poseidon.clone());
                t.push(PoseidonChipRead::init(it, ctx));
            }

            // The last Transcript Chip is for challenge used to batch pairing.
            let empty = vec![];
            let it = PoseidonRead::init_with_poseidon(&empty[..], poseidon.clone());
            t.push(PoseidonChipRead::init(it, ctx));

            // To uniform circuit from fixed commitments/scalars,
            // the fixed commitments/scalars will assigned as witness,
            // and expose a hash at instance[0].
            let mut constant_hasher = PoseidonChipRead::init(
                PoseidonRead::init_with_poseidon(&empty[..], poseidon.clone()),
                ctx,
            );

            // The context_eval() constructs circuit.
            context_eval::<E, _>(
                c,
                &instance_commitments
                    .iter()
                    .map(|x| &x[..])
                    .collect::<Vec<_>>()[..],
                &mut t.iter_mut().collect::<Vec<_>>(),
                ctx,
                &mut constant_hasher,
            )?
        }
        _ => unreachable!(),
    };

    // Advice column commitment check
    for check in pl[0..absorb_start_idx].chunks(2).skip(1) {
        ctx.ecc_assert_equal(&check[0], &check[1])?;
    }

    // Absorb: remove an encoded commitment (of target circuit)
    //         from instance commitment (of last round aggregator).
    // new_instance_commitment =
    //         instance_commitment - MSM(encoded points, params.g1[row..row + encoded_len])
    for (proof_idx_of_target, columns, proof_idx_of_prev_agg, expose_row) in
        config.absorb_instance.iter()
    {
        // Encode commitment to scalar vec.
        let encoded_c = ctx.ecc_encode(&il[*proof_idx_of_target][*columns])?;

        // Aggregator circuit only has 1 instance column.
        assert!(il[*proof_idx_of_prev_agg].len() == 1);
        let instance_commit = il[*proof_idx_of_prev_agg][0].clone();

        // Encoded scalars must be 3-element vec.
        assert!(encoded_c.len() == 3);
        let g0 = ctx.assign_constant_point(params.g_lagrange[*expose_row + 0])?;
        let g1 = ctx.assign_constant_point(params.g_lagrange[*expose_row + 1])?;
        let g2 = ctx.assign_constant_point(params.g_lagrange[*expose_row + 2])?;

        let msm_c = ctx.msm_unsafe(&vec![g0, g1, g2], &encoded_c)?;
        let diff_commit = ctx.ecc_neg(&msm_c)?;
        let update_commit = ctx.ecc_add(&instance_commit, &diff_commit)?;
        il[*proof_idx_of_prev_agg][0] = update_commit;
    }

    // Generate the aggregator hash H,
    // it can determine the aggregator round number and target circuits.
    // H_0 = Hash(constant_hash)
    // H_i = Hash(H_{i-1}, constant_hash), i > 0.
    let assigned_final_hash = {
        let empty = vec![];
        let mut hasher = PoseidonChipRead::init(
            PoseidonRead::init_with_poseidon(&empty[..], poseidon.clone()),
            ctx,
        );

        for (proof_index, instance_col, hash) in
            &config.target_aggregator_constant_hash_instance_offset
        {
            // The value is restricted in current version, because aggregator only has one instance column.
            assert!(*instance_col == 0);
            // To avoid incorrect config in current version.
            assert!(*hash == instances[*proof_index][*instance_col][0]);

            let assigned_hash = ctx.integer_context().plonk_region_context().assign(*hash)?;
            hasher.common_scalar(ctx, &assigned_hash);

            // Absorb the H_{i-1} from the last round aggregator's instance commitment.
            // il[target_aggregator_circuit's hash instance col] -= params[0] * hash
            let mut points = vec![];
            let mut scalars = vec![];
            // The aggregator hash is always placed at row 0.
            points.push(ctx.assign_constant_point(-params.g_lagrange[0])?);
            scalars.push(assigned_hash);

            let diff_commitment = ctx.msm_unsafe(&points, &scalars)?;
            let instance_commit = &il[*proof_index][*instance_col];
            let update_commit = ctx.ecc_add(instance_commit, &diff_commitment)?;
            il[*proof_index][*instance_col] = update_commit;
        }

        hasher.common_scalar(ctx, &assigned_constant_hash);

        hasher.squeeze(ctx)
    };

    macro_rules! assert_eq_on_some {
        ($l:expr, $r:expr) => {
            match $r {
                Some(v) => {
                    assert_eq!($l, v)
                }
                None => {}
            }
        };
    }

    // Expose advice commitments as encoded scalars into aggregator's instance
    for (i, c) in pl[absorb_start_idx..expose_start_idx].iter().enumerate() {
        let encoded_c = ctx.ecc_encode(c)?;
        let [proof_index, instance_offset, g_index] = config.absorb[i].0;

        assert_eq_on_some!(
            instances[proof_index][instance_offset][g_index],
            encoded_c[0].value()
        );
        assert_eq_on_some!(
            instances[proof_index][instance_offset][g_index + 1],
            encoded_c[1].value()
        );
        assert_eq_on_some!(
            instances[proof_index][instance_offset][g_index + 2],
            encoded_c[2].value()
        );

        let instance_commit = il[proof_index][instance_offset].clone();
        // Encoded scalars must be 3-element vec.
        assert!(encoded_c.len() == 3);
        let g0 = ctx.assign_constant_point(params.g_lagrange[g_index + 0])?;
        let g1 = ctx.assign_constant_point(params.g_lagrange[g_index + 1])?;
        let g2 = ctx.assign_constant_point(params.g_lagrange[g_index + 2])?;
        let msm_c = ctx.msm_unsafe(&vec![g0, g1, g2], &encoded_c)?;
        let diff_commit = ctx.ecc_neg(&msm_c)?;
        let update_commit = ctx.ecc_add(&instance_commit, &diff_commit)?;
        il[proof_index][instance_offset] = update_commit;
    }

    // Check pairing result for debug purpose.
    let pairing_c_wi = {
        // Assert because circuit does it in multi_miller_loop()
        assert_eq_on_some!(E::Scalar::from(0u64), pl[0].z.value());
        assert_eq_on_some!(E::Scalar::from(0u64), pl[1].z.value());

        let (w_x, w_g) = if pl[0].z.value().is_none() {
            // For setup stage
            (E::G1Affine::identity(), E::G1Affine::identity())
        } else {
            let w_x = E::G1Affine::from_xy(
                bn_to_field(
                    ctx.get_integer_context()
                        .get_w_bn(&pl[0].x)
                        .as_ref()
                        .unwrap(),
                ),
                bn_to_field(
                    ctx.get_integer_context()
                        .get_w_bn(&pl[0].y)
                        .as_ref()
                        .unwrap(),
                ),
            )
            .unwrap();

            let w_g = E::G1Affine::from_xy(
                bn_to_field(
                    ctx.get_integer_context()
                        .get_w_bn(&pl[1].x)
                        .as_ref()
                        .unwrap(),
                ),
                bn_to_field(
                    ctx.get_integer_context()
                        .get_w_bn(&pl[1].y)
                        .as_ref()
                        .unwrap(),
                ),
            )
            .unwrap();

            (w_x, w_g)
        };

        let s_g2_prepared = E::G2Prepared::from(params.s_g2);
        let n_g2_prepared = E::G2Prepared::from(-params.g2);
        let f = E::multi_miller_loop(&[(&w_x, &s_g2_prepared), (&w_g, &n_g2_prepared)]);
        //verify pairing with final exponent
        let success = bool::from(f.final_exponentiation().is_identity());
        assert!(success);

        if E::support_on_prove_pairing() {
            #[cfg(not(feature = "on_prove_pairing_affine"))]
            {
                //verify pairing with c and wi scheme
                let (c, wi) = miller_loop_compute_c_wi::<E>(f);
                let success = bool::from(
                    E::multi_miller_loop_c_wi(
                        &c,
                        &wi,
                        &[(&w_x, &s_g2_prepared), (&w_g, &n_g2_prepared)],
                    )
                    .is_identity(),
                );
                assert!(success);
                Some((c, wi, None))
            }

            #[cfg(feature = "on_prove_pairing_affine")]
            {
                let s_g2_prepared = E::G2OnProvePrepared::from(params.s_g2);
                let n_g2_prepared = E::G2OnProvePrepared::from(-params.g2);
                let f = E::multi_miller_loop_on_prove_pairing_prepare(&[
                    (&w_x, &s_g2_prepared),
                    (&w_g, &n_g2_prepared),
                ]);
                //verify pairing with final exponent
                let success = bool::from(f.final_exponentiation().is_identity());
                assert!(success);

                //verify pairing with c and wi scheme (equivalent to final exponent scheme)
                let (c, wi) = miller_loop_compute_c_wi::<E>(f);
                let success = bool::from(
                    E::multi_miller_loop_on_prove_pairing(
                        &c,
                        &wi,
                        &[(&w_x, &s_g2_prepared), (&w_g, &n_g2_prepared)],
                    )
                    .is_identity(),
                );
                assert!(success);
                Some((c, wi, Some((s_g2_prepared, n_g2_prepared))))
            }
        } else {
            None
        }
    };

    // Do pairing in circuit.
    {
        let s_g2 = params.s_g2.coordinates().unwrap();
        let s_g2_x = *s_g2.x();
        let s_g2_y = *s_g2.y();
        let assigned_s_g2_x = ctx.fq2_assign_constant(E::decode(s_g2_x))?;
        let assigned_s_g2_y = ctx.fq2_assign_constant(E::decode(s_g2_y))?;

        let g2 = (-params.g2).coordinates().unwrap();
        let g2_x = *g2.x();
        let g2_y = *g2.y();
        let assigned_g2_x = ctx.fq2_assign_constant(E::decode(g2_x))?;
        let assigned_g2_y = ctx.fq2_assign_constant(E::decode(g2_y))?;

        let z = ctx
            .get_integer_context()
            .plonk_region_context()
            .assign_constant(E::Scalar::from(0u64))?
            .into();

        let assigned_s_g2 = AssignedG2Affine::new(assigned_s_g2_x, assigned_s_g2_y, z);
        let assigned_g2 = AssignedG2Affine::new(assigned_g2_x, assigned_g2_y, z);

        let timer = start_timer!(|| "check_pairing");
        if let Some(v) = pairing_c_wi {
            let (c, wi, on_pairing_coeff) = v;
            let c_assigned = ctx.fq12_assign(Some(E::decode_gt(c)))?;
            let wi_assigned = ctx.fq12_assign(Some(E::decode_gt(wi)))?;

            // if support on_prove_pairing affine coordinate scheme,
            // assign constant coeffs(slope,bias) in advance instead of calculating in circuit
            if let Some((s_g2_prepared, n_g2_prepared)) = on_pairing_coeff {
                let mut coeffs_s_g2: Vec<
                    [AssignedFq2<<E::G1Affine as CurveAffine>::Base, E::Scalar>; 2],
                > = vec![];
                for v in E::get_g2_on_prove_prepared_coeffs(&s_g2_prepared).iter() {
                    coeffs_s_g2.push([
                        ctx.fq2_assign_constant((v.0 .0, v.0 .1))?,
                        ctx.fq2_assign_constant((v.1 .0, v.1 .1))?,
                    ]);
                }
                let mut coeffs_n_g2: Vec<
                    [AssignedFq2<<E::G1Affine as CurveAffine>::Base, E::Scalar>; 2],
                > = vec![];
                for v in E::get_g2_on_prove_prepared_coeffs(&n_g2_prepared).iter() {
                    coeffs_n_g2.push([
                        ctx.fq2_assign_constant((v.0 .0, v.0 .1))?,
                        ctx.fq2_assign_constant((v.1 .0, v.1 .1))?,
                    ]);
                }
                let assigned_s_g2_prepared =
                    AssignedG2OnProvePrepared::new(coeffs_s_g2, assigned_s_g2);
                let assigned_n_g2_prepared =
                    AssignedG2OnProvePrepared::new(coeffs_n_g2, assigned_g2);
                ctx.check_pairing_on_prove_pairing(
                    &c_assigned,
                    &wi_assigned,
                    &[
                        (&pl[0], &assigned_s_g2_prepared),
                        (&pl[1], &assigned_n_g2_prepared),
                    ],
                )?;
            } else {
                // only replace final exponent check
                ctx.check_pairing_c_wi(
                    &c_assigned,
                    &wi_assigned,
                    &[(&pl[0], &assigned_s_g2), (&pl[1], &assigned_g2)],
                )?;
            }
        } else {
            ctx.check_pairing(&[(&pl[0], &assigned_s_g2), (&pl[1], &assigned_g2)])?;
        }
        end_timer!(timer);
    }

    let (assigned_instances, assigned_shadow_instances) = if !config.is_final_aggregator {
        // Aggregator's instance is [aggregator_hash, target circuits' instance commitments, exposed advice commitments].
        let mut assigned_instances = vec![assigned_final_hash];

        assigned_instances.append(
            &mut vec![&il.concat()[..], &pl[expose_start_idx..pl.len()]]
                .concat()
                .iter()
                .map(|p| ctx.ecc_encode(p))
                .collect::<Result<Vec<_>, _>>()?
                .concat(),
        );

        (assigned_instances, vec![])
    } else {
        // Final aggregator's instance is different for reducing solidity gas.
        // It doesn't expose target circuit's instance commitment but hash them with shadow instance.
        // The shadow instance contains aggregator_hash and exposed commitments (as encoded scalars).
        let mut hash_list = vec![];

        for (proof_idx, max_row_of_cols) in config.target_proof_max_instance.iter().enumerate() {
            for (column_idx, max_row) in max_row_of_cols.iter().enumerate() {
                let mut start_row = 0;
                let end_row = *max_row;

                // Skip instance because they has been absorbed in previous steps.
                if let Some((_, skips)) = config
                    .prev_aggregator_skip_instance
                    .iter()
                    .find(|(pi, _)| *pi == proof_idx)
                {
                    // Aggregagtor only has one instance column.
                    assert!(column_idx == 0);
                    start_row += skips;
                }

                // Calculate instance commitment in circuit.
                let instance_commitment = if end_row > start_row {
                    let mut sl = vec![];
                    for row_idx in start_row..end_row {
                        let assigned_s = ctx.integer_context().plonk_region_context().assign(
                            instances[proof_idx][column_idx]
                                .get(row_idx)
                                .cloned()
                                .unwrap_or(E::Scalar::from(0u64)),
                        )?;
                        hash_list.push(assigned_s.clone());
                        sl.push(assigned_s)
                    }

                    let mut pl = vec![];
                    for row_idx in start_row..end_row {
                        let assigned_p = ctx.assign_constant_point(params.g_lagrange[row_idx])?;
                        pl.push(assigned_p);
                    }

                    let instance_commitment = ctx.msm_unsafe(&pl, &sl)?;

                    instance_commitment
                } else {
                    let instance_commitment = ctx.assign_constant_point(E::G1Affine::identity())?;

                    instance_commitment
                };

                // The instance commitment calculated in circuit should be same with the one in assigned.
                ctx.ecc_assert_equal(&instance_commitment, &il[proof_idx][column_idx])?;
            }
        }

        let mut assigned_shadow_instances = vec![assigned_final_hash];

        assigned_shadow_instances.append(
            &mut vec![&pl[expose_start_idx..pl.len()]]
                .concat()
                .iter()
                .map(|p| ctx.ecc_encode(p))
                .collect::<Result<Vec<_>, _>>()?
                .concat(),
        );

        hash_list.append(&mut assigned_shadow_instances.clone());

        let assigned_instances = vec![ctx.get_plonk_region_context().hash(&hash_list[..])?];

        (assigned_instances, assigned_shadow_instances)
    };

    println!("offset {:?}", ctx.offset());

    Ok((
        assigned_instances,
        assigned_shadow_instances,
        assigned_constant_hash,
    ))
}

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
    EccUnsafeError,
> {
    let mut it: Vec<(
        Option<AssignedPoint<E::G1Affine, E::Scalar>>,
        Option<AssignedValue<E::Scalar>>,
    )> = vec![];
    let const_scalars = {
        c.const_scalars
            .iter()
            .map(|c| {
                circuit
                    .integer_context()
                    .plonk_region_context()
                    .assign(*c)
                    .unwrap()
            })
            .collect::<Vec<_>>()
    };

    for c in const_scalars.iter() {
        constants_hasher.common_scalar(circuit, c);
    }

    let const_points = {
        c.const_points
            .iter()
            .map(|c| circuit.assign_point(Some(*c)).unwrap())
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
                        circuit.assign_point(Some(*instance_commitment)).unwrap()
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
                        .integer_context()
                        .plonk_region_context()
                        .add(eval_scalar_pos!(a), eval_scalar_pos!(b))
                        .unwrap(),
                ),
            ),
            EvalOps::ScalarSub(a, b) => (
                None,
                Some(
                    circuit
                        .integer_context()
                        .plonk_region_context()
                        .sub(eval_scalar_pos!(a), eval_scalar_pos!(b))
                        .unwrap(),
                ),
            ),
            EvalOps::ScalarMul(a, b, _) => (
                None,
                Some(
                    circuit
                        .integer_context()
                        .plonk_region_context()
                        .mul(eval_scalar_pos!(a), eval_scalar_pos!(b))
                        .unwrap(),
                ),
            ),
            EvalOps::ScalarDiv(a, b) => (
                None,
                Some(
                    circuit
                        .integer_context()
                        .plonk_region_context()
                        .div_unsafe(eval_scalar_pos!(a), eval_scalar_pos!(b))
                        .unwrap(),
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
                    acc = circuit
                        .integer_context()
                        .plonk_region_context()
                        .mul(&acc, &acc)
                        .unwrap();
                    p >>= 1;
                }
                let s = c
                    .into_iter()
                    .reduce(|acc, x| {
                        circuit
                            .integer_context()
                            .plonk_region_context()
                            .mul(&acc, &x)
                            .unwrap()
                    })
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

                let res = (Some(circuit.msm_unsafe(&pl, &sl)?), None);

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
            .map(|x| circuit.ecc_reduce(it[*x].0.as_ref().unwrap()).unwrap())
            .collect(),
        instance_commitments,
        constants_hash,
    ))
}
