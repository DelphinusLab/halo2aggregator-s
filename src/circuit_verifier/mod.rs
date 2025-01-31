use crate::api::ast_eval::EvalContext;
use crate::api::halo2::verify_aggregation_proofs;
use crate::circuits::utils::instance_to_instance_commitment;
use crate::circuits::utils::AggregatorConfig;
use crate::circuits::utils::TranscriptHash;
use crate::native_verifier::NativeEvalContext;
use crate::transcript::poseidon::PoseidonPure;
use crate::transcript::poseidon::PoseidonRead;
use crate::utils::bn_to_field;
use crate::utils::field_to_bn;
use circuit::AggregatorCircuit;
use halo2_proofs::arithmetic::BaseExt;
use halo2_proofs::arithmetic::CurveAffine;
use halo2_proofs::arithmetic::Field;
use halo2_proofs::arithmetic::MillerLoopResult;
use halo2_proofs::arithmetic::MultiMillerLoop;
use halo2_proofs::arithmetic::MultiMillerLoopOnProvePairing;
use halo2_proofs::pairing::group::prime::PrimeCurveAffine;
use halo2_proofs::pairing::group::Curve;
use halo2_proofs::pairing::group::Group;
use halo2_proofs::plonk::VerifyingKey;
use halo2_proofs::poly::commitment::ParamsVerifier;
use halo2_proofs::transcript::Transcript;
pub use helper::*;
use num_bigint::BigUint;
use sha3::Digest;
use sha3::Keccak256;
use std::borrow::Borrow;
use std::sync::Arc;

pub mod circuit;
pub mod helper;
pub mod transcript;

pub fn build_aggregate_verify_circuit<E: MultiMillerLoop + MultiMillerLoopOnProvePairing>(
    params: Arc<ParamsVerifier<E>>,
    vkey: &[Arc<VerifyingKey<E::G1Affine>>],
    instances: Vec<Vec<Vec<E::Scalar>>>,
    proofs: Vec<Vec<u8>>,
    config: Arc<AggregatorConfig<E::Scalar>>,
) -> (
    AggregatorCircuit<E>,
    Vec<E::Scalar>,
    Vec<E::Scalar>,
    E::Scalar,
) {
    let (agg_circuit_instances, agg_circuit_shadow_instances, agg_circuit_constant_hash) =
        calc_instances(
            &params,
            &vkey.iter().map(|x| x.borrow()).collect::<Vec<_>>(),
            instances.clone(),
            &proofs,
            &config,
        );

    let circuit = AggregatorCircuit {
        params,
        vkey: vkey.to_vec(),
        config,
        instances,
        proofs,
    };

    (
        circuit,
        agg_circuit_instances,
        agg_circuit_shadow_instances,
        agg_circuit_constant_hash,
    )
}

pub fn build_single_proof_verify_circuit<
    E: MultiMillerLoop + G2AffineBaseHelper + GtHelper + MultiMillerLoopOnProvePairing,
>(
    params: Arc<ParamsVerifier<E>>,
    vkey: Arc<VerifyingKey<E::G1Affine>>,
    instances: Vec<Vec<E::Scalar>>,
    proof: Vec<u8>,
    config: Arc<AggregatorConfig<E::Scalar>>,
) -> (
    AggregatorCircuit<E>,
    Vec<E::Scalar>,
    Vec<E::Scalar>,
    E::Scalar,
) {
    build_aggregate_verify_circuit(params, &[vkey], vec![instances], vec![proof], config)
}

pub fn encode_point<C: CurveAffine>(point: &C) -> Vec<C::Scalar> {
    let x_y: Option<_> = point.coordinates().map(|c| (*c.x(), *c.y())).into();
    let (x, y) = x_y.unwrap_or((C::Base::zero(), C::Base::zero()));

    let x = field_to_bn(&x);
    let y = field_to_bn(&y);

    let shift = BigUint::from(1u64) << 108;

    vec![
        bn_to_field(&(&x % (&shift * &shift))),
        bn_to_field(&(x / (&shift * &shift) + (&y % &shift) * &shift)),
        bn_to_field(&(y / shift)),
    ]
}

fn calc_instances<E: MultiMillerLoop + MultiMillerLoopOnProvePairing>(
    params: &ParamsVerifier<E>,
    vkey: &[&VerifyingKey<E::G1Affine>],
    instances: Vec<Vec<Vec<E::Scalar>>>,
    proofs: &Vec<Vec<u8>>,
    config: &AggregatorConfig<E::Scalar>,
) -> (Vec<E::Scalar>, Vec<E::Scalar>, E::Scalar) {
    let (w_x, w_g, advices) = verify_aggregation_proofs(
        params,
        vkey,
        &config.commitment_check,
        config.target_proof_with_shplonk_as_default,
        &config.target_proof_with_shplonk,
    );

    let instance_commitments =
        instance_to_instance_commitment(params, vkey, instances.iter().collect());

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
    let poseidon = PoseidonPure::default();

    let (pl, mut il, constant_hash) = match config.hash {
        TranscriptHash::Poseidon => {
            let mut t = vec![];
            for i in 0..proofs.len() {
                t.push(PoseidonRead::init_with_poseidon(
                    &proofs[i][..],
                    poseidon.clone(),
                ));
            }

            let empty = vec![];
            t.push(PoseidonRead::init_with_poseidon(
                &empty[..],
                poseidon.clone(),
            ));

            let mut ctx = NativeEvalContext::<E, _, _>::new(c, instance_commitments.clone(), t);
            ctx.context_eval();

            let mut constant_hasher =
                PoseidonRead::init_with_poseidon(&empty[..], poseidon.clone());

            for s in ctx.c.const_scalars {
                constant_hasher.common_scalar(s).unwrap();
            }

            for p in ctx.c.const_points {
                constant_hasher.common_point(p).unwrap();
            }

            let constant_hash: E::Scalar = *constant_hasher.squeeze_challenge_scalar::<()>();

            (ctx.finals, instance_commitments, constant_hash)
        }
        _ => unreachable!(),
    };

    let s_g2_prepared = E::G2Prepared::from(params.s_g2);
    let n_g2_prepared = E::G2Prepared::from(-params.g2);

    let success = bool::from(
        E::multi_miller_loop(&[(&pl[0], &s_g2_prepared), (&pl[1], &n_g2_prepared)])
            .final_exponentiation()
            .is_identity(),
    );

    assert!(success);

    // Commitment check
    for c in pl[0..absorb_start_idx].chunks(2).skip(1) {
        assert_eq!(c[0], c[1]);
    }

    // Absorb
    for (proof_idx_of_target, columns, proof_idx_of_prev_agg, expose_row) in
        config.absorb_instance.iter()
    {
        // Aggregator circuit only has 1 instance column.
        assert!(il[*proof_idx_of_prev_agg].len() == 1);

        // Encode commitment to scalar vec.
        let encoded_c = encode_point(&il[*proof_idx_of_target][*columns]);
        assert!(encoded_c.len() == 3);

        let g0 = params.g_lagrange[*expose_row + 0];
        let g1 = params.g_lagrange[*expose_row + 1];
        let g2 = params.g_lagrange[*expose_row + 2];

        let instance_commit = &il[*proof_idx_of_prev_agg][0];
        let instance_commit = instance_commit.to_curve()
            - (g0 * encoded_c[0] + g1 * encoded_c[1] + g2 * encoded_c[2]);

        il[*proof_idx_of_prev_agg][0] = instance_commit.to_affine();
    }

    // Expose advice commitments as encoded scalars into aggregator's instance
    for (i, c) in pl[absorb_start_idx..expose_start_idx].iter().enumerate() {
        let [proof_index, instance_offset, g_index] = config.absorb[i].0;

        let encoded_c = encode_point(c);
        assert!(encoded_c.len() == 3);

        let instance_commit = &il[proof_index][instance_offset].clone();

        let g0 = params.g_lagrange[g_index + 0];
        let g1 = params.g_lagrange[g_index + 1];
        let g2 = params.g_lagrange[g_index + 2];

        let instance_commit = instance_commit.to_curve()
            - (g0 * encoded_c[0] + g1 * encoded_c[1] + g2 * encoded_c[2]);
        il[proof_index][instance_offset] = instance_commit.to_affine();
    }

    // Generate the aggregator hash H,
    // it can determine the aggregator round number and target circuits.
    // H_0 = Hash(constant_hash)
    // H_i = Hash(H_{i-1}, constant_hash), i > 0.
    let final_hash = {
        let empty = vec![];
        let mut hasher = PoseidonRead::init_with_poseidon(&empty[..], poseidon.clone());

        for (proof_index, instance_col, hash) in
            &config.target_aggregator_constant_hash_instance_offset
        {
            // The value is restricted in current version, because aggregator only has one instance column.
            assert!(*instance_col == 0);
            // To avoid incorrect config in current version.
            assert!(*hash == instances[*proof_index][*instance_col][0]);

            hasher.common_scalar(*hash).unwrap();

            // Absorb the H_{i-1} from the last round aggregator's instance commitment.
            // il[target_aggregator_circuit's hash instance col] -= params[0] * hash
            let instance_commit = &il[*proof_index][*instance_col];
            il[*proof_index][*instance_col] =
                (instance_commit.to_curve() - (params.g_lagrange[0] * hash)).to_affine();
        }

        hasher.common_scalar(constant_hash).unwrap();

        *hasher.squeeze_challenge_scalar::<()>()
    };

    let (instances, shadow_instances) = if !config.is_final_aggregator {
        // Aggregator's instance is [aggregator_hash, target circuits' instance commitments, exposed advice commitments].
        let mut instances = vec![final_hash];

        instances.append(
            &mut vec![&il.concat()[..], &pl[expose_start_idx..pl.len()]]
                .concat()
                .iter()
                .map(|p| encode_point(p))
                .collect::<Vec<_>>()
                .concat(),
        );

        (instances, vec![])
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
                let mut instance_commitment = E::G1Affine::identity().to_curve();
                for row_idx in start_row..end_row {
                    instance_commitment = instance_commitment
                        + params.g_lagrange[row_idx]
                            * instances[proof_idx][column_idx]
                                .get(row_idx)
                                .cloned()
                                .unwrap_or(E::Scalar::from(0u64));
                }

                // The instance commitment calculated in circuit should be same with the one in assigned.
                assert_eq!(&instance_commitment.to_affine(), &il[proof_idx][column_idx]);
            }
        }

        let mut shadow_instances: Vec<E::Scalar> = vec![final_hash];
        shadow_instances.append(
            &mut vec![&pl[expose_start_idx..pl.len()]]
                .concat()
                .iter()
                .map(|p| encode_point(p))
                .collect::<Vec<_>>()
                .concat(),
        );

        hash_list.append(&mut shadow_instances.clone());
        let instances = {
            let mut keccak = Keccak256::new();
            let mut data = vec![];
            hash_list.iter().for_each(|x| x.write(&mut data).unwrap());
            keccak.update(&data);
            let res: [u8; 32] = keccak.finalize().into();
            let res_bn = BigUint::from_bytes_le(&res);
            let res = bn_to_field(&res_bn);
            vec![res]
        };

        (instances, shadow_instances)
    };

    (instances, shadow_instances, constant_hash)
}
