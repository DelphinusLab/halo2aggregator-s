use self::codegen::solidity_codegen_with_proof;
use crate::circuits::utils::TranscriptHash;
use crate::utils::field_to_bn;
use halo2_proofs::arithmetic::BaseExt;
use halo2_proofs::arithmetic::CurveAffine;
use halo2_proofs::arithmetic::MultiMillerLoop;
use halo2_proofs::plonk::VerifyingKey;
use halo2_proofs::poly::commitment::ParamsVerifier;
use num_bigint::BigUint;
use sha2::Digest;
use std::path::Path;
use tera::Tera;

pub mod codegen;

pub fn solidity_render<E: MultiMillerLoop, D: Digest + Clone>(
    path_in: &str,
    path_out: &str,
    common_template_name: Vec<(String, String)>,
    start_step_template_name: &str,
    end_step_template_name: &str,
    step_out_file_name: impl Fn(usize) -> String,
    hasher: TranscriptHash,
    verify_circuit_params: &ParamsVerifier<E>,
    vkey: &VerifyingKey<E::G1Affine>,
    instances: &Vec<E::Scalar>,
    proofs: Vec<u8>,
) {
    solidity_render_with_check_option::<_, D>(
        path_in,
        path_out,
        common_template_name,
        start_step_template_name,
        end_step_template_name,
        step_out_file_name,
        hasher,
        verify_circuit_params,
        vkey,
        instances,
        proofs,
        true,
    );
}

pub fn solidity_render_with_check_option<E: MultiMillerLoop, D: Digest + Clone>(
    path_in: &str,
    path_out: &str,
    common_template_name: Vec<(String, String)>,
    start_step_template_name: &str,
    end_step_template_name: &str,
    step_out_file_name: impl Fn(usize) -> String,
    hasher: TranscriptHash,
    verify_circuit_params: &ParamsVerifier<E>,
    vkey: &VerifyingKey<E::G1Affine>,
    instances: &Vec<E::Scalar>,
    proofs: Vec<u8>,
    check: bool,
) {
    let tera = Tera::new(path_in).unwrap();
    let mut tera_ctx = tera::Context::new();

    match hasher {
        TranscriptHash::Sha => tera_ctx.insert("hasher", "sha256"),
        TranscriptHash::Keccak => tera_ctx.insert("hasher", "keccak"),
        _ => unreachable!(),
    }

    let g2field_to_bn = |f: &<E::G2Affine as CurveAffine>::Base| {
        let mut bytes: Vec<u8> = Vec::new();
        f.write(&mut bytes).unwrap();
        (
            BigUint::from_bytes_le(&bytes[32..64]),
            BigUint::from_bytes_le(&bytes[..32]),
        )
    };

    let insert_g2 = |tera_ctx: &mut tera::Context, prefix, g2: E::G2Affine| {
        let c = g2.coordinates().unwrap();
        let x = g2field_to_bn(c.x());
        let y = g2field_to_bn(c.y());
        tera_ctx.insert(format!("{}_{}", prefix, "x0"), &x.0.to_str_radix(10));
        tera_ctx.insert(format!("{}_{}", prefix, "x1"), &x.1.to_str_radix(10));
        tera_ctx.insert(format!("{}_{}", prefix, "y0"), &y.0.to_str_radix(10));
        tera_ctx.insert(format!("{}_{}", prefix, "y1"), &y.1.to_str_radix(10));
    };

    insert_g2(
        &mut tera_ctx,
        "verify_circuit_s_g2",
        verify_circuit_params.s_g2,
    );
    insert_g2(
        &mut tera_ctx,
        "verify_circuit_n_g2",
        -verify_circuit_params.g2,
    );

    let verify_circuit_g_lagrange = verify_circuit_params
        .g_lagrange
        .iter()
        .map(|g1| {
            let c = g1.coordinates().unwrap();
            [
                field_to_bn(c.x()).to_str_radix(10),
                field_to_bn(c.y()).to_str_radix(10),
            ]
        })
        .collect::<Vec<_>>();
    tera_ctx.insert(
        "verify_circuit_lagrange_commitments",
        &verify_circuit_g_lagrange,
    );

    // vars for challenge
    let mut hasher = blake2b_simd::Params::new()
        .hash_length(64)
        .personal(b"Halo2-Verify-Key")
        .to_state();

    let s = format!("{:?}", vkey.pinned());
    hasher.update(&(s.len() as u64).to_le_bytes());
    hasher.update(s.as_bytes());

    let scalar = E::Scalar::from_bytes_wide(hasher.finalize().as_array());

    tera_ctx.insert("init_scalar", &field_to_bn(&scalar).to_str_radix(10));

    tera_ctx.insert("n_advice", &vkey.cs.num_advice_columns);

    // logup's multiplicity commitment
    let lookups = vkey.cs.lookups.len();
    tera_ctx.insert("n_lookups_m", &lookups);

    // logup's z_sets constructed by inputs_sets
    // logup's evals: 1*multipliciy_poly + n*z_poly(x, next_x, last_x(except the last z)) = 3n
    let n_lookups_zs = vkey
        .cs
        .lookups
        .iter()
        .map(|arg| arg.input_expressions_sets.len())
        .sum::<usize>();
    tera_ctx.insert("n_lookups_zs", &n_lookups_zs);

    let shuffles = vkey.cs.shuffles.len();
    tera_ctx.insert("shuffles", &shuffles);

    let n_permutation_product = vkey
        .cs
        .permutation
        .columns
        .chunks(vkey.cs.degree() - 2)
        .len();
    tera_ctx.insert("permutation_products", &n_permutation_product);

    tera_ctx.insert("degree", &vkey.domain.get_quotient_poly_degree());

    let evals = vkey.cs.instance_queries.len()
        + vkey.cs.advice_queries.len()
        + vkey.cs.fixed_queries.len()
        + 1
        + vkey.permutation.commitments.len()
        + 3 * n_permutation_product
        - 1
        + 3 * n_lookups_zs
        + 2 * shuffles;
    tera_ctx.insert("evals", &evals);

    let steps = solidity_codegen_with_proof::<_, D>(
        &verify_circuit_params,
        &vkey,
        instances,
        proofs,
        &mut tera_ctx,
        check,
    );

    for (f_in, f_out) in common_template_name {
        let fd = std::fs::File::create(Path::new(path_out).join(f_out)).unwrap();

        tera.render_to(&f_in, &tera_ctx, fd)
            .expect("failed to render template");
    }

    for (i, step) in steps.iter().enumerate() {
        let template = if i == steps.len() - 1 {
            end_step_template_name
        } else {
            start_step_template_name
        };
        let fd = std::fs::File::create(Path::new(path_out).join(&step_out_file_name(i))).unwrap();

        tera_ctx.insert("step", step);
        tera_ctx.insert("step_index", &(i + 1));
        tera.render_to(template, &tera_ctx, fd)
            .expect("failed to render template");
        tera_ctx.remove("step");
    }
}

#[cfg(test)]
mod tests {
    use crate::circuits::samples::simple::SimpleCircuit;
    use crate::circuits::utils::load_or_build_unsafe_params;
    use crate::circuits::utils::load_or_build_vkey;
    use crate::circuits::utils::load_proof;
    use crate::circuits::utils::run_circuit_unsafe_full_pass_no_rec;
    use crate::circuits::utils::TranscriptHash;
    use crate::solidity_verifier::codegen::solidity_aux_gen;
    use crate::solidity_verifier::solidity_render;
    use halo2_proofs::pairing::bn256::Bn256;
    use halo2_proofs::pairing::bn256::Fr;
    use halo2_proofs::plonk::Circuit;
    use halo2_proofs::poly::commitment::ParamsVerifier;
    use sha2::Digest;
    use std::fs::DirBuilder;
    use std::path::Path;

    fn test_solidity_render<D: Digest + Clone>(aggregator_circuit_hasher: TranscriptHash) {
        assert!(
            aggregator_circuit_hasher == TranscriptHash::Sha
                || aggregator_circuit_hasher == TranscriptHash::Keccak,
            "aggregator circuit only support sha or keccak."
        );

        let path = "./output";
        DirBuilder::new().recursive(true).create(path).unwrap();

        let n_proofs = 2;
        let target_circuit_k = 16;
        let verify_circuit_k = 22;

        let path = Path::new(path);
        let (circuit, instances) = SimpleCircuit::<Fr>::random_new_with_instance();
        let (circuit, instances, shadow_instances, _) =
            run_circuit_unsafe_full_pass_no_rec::<Bn256, _>(
                path,
                "simple-circuit",
                target_circuit_k,
                vec![circuit.clone(), circuit],
                vec![instances.clone(), instances],
                vec![],
                TranscriptHash::Poseidon,
                vec![[0, 0, 1, 0]],
                vec![],
                vec![vec![1], vec![1]],
                true,
            )
            .unwrap();

        let circuit0 = circuit.without_witnesses();
        run_circuit_unsafe_full_pass_no_rec::<Bn256, _>(
            path,
            "verify-circuit",
            verify_circuit_k,
            vec![circuit],
            vec![vec![instances.clone()]],
            vec![vec![shadow_instances]],
            aggregator_circuit_hasher,
            vec![],
            vec![],
            vec![vec![1]],
            true,
        );

        let params = load_or_build_unsafe_params::<Bn256>(
            verify_circuit_k,
            Some(&path.join(format!("K{}.params", verify_circuit_k))),
        );
        let verifier_params_verifier: ParamsVerifier<Bn256> =
            params.verifier(3 * n_proofs + 1).unwrap();

        let vkey = load_or_build_vkey::<Bn256, _>(
            &params,
            &circuit0,
            Some(&path.join(format!("{}.{}.vkey.data", "verify-circuit", 0))),
        );

        let proof = load_proof(&path.join(format!("{}.{}.transcript.data", "verify-circuit", 0)));
        solidity_render::<_, D>(
            "sol/templates/*",
            "sol/contracts",
            vec![(
                "AggregatorConfig.sol.tera".to_owned(),
                "AggregatorConfig.sol".to_owned(),
            )],
            "AggregatorVerifierStepStart.sol.tera",
            "AggregatorVerifierStepEnd.sol.tera",
            |i| format!("AggregatorVerifierStep{}.sol", i + 1),
            aggregator_circuit_hasher,
            &verifier_params_verifier,
            &vkey,
            &instances,
            proof.clone(),
        );

        solidity_aux_gen::<_, D>(
            &verifier_params_verifier,
            &vkey,
            &instances,
            proof,
            &path.join(format!("{}.{}.aux.data", "verify-circuit", 0)),
        );
    }

    #[test]
    fn test_solidity_render_sha256() {
        test_solidity_render::<sha2::Sha256>(TranscriptHash::Sha)
    }

    #[test]
    fn test_solidity_render_keccak() {
        test_solidity_render::<sha3::Keccak256>(TranscriptHash::Keccak)
    }
}
