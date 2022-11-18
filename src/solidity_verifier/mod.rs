use crate::circuits::utils::load_or_build_unsafe_params;
use crate::circuits::utils::load_or_build_vkey;
use halo2_proofs::arithmetic::BaseExt;
use halo2_proofs::arithmetic::CurveAffine;
use halo2_proofs::arithmetic::MultiMillerLoop;
use halo2_proofs::plonk::VerifyingKey;
use halo2_proofs::poly::commitment::ParamsVerifier;
use num_bigint::BigUint;
use std::fs;
use std::fs::write;
use tera::Tera;

pub fn solidity_render<E: MultiMillerLoop>(
    path_in: &str,
    path_out: &str,
    template_name: &str,
    params: &ParamsVerifier<E>,
    //_vkey: &VerifyingKey<E::G1Affine>,
) {
    let tera = Tera::new(path_in).unwrap();
    let mut tera_ctx = tera::Context::new();

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

    insert_g2(&mut tera_ctx, "target_circuit_s_g2", params.s_g2);
    insert_g2(&mut tera_ctx, "target_circuit_n_g2", -params.s_g2);

    let fd = std::fs::File::create(path_out).unwrap();

    tera.render_to(template_name, &tera_ctx, fd)
        .expect("failed to render template");
}

#[test]
pub fn test_solidity_render() {
    use crate::circuits::samples::simple::SimpleCircuit;
    use crate::circuits::utils::run_circuit_unsafe_full_pass;
    use crate::circuits::utils::TranscriptHash;
    use halo2_proofs::pairing::bn256::Bn256;
    use halo2_proofs::pairing::bn256::Fr;
    use std::fs::DirBuilder;
    use std::path::Path;

    let path = "./output";
    DirBuilder::new().recursive(true).create(path).unwrap();

    let path = Path::new(path);
    let (circuit, instances) = SimpleCircuit::<Fr>::random_new_with_instance();
    let (circuit, instances) = run_circuit_unsafe_full_pass::<Bn256, _>(
        path,
        "simple-circuit",
        8,
        vec![circuit],
        vec![instances],
        TranscriptHash::Poseidon,
        vec![[0, 0, 0, 0]],
    )
    .unwrap();

    let k = 8;
    let params =
        load_or_build_unsafe_params::<Bn256>(k, Some(&path.join(format!("K{}.params", k))));
    let params_verifier: ParamsVerifier<Bn256> = params.verifier(10).unwrap();

    solidity_render(
        "sol/templates/*",
        "sol/contracts/AggregatorVerifier.sol",
        "AggregatorVerifier.sol.template",
        &params_verifier,
    );

    /*
    let vkey = load_or_build_vkey::<Bn256, _>(
        &params,
        &circuit,
        Some(&path.join(format!("{}_{}.vkey.data", "verify-circuit", 0))),
    );
     */
}
