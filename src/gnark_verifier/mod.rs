use halo2_proofs::arithmetic::BaseExt;
use halo2_proofs::arithmetic::CurveAffine;
use halo2_proofs::arithmetic::MultiMillerLoop;
use halo2_proofs::plonk::VerifyingKey;
use halo2_proofs::poly::commitment::ParamsVerifier;
use halo2ecc_s::utils::field_to_bn;
use num_bigint::BigUint;
use serde::Deserialize;
use serde::Serialize;
use sha2::Sha256;

mod codegen;

#[derive(Serialize, Deserialize)]
struct AggregatorConfig {
    verify_circuit_g_lagrange: Vec<[String; 2]>,
    verify_circuit_g2: Vec<[String; 4]>,
    challenge_init_scalar: String,
    nb_advices: u32,
    nb_lookups_m: u32,
    nb_lookups_zs: u32,
    nb_permutation_groups: u32,
    nb_evals: u32,
    degree: u32,
}

#[derive(Serialize, Deserialize)]
struct AggregatorProofData {
    instance: Vec<Vec<String>>,
    transcript: Vec<String>,
}

pub fn gnark_export_proof<F: BaseExt>(gnark_root: &str, instances: &Vec<F>, proofs: Vec<u8>) {
    let instance_str = instances
        .iter()
        .map(|x| field_to_bn(x).to_str_radix(10))
        .collect::<Vec<_>>();

    let proof_str = proofs.iter().map(|x| format!("{}", x)).collect::<Vec<_>>();

    let data = AggregatorProofData {
        instance: vec![instance_str],
        transcript: proof_str,
    };

    std::fs::write(
        format!("{}/halo2_verifier_proof.json", gnark_root),
        serde_json::to_string_pretty(&data).unwrap(),
    )
    .unwrap();
}

pub fn gnark_render<E: MultiMillerLoop>(
    gnark_root: &str,
    verify_circuit_params: &ParamsVerifier<E>,
    vkey: &VerifyingKey<E::G1Affine>,
    instances: &Vec<E::Scalar>,
    proofs: Vec<u8>,
) {
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

    let challenge_init_scalar = {
        let mut hasher = blake2b_simd::Params::new()
            .hash_length(64)
            .personal(b"Halo2-Verify-Key")
            .to_state();

        let s = format!("{:?}", vkey.pinned());
        hasher.update(&(s.len() as u64).to_le_bytes());
        hasher.update(s.as_bytes());

        let scalar = E::Scalar::from_bytes_wide(hasher.finalize().as_array());
        field_to_bn(&scalar).to_str_radix(10)
    };

    let nb_advices = vkey.cs.num_advice_columns as u32;
    let nb_lookups_m = vkey.cs.lookups.len() as u32;
    let nb_lookups_zs = vkey
        .cs
        .lookups
        .iter()
        .map(|arg| arg.input_expressions_sets.len())
        .sum::<usize>() as u32;
    let nb_permutation_groups = vkey
        .cs
        .permutation
        .columns
        .chunks(vkey.cs.degree() - 2)
        .len() as u32;

    let degree = vkey.domain.get_quotient_poly_degree() as u32;

    let nb_evals = vkey.cs.instance_queries.len() as u32
        + vkey.cs.advice_queries.len() as u32
        + vkey.cs.fixed_queries.len() as u32
        + 1
        + vkey.permutation.commitments.len() as u32
        + 3 * nb_permutation_groups
        - 1
        + 3 * nb_lookups_zs;

    let g2field_to_bn = |f: &<E::G2Affine as CurveAffine>::Base| {
        let mut bytes: Vec<u8> = Vec::new();
        f.write(&mut bytes).unwrap();
        (
            BigUint::from_bytes_le(&bytes[32..64]),
            BigUint::from_bytes_le(&bytes[..32]),
        )
    };

    let g2_to_str = |g2: E::G2Affine| {
        let c = g2.coordinates().unwrap();
        let x = g2field_to_bn(c.x());
        let y = g2field_to_bn(c.y());
        [
            x.1.to_str_radix(10),
            x.0.to_str_radix(10),
            y.1.to_str_radix(10),
            y.0.to_str_radix(10),
        ]
    };

    let verify_circuit_g2 = vec![
        g2_to_str(verify_circuit_params.s_g2),
        g2_to_str(-verify_circuit_params.g2),
    ];

    let config = AggregatorConfig {
        verify_circuit_g_lagrange,
        verify_circuit_g2,
        challenge_init_scalar,
        nb_advices,
        nb_lookups_m,
        nb_lookups_zs,
        nb_permutation_groups,
        nb_evals,
        degree,
    };

    std::fs::write(
        format!("{}/halo2_verifier_config.json", gnark_root),
        serde_json::to_string_pretty(&config).unwrap(),
    )
    .unwrap();

    let code_pre = r#"
package main

import (
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/emulated/emparams"
)

func (halo2Api *Halo2VerifierAPI) verify(
	instanceCommitments []*sw_emulated.AffinePoint[emparams.BN254Fp],
	commitments []*sw_emulated.AffinePoint[emparams.BN254Fp],
	evals []frontend.Variable,
	challenges []frontend.Variable,
) (*sw_emulated.AffinePoint[emparams.BN254Fp], *sw_emulated.AffinePoint[emparams.BN254Fp]) {
    "#;

    let code = codegen::gnark_codegen_with_proof::<_, Sha256>(
        verify_circuit_params,
        vkey,
        instances,
        proofs.clone(),
        true,
    );

    let code_post = r#"
        return p0, p1
    }
    "#;

    std::fs::write(
        format!("{}/verify.go", gnark_root),
        format!("{}{}{}", code_pre, code, code_post),
    )
    .unwrap();

    gnark_export_proof(gnark_root, instances, proofs)
}

#[cfg(test)]
mod tests {
    use super::gnark_render;
    use crate::circuits::samples::simple::SimpleCircuit;
    use crate::circuits::utils::load_or_build_unsafe_params;
    use crate::circuits::utils::load_or_build_vkey;
    use crate::circuits::utils::load_proof;
    use crate::circuits::utils::run_circuit_unsafe_full_pass_no_rec;
    use crate::circuits::utils::TranscriptHash;
    use halo2_proofs::pairing::bn256::Bn256;
    use halo2_proofs::pairing::bn256::Fr;
    use halo2_proofs::plonk::Circuit;
    use halo2_proofs::poly::commitment::ParamsVerifier;
    use std::fs::DirBuilder;
    use std::path::Path;

    #[test]
    fn test_gnark_render() {
        let aggregator_circuit_hasher = TranscriptHash::Sha;
        let path = "./output";
        DirBuilder::new().recursive(true).create(path).unwrap();

        let n_proofs = 2;
        let target_circuit_k = 8;
        let verify_circuit_k = 22;

        let path = Path::new(path);
        let (circuit, instances) = SimpleCircuit::<Fr>::default_with_instance();
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
        let circuit = circuit.circuit_without_select_chip.unwrap();

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
            false,
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
        gnark_render("gnark", &verifier_params_verifier, &vkey, &instances, proof);
    }
}
