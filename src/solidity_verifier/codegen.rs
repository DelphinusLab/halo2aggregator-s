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

fn context_eval<E: MultiMillerLoop>(c: EvalContext<E::G1Affine>) {
    for (i, op) in c.ops.iter().enumerate() {
        match op {
            EvalOps::CheckPoint(_, _) => {}
            _ => println!("i {} op {:?}", i, op),
        };
    }

}

pub fn verifier_code_generator<E: MultiMillerLoop>(
    params: &ParamsVerifier<E>,
    vkey: &VerifyingKey<E::G1Affine>,
) {
    let (w_x, w_g, _) = verify_aggregation_proofs(params, &[vkey]);

    let targets = vec![w_x.0, w_g.0];

    let c = EvalContext::translate(&targets[..]);

    context_eval::<E>(c);
}
