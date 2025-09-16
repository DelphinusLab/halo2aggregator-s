use crate::api::ast_eval::EvalContext;
use crate::api::ast_eval::EvalOps;
use crate::api::ast_eval::EvalPos;
use crate::api::verify_aggregation_proofs;
use crate::circuits::utils::instance_to_instance_commitment;
use crate::circuits::utils::TranscriptHash;
use crate::transcript::poseidon::PoseidonPure;
use crate::transcript::poseidon::PoseidonRead;
use crate::transcript::sha256::ShaRead;
use halo2_proofs::arithmetic::Field;
use halo2_proofs::arithmetic::MillerLoopResult;
use halo2_proofs::arithmetic::MultiMillerLoop;
use halo2_proofs::pairing::group::Curve;
use halo2_proofs::pairing::group::Group;
use crate::api::VerifierKey;
use halo2_proofs::poly::commitment::ParamsVerifier;
use halo2_proofs::transcript::Blake2bRead;
use halo2_proofs::transcript::Challenge255;
use halo2_proofs::transcript::EncodedChallenge;
use halo2_proofs::transcript::TranscriptRead;
use std::marker::PhantomData;

pub struct NativeEvalContext<
    E: MultiMillerLoop,
    EC: EncodedChallenge<E::G1Affine>,
    T: TranscriptRead<E::G1Affine, EC>,
> {
    pub finals: Vec<E::G1Affine>,
    pub values: Vec<(Option<E::G1Affine>, Option<E::Scalar>)>,

    pub(crate) c: EvalContext<E::G1Affine>,
    instance_commitments: Vec<Vec<E::G1Affine>>,
    t: Vec<T>,
    _mark: PhantomData<EC>,
}

impl<E: MultiMillerLoop, EC: EncodedChallenge<E::G1Affine>, T: TranscriptRead<E::G1Affine, EC>>
    NativeEvalContext<E, EC, T>
{
    pub fn new(
        c: EvalContext<E::G1Affine>,
        instance_commitments: Vec<Vec<E::G1Affine>>,
        t: Vec<T>,
    ) -> Self {
        Self {
            c,
            instance_commitments,
            t,
            values: vec![],
            finals: vec![],
            _mark: PhantomData,
        }
    }

    fn eval_scalar_pos(&self, pos: &EvalPos) -> E::Scalar {
        match pos {
            EvalPos::Constant(i) => self.c.const_scalars[*i],
            EvalPos::Ops(i) => self.values[*i].1.unwrap(),
            _ => unreachable!(),
        }
    }

    fn eval_point_pos(&self, pos: &EvalPos) -> E::G1Affine {
        match pos {
            EvalPos::Constant(i) => self.c.const_points[*i],
            EvalPos::Ops(i) => self.values[*i].0.unwrap(),
            EvalPos::Instance(i, j) => self.instance_commitments[*i][*j],
            _ => unreachable!(),
        }
    }

    fn eval_any_pos(&self, pos: &EvalPos) -> (Option<E::G1Affine>, Option<E::Scalar>) {
        match pos {
            EvalPos::Ops(i) => self.values[*i],
            _ => unreachable!(),
        }
    }

    pub fn context_eval(&mut self) {
        for (_, op) in self.c.ops.iter().enumerate() {
            let v = match op {
                EvalOps::TranscriptReadScalar(i, _) => {
                    (None, Some(self.t[*i].read_scalar().unwrap()))
                }
                EvalOps::TranscriptReadPoint(i, _) => {
                    (Some(self.t[*i].read_point().unwrap()), None)
                }
                EvalOps::TranscriptCommonScalar(i, _, s) => {
                    let v = self.eval_scalar_pos(s);
                    self.t[*i].common_scalar(v).unwrap();
                    (None, None)
                }
                EvalOps::TranscriptCommonPoint(i, _, p) => {
                    let v = self.eval_point_pos(p);
                    self.t[*i].common_point(v).unwrap();
                    (None, None)
                }
                EvalOps::TranscriptSqueeze(i, _) => {
                    (None, Some(self.t[*i].squeeze_challenge().get_scalar()))
                }
                EvalOps::ScalarAdd(a, b) => (
                    None,
                    Some(self.eval_scalar_pos(a) + self.eval_scalar_pos(b)),
                ),
                EvalOps::ScalarSub(a, b) => (
                    None,
                    Some(self.eval_scalar_pos(a) - self.eval_scalar_pos(b)),
                ),
                EvalOps::ScalarMul(a, b, _) => (
                    None,
                    Some(self.eval_scalar_pos(a) * self.eval_scalar_pos(b)),
                ),
                EvalOps::ScalarDiv(a, b) => (
                    None,
                    Some(self.eval_scalar_pos(a) * self.eval_scalar_pos(b).invert().unwrap()),
                ),
                EvalOps::ScalarPow(a, n) => {
                    (None, Some(self.eval_scalar_pos(a).pow_vartime([*n as u64])))
                }
                EvalOps::MSM(_, last) => (Some(self.eval_point_pos(last)), None),
                EvalOps::MSMSlice((p, s), last, _) => {
                    let curr = (self.eval_point_pos(p) * self.eval_scalar_pos(s)).to_affine();
                    let acc = last
                        .as_ref()
                        .map(|x| (self.eval_point_pos(x) + curr).to_affine())
                        .unwrap_or(curr);
                    (Some(acc), None)
                }
                EvalOps::CheckPoint(tag, v) => {
                    if false {
                        println!("checkpoint {}: {:?}", tag, self.eval_any_pos(v));
                    }
                    self.eval_any_pos(v)
                }
            };
            self.values.push(v);
        }

        self.finals = self
            .c
            .finals
            .iter()
            .map(|x| self.values[*x].0.unwrap())
            .collect();
    }
}

pub fn verify_single_proof<E: MultiMillerLoop>(
    params: &ParamsVerifier<E>,
    vkey: &VerifierKey<E::G1Affine>,
    instances: &Vec<Vec<E::Scalar>>,
    proof: Vec<u8>,
    hash: TranscriptHash,
    use_shplonk_as_default: bool,
    proofs_with_shplonk: &Vec<usize>,
) {
    verify_proofs(
        params,
        &[vkey],
        &vec![instances.clone()],
        vec![proof],
        hash,
        &vec![],
        use_shplonk_as_default,
        proofs_with_shplonk,
    )
}

pub fn verify_proofs<E: MultiMillerLoop>(
    params: &ParamsVerifier<E>,
    vkey: &[&VerifierKey<E::G1Affine>],
    instances: &Vec<Vec<Vec<E::Scalar>>>,
    proofs: Vec<Vec<u8>>,
    hash: TranscriptHash,
    commitment_check: &Vec<[usize; 4]>,
    use_shplonk_as_default: bool,
    proofs_with_shplonk: &Vec<usize>,
) {
    let (w_x, w_g, advices) = verify_aggregation_proofs(
        params,
        vkey,
        commitment_check,
        use_shplonk_as_default,
        proofs_with_shplonk,
        instances,
    );

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
            let mut ctx = NativeEvalContext::<E, _, _>::new(c, instance_commitments, t);
            ctx.context_eval();
            ctx.finals
        }
        TranscriptHash::Poseidon => {
            let mut t = vec![];
            let poseidon = PoseidonPure::<E::G1Affine>::default();
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
            let mut ctx = NativeEvalContext::<E, _, _>::new(c, instance_commitments, t);
            ctx.context_eval();
            ctx.finals
        }
        TranscriptHash::Sha => {
            let mut t = vec![];
            for i in 0..proofs.len() {
                t.push(ShaRead::<_, _, _, sha2::Sha256>::init(&proofs[i][..]));
            }
            let empty = vec![];
            t.push(ShaRead::init(&empty[..]));
            let mut ctx = NativeEvalContext::<E, _, _>::new(c, instance_commitments, t);
            ctx.context_eval();
            ctx.finals
        }
        TranscriptHash::Keccak => {
            let mut t = vec![];
            for i in 0..proofs.len() {
                t.push(ShaRead::<_, _, _, sha3::Keccak256>::init(&proofs[i][..]));
            }
            let empty = vec![];
            t.push(ShaRead::init(&empty[..]));
            let mut ctx = NativeEvalContext::<E, _, _>::new(c, instance_commitments, t);
            ctx.context_eval();
            ctx.finals
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


#[test]
fn test_verify_hyper_proof() {
    use std::{fs::File, io::BufReader, marker::PhantomData, path::PathBuf};
    use halo2_proofs::pairing::bn256::Bn256;
    use halo2_proofs::arithmetic::MultiMillerLoop;
    use halo2_proofs::arithmetic::Engine;
    // use halo2_proofs::pairing::arithmetic::MultiMillerLoop;
    use plonkish_backend::pcs::multilinear::ZeromorphKzgVerifierParam;
    use plonkish_backend::pcs::multilinear;
    use plonkish_backend::pcs::univariate;
    use plonkish_backend::pcs::univariate::UnivariateKzgCommitment;
    use plonkish_backend::backend::hyperplonk::HyperPlonkVerifierParam;
    use plonkish_backend::backend::hyperplonk::HyperPlonkVerifierSetupParam;

    let file = File::open("./test/hyperplonk_vk.json").expect("File does not exist");
    type kzg = multilinear::Zeromorph<univariate::UnivariateKzg<Bn256>>;
    let vp: HyperPlonkVerifierParam<<Bn256 as Engine>::G1Affine> = match serde_json::from_reader(BufReader::new(file)) {
        Err(e) => {
            println!("load json error {:?}", e);
            unreachable!();
        }
        Ok(o) => o,
    };
    let vp = VerifierKey::HyperPlonk(vp);

    let file = File::open("./test/hyperplonk_proof.json").expect("File does not exist");
    let proof: Vec<u8> = match serde_json::from_reader(BufReader::new(file)) {
        Err(e) => {
            println!("load json error {:?}", e);
            unreachable!();
        }
        Ok(o) => o,
    };

    let file = File::open("./test/vs.json").expect("File does not exist");
    let vs: HyperPlonkVerifierSetupParam<<Bn256 as Engine>::Scalar, kzg> = match serde_json::from_reader(BufReader::new(file)) {
        Err(e) => {
            println!("load json error {:?}", e);
            unreachable!();
        }
        Ok(o) => o,
    };
    let zero_veri_param = &vs.pcs as &ZeromorphKzgVerifierParam<Bn256>;
    let verify_param = ParamsVerifier::<Bn256>{
        k:14,
        n:14,
        g1:zero_veri_param.g1(),
        g2:zero_veri_param.g2(),
        s_g2:zero_veri_param.s_g2(),
        g_lagrange:vec![],
    };

    verify_proofs(&verify_param,&[&vp],&vec![],
                        vec![proof],TranscriptHash::Poseidon,&vec![],false,&vec![]);


}