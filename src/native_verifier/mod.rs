use crate::api::ast_eval::EvalContext;
use crate::api::ast_eval::EvalOps;
use crate::api::ast_eval::EvalPos;
use crate::api::verify_aggregation_proofs;
use crate::api::VerifierKey;
use crate::circuits::utils::instance_to_instance_commitment;
use crate::circuits::utils::TranscriptHash;
use crate::transcript::poseidon::PoseidonPure;
use crate::transcript::poseidon::PoseidonRead;
use crate::transcript::sha256::ShaRead;
use ark_std::iterable::Iterable;
use halo2_proofs::arithmetic::Field;
use halo2_proofs::arithmetic::MillerLoopResult;
use halo2_proofs::arithmetic::MultiMillerLoop;
use halo2_proofs::pairing::group::Curve;
use halo2_proofs::pairing::group::Group;
use halo2_proofs::poly::commitment::ParamsVerifier;
use halo2_proofs::transcript::Blake2bRead;
use halo2_proofs::transcript::Challenge255;
use halo2_proofs::transcript::EncodedChallenge;
use halo2_proofs::transcript::TranscriptRead;
use std::collections::HashMap;
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
    commitment_diff_basis_check: &Vec<[usize; 4]>,
    use_shplonk_as_default: bool,
    proofs_with_shplonk: &Vec<usize>,
) {
    let (w_x, w_g, advices, cross_terms) = verify_aggregation_proofs(
        params,
        vkey,
        commitment_check,
        use_shplonk_as_default,
        proofs_with_shplonk,
        instances,
    );

    let mut cross_terms_map = HashMap::new();
    for (proof_idx, commits) in cross_terms.iter().enumerate() {
        for (advice_idx, commit) in commits.iter() {
            cross_terms_map.insert((proof_idx, *advice_idx), commit.clone());
        }
    }

    let instance_commitments = instance_to_instance_commitment(params, vkey, instances);

    let mut targets = vec![w_x.0, w_g.0];
    for idx in commitment_check {
        targets.push(advices[idx[0]][idx[1]].0.clone());
        targets.push(advices[idx[2]][idx[3]].0.clone());
    }

    let commit_diff_basis_check_start_idx = targets.len();
    for idx in commitment_diff_basis_check {
        targets.push(advices[idx[0]][idx[1]].0.clone());
        targets.push(advices[idx[2]][idx[3]].0.clone());
    }

    let cross_terms_commit_start_idx = targets.len();
    //idx[0,1] for lagrange, idx[2,3] for coeff, only idx[2,3] needed
    for (i, idx) in commitment_diff_basis_check.iter().enumerate() {
        let vk_halo2 = vkey[idx[0]];
        assert!(
            vk_halo2.is_halo2(),
            "the {}-th diff_basis_commit_check's 1st proof is not halo2",
            i
        );
        let vk_hyper = vkey[idx[2]];
        assert!(
            vk_hyper.is_hyper_plonk(),
            "the {}-th diff_basis_commit_check's 2nd proof is not hyper",
            i
        );

        targets.push(cross_terms_map.get(&(idx[2], idx[3])).unwrap().0.clone());
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

    //TODO: add challenge for different proof's commits
    // commit_coeff + commit_lagrange
    let mut diff_basis_commit_sum = E::G1::identity();
    for c in &pl[commit_diff_basis_check_start_idx..cross_terms_commit_start_idx] {
        diff_basis_commit_sum = diff_basis_commit_sum + c;
    }

    // e(commit(coeff + lagrange),xG2)=e(commit_cross_item,G2)
    let mut cross_terms_commit_sum = E::G1::identity();
    for c in &pl[cross_terms_commit_start_idx..] {
        cross_terms_commit_sum = cross_terms_commit_sum + c;
    }

    let s_g2_prepared = E::G2Prepared::from(params.s_g2);
    let n_g2_prepared = E::G2Prepared::from(-params.g2);
    let success = bool::from(
        E::multi_miller_loop(&[
            (
                &(diff_basis_commit_sum + &pl[0]).to_affine(),
                &s_g2_prepared,
            ),
            (
                &(cross_terms_commit_sum + &pl[1]).to_affine(),
                &n_g2_prepared,
            ),
        ])
        .final_exponentiation()
        .is_identity(),
    );
    assert!(success);

    for c in pl[0..commit_diff_basis_check_start_idx].chunks(2).skip(1) {
        assert_eq!(c[0], c[1]);
    }
}
