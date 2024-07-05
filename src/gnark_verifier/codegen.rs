use crate::api::ast_eval::EvalContext;
use crate::api::ast_eval::EvalOps;
use crate::api::ast_eval::EvalPos;
use crate::api::halo2::verify_aggregation_proofs;
use crate::circuits::utils::instance_to_instance_commitment;
use crate::transcript::sha256::ShaRead;
use halo2_proofs::arithmetic::CurveAffine;
use halo2_proofs::arithmetic::Field;
use halo2_proofs::arithmetic::MillerLoopResult;
use halo2_proofs::arithmetic::MultiMillerLoop;
use halo2_proofs::pairing::group::Curve;
use halo2_proofs::pairing::group::Group;
use halo2_proofs::plonk::VerifyingKey;
use halo2_proofs::poly::commitment::ParamsVerifier;
use halo2_proofs::transcript::Challenge255;
use halo2_proofs::transcript::EncodedChallenge;
use halo2_proofs::transcript::Transcript;
use halo2_proofs::transcript::TranscriptRead;
use halo2ecc_s::utils::field_to_bn;
use sha2::Digest;
use std::io::Read;

struct GnarkEvalContext<R: Read, E: MultiMillerLoop, D: Digest> {
    c: EvalContext<E::G1Affine>,
    instance_commitments: Vec<E::G1Affine>,
    t: ShaRead<R, E::G1Affine, Challenge255<E::G1Affine>, D>,

    commiment_idx: usize,
    eval_idx: usize,
    challenge_idx: usize,

    challenges: Vec<E::Scalar>,
    values: Vec<(Option<E::G1Affine>, Option<E::Scalar>)>,
    finals: Vec<E::G1Affine>,

    statements: Vec<String>,
}

impl<R: Read, E: MultiMillerLoop, D: Digest + Clone> GnarkEvalContext<R, E, D> {
    pub fn new(
        c: EvalContext<E::G1Affine>,
        instance_commitments: Vec<E::G1Affine>,
        t: ShaRead<R, E::G1Affine, Challenge255<E::G1Affine>, D>,
    ) -> Self {
        Self {
            c,
            instance_commitments,
            t,
            values: vec![],
            finals: vec![],
            challenges: vec![],
            challenge_idx: 0,
            commiment_idx: 0,
            eval_idx: 0,
            statements: vec![],
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
            EvalPos::Instance(_, j) => self.instance_commitments[*j],
            _ => unreachable!(),
        }
    }

    fn eval_any_pos(&self, pos: &EvalPos) -> (Option<E::G1Affine>, Option<E::Scalar>) {
        match pos {
            EvalPos::Ops(i) => self.values[*i],
            _ => unreachable!(),
        }
    }

    pub fn value_gen(&mut self) {
        for (_, op) in self.c.ops.iter().enumerate() {
            self.values.push(match op {
                EvalOps::TranscriptReadScalar(_, _) => (None, Some(self.t.read_scalar().unwrap())),
                EvalOps::TranscriptReadPoint(_, _) => (Some(self.t.read_point().unwrap()), None),
                EvalOps::TranscriptCommonScalar(_, _, s) => {
                    let v = self.eval_scalar_pos(s);
                    self.t.common_scalar(v).unwrap();
                    (None, None)
                }
                EvalOps::TranscriptCommonPoint(_, _, p) => {
                    let v = self.eval_point_pos(p);
                    self.t.common_point(v).unwrap();
                    (None, None)
                }
                EvalOps::TranscriptSqueeze(_, _) => {
                    let c = self.t.squeeze_challenge().get_scalar();
                    self.challenges.push(c);
                    (None, Some(c))
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
                EvalOps::ScalarDiv(a, b) => {
                    let t = self.eval_scalar_pos(a) * self.eval_scalar_pos(b).invert().unwrap();
                    (None, Some(t))
                }
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
            })
        }

        self.finals = self
            .c
            .finals
            .iter()
            .map(|x| self.values[*x].0.unwrap())
            .collect();
    }

    fn render_scalar_pos(&self, pos: &EvalPos) -> String {
        match pos {
            EvalPos::Constant(i) => format!("const_scalars[{}]", *i),
            EvalPos::Empty => unreachable!(),
            EvalPos::Instance(_, _) => unreachable!(),
            EvalPos::Ops(i) => format!("t{}", *i),
        }
    }

    fn render_point_pos(&self, pos: &EvalPos) -> String {
        match pos {
            EvalPos::Constant(i) => format!("const_points[{}]", *i),
            EvalPos::Empty => unreachable!(),
            EvalPos::Instance(_, i) => format!("instanceCommitments[{}]", *i),
            EvalPos::Ops(i) => format!("t{}", *i),
        }
    }

    pub fn code_gen(&mut self) {
        for (i, op) in self.c.ops.clone().iter().enumerate() {
            match op {
                EvalOps::CheckPoint(_, _) => (),
                EvalOps::TranscriptReadScalar(_, _) => {
                    self.statements
                        .push(format!("t{} := evals[{}]", i, self.eval_idx));
                    self.eval_idx += 1;
                }
                EvalOps::TranscriptReadPoint(_, _) => {
                    self.statements
                        .push(format!("t{} := commitments[{}]", i, self.commiment_idx));
                    self.commiment_idx += 1;
                }
                EvalOps::TranscriptSqueeze(_, _) => {
                    self.statements
                        .push(format!("t{} := challenges[{}]", i, self.challenge_idx));
                    self.challenge_idx += 1;
                }
                EvalOps::ScalarMul(a, b, _) => {
                    self.statements.push(format!(
                        "t{} := halo2Api.api.Mul({}, {})",
                        i,
                        self.render_scalar_pos(a),
                        self.render_scalar_pos(b)
                    ));
                }
                EvalOps::ScalarAdd(a, b) => {
                    self.statements.push(format!(
                        "t{} := halo2Api.api.Add({}, {})",
                        i,
                        self.render_scalar_pos(a),
                        self.render_scalar_pos(b)
                    ));
                }
                EvalOps::ScalarSub(a, b) => {
                    self.statements.push(format!(
                        "t{} := halo2Api.api.Sub({}, {})",
                        i,
                        self.render_scalar_pos(a),
                        self.render_scalar_pos(b)
                    ));
                }
                EvalOps::ScalarDiv(a, b) => {
                    self.statements.push(format!(
                        "t{} := halo2Api.api.Div({}, {})",
                        i,
                        self.render_scalar_pos(a),
                        self.render_scalar_pos(b)
                    ));
                }
                EvalOps::ScalarPow(a, n) => {
                    self.statements.push(format!(
                        "t{} := ScalarPow(halo2Api.api, {}, {})",
                        i,
                        self.render_scalar_pos(a),
                        *n
                    ));
                }
                EvalOps::MSMSlice((p, s), last, group) => {
                    if let Some(_) = last {
                        self.statements.push(format!(
                            "p{} = halo2Api.bn254Api.BN254ScalarMulAndAddG1({}, {}, p{})",
                            *group,
                            self.render_point_pos(p),
                            self.render_scalar_pos(s),
                            *group
                        ));
                    } else {
                        self.statements.push(format!(
                            "p{} := halo2Api.bn254Api.BN254ScalarMul({}, {})",
                            *group,
                            self.render_point_pos(p),
                            self.render_scalar_pos(s)
                        ));
                    }
                }
                EvalOps::MSM(_psl, _) => {
                    //skip this because we handled msm slice
                }
                _ => (),
            }
        }
    }
}

pub fn gnark_codegen_with_proof<E: MultiMillerLoop, D: Digest + Clone>(
    params: &ParamsVerifier<E>,
    vkey: &VerifyingKey<E::G1Affine>,
    instances: &Vec<E::Scalar>,
    proofs: Vec<u8>,
    check: bool,
) -> String {
    let (w_x, w_g, _) = verify_aggregation_proofs(params, &[vkey], &vec![], true, &vec![]);

    let instance_commitments =
        instance_to_instance_commitment(params, &[vkey], vec![&vec![instances.clone()]])[0].clone();

    let targets = vec![w_x.0, w_g.0];

    let c = EvalContext::translate(&targets[..]);

    let mut ctx = GnarkEvalContext::<_, E, D>::new(
        c,
        instance_commitments,
        ShaRead::<_, _, _, D>::init(&proofs[..]),
    );

    ctx.value_gen();
    ctx.code_gen();

    if check {
        let s_g2_prepared = E::G2Prepared::from(params.s_g2);
        let n_g2_prepared = E::G2Prepared::from(-params.g2);
        let success = bool::from(
            E::multi_miller_loop(&[
                (&ctx.finals[0], &s_g2_prepared),
                (&ctx.finals[1], &n_g2_prepared),
            ])
            .final_exponentiation()
            .is_identity(),
        );

        assert!(success);
    }

    for challenge in ctx.challenges {
        println!("challenge: {:?}", challenge)
    }

    let mut statements_pre = vec![
        format!("x := big.NewInt(0)"),
        format!("y := big.NewInt(0)"),
        format!(
            "const_scalars := make([]frontend.Variable, {})",
            ctx.c.const_scalars.len()
        ),
        format!(
            "const_points := make([]*sw_emulated.AffinePoint[emparams.BN254Fp], {})",
            ctx.c.const_points.len()
        ),
    ];

    for (i, cs) in ctx.c.const_scalars.iter().enumerate() {
        statements_pre.push(format!(
            "const_scalars[{}], _ = new(big.Int).SetString(\"{}\",10)",
            i,
            field_to_bn(cs).to_str_radix(10)
        ));
    }

    for (i, cp) in ctx.c.const_points.iter().enumerate() {
        statements_pre.push(format!(
            "const_points[{}] = new(sw_emulated.AffinePoint[emparams.BN254Fp])",
            i
        ));
        statements_pre.push(format!(
            "x, _ = new(big.Int).SetString(\"{}\",10)",
            field_to_bn(cp.coordinates().unwrap().x()).to_str_radix(10)
        ));
        statements_pre.push(format!(
            "y, _ = new(big.Int).SetString(\"{}\",10)",
            field_to_bn(cp.coordinates().unwrap().x()).to_str_radix(10)
        ));
        statements_pre.push(format!(
            "const_points[{}].X = emulated.ValueOf[emparams.BN254Fp](x)",
            i
        ));
        statements_pre.push(format!(
            "const_points[{}].Y = emulated.ValueOf[emparams.BN254Fp](y)",
            i
        ));
    }

    statements_pre.append(&mut ctx.statements);
    statements_pre
        .into_iter()
        .reduce(|a, b| format!("{}\n{}", a, b))
        .unwrap()
}
