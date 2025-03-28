use crate::api::ast_eval::EvalContext;
use crate::api::ast_eval::EvalOps;
use crate::api::ast_eval::EvalPos;
use crate::api::halo2::verify_aggregation_proofs;
use crate::circuits::utils::instance_to_instance_commitment;
use crate::transcript::sha256::ShaRead;
use crate::utils::field_to_bn;
use halo2_proofs::arithmetic::BaseExt;
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
use sha2::Digest;
use std::collections::BTreeSet;
use std::io::Read;
use std::path::Path;

const INSTANCE_COLUMN_COUNT: usize = 1;
const MAX_MSM_COUNT: usize = 2;
const CHALLENGE_BUF_START: usize = 2 * INSTANCE_COLUMN_COUNT;
const CHALLENGE_BUF_MAX: usize = 8;
const MSM_BUF_START: usize = CHALLENGE_BUF_START + CHALLENGE_BUF_MAX;
const TEMP_BUF_START: usize = MSM_BUF_START + 2 * MAX_MSM_COUNT + 3; // 3 reserved for msm operation;
const DEEP_LIMIT: usize = 6;

const SOLIDITY_VERIFY_FIRST_STEP_MAX_SIZE: usize = 90; // first step need to be less for shplonk
const SOLIDITY_VERIFY_STEP_MAX_SIZE: usize = 100;

const SOLIDITY_DEBUG: bool = false;

#[derive(Clone)]
pub enum SolidityVar<E: MultiMillerLoop> {
    Transcript(usize),
    Instance(usize),
    Challenge(usize),
    Temp(usize, usize), // var_index, op_pos
    ConstantScalar(E::Scalar),
    ConstantPoint(E::G1Affine),
    Expression(String, usize, Vec<(usize, usize)>),
}

impl<E: MultiMillerLoop> SolidityVar<E> {
    pub fn get_deep(&self) -> usize {
        match &self {
            SolidityVar::Expression(_, n, _) => *n,
            _ => 1,
        }
    }

    pub fn get_dep(&self) -> Vec<(usize, usize)> {
        match &self {
            SolidityVar::Expression(_, _, dep) => dep.clone(),
            SolidityVar::Temp(t, i) => vec![(*t, *i)],
            _ => vec![],
        }
    }

    pub fn to_string(&self, is_scalar: bool) -> String {
        match &self {
            SolidityVar::Transcript(i) => {
                if is_scalar {
                    format!("transcript[{}]", i)
                } else {
                    format!("(transcript[{}], transcript[{}])", i, i + 1)
                }
            }
            SolidityVar::Instance(i) => format!("(buf[{}], buf[{}])", i, i + 1),
            SolidityVar::Challenge(i) => format!("buf[{}]", i + CHALLENGE_BUF_START),
            SolidityVar::Temp(i, _) => {
                assert!(is_scalar);
                format!("buf[{}]", i)
            }
            SolidityVar::ConstantScalar(i) => field_to_bn(i).to_str_radix(10),
            SolidityVar::ConstantPoint(p) => {
                let c = p.coordinates().unwrap();
                format!(
                    "({}, {})",
                    field_to_bn(c.x()).to_str_radix(10),
                    field_to_bn(c.y()).to_str_radix(10)
                )
            }
            SolidityVar::Expression(s, _, _) => s.to_owned(),
        }
    }
}

struct SolidityEvalContext<R: Read, E: MultiMillerLoop, D: Digest> {
    c: EvalContext<E::G1Affine>,
    instance_commitments: Vec<E::G1Affine>,
    t: ShaRead<R, E::G1Affine, Challenge255<E::G1Affine>, D>,

    statements: Vec<String>,
    exprs: Vec<Option<SolidityVar<E>>>,
    values: Vec<(Option<E::G1Affine>, Option<E::Scalar>)>,
    finals: Vec<E::G1Affine>,
    lifetime: Vec<usize>,
    deps: Vec<usize>,
    aux_index: usize,
    transcript_idx: usize,
    challenge_idx: usize,
    temp_idx_allocator: (BTreeSet<usize>, usize),
    max_temp_buffer_index: usize,
    constant_scalars: Vec<E::Scalar>,
    div_res: Vec<E::Scalar>,
    challenges: Vec<E::Scalar>,
}

impl<R: Read, E: MultiMillerLoop, D: Digest + Clone> SolidityEvalContext<R, E, D> {
    pub fn new(
        c: EvalContext<E::G1Affine>,
        instance_commitments: Vec<E::G1Affine>,
        t: ShaRead<R, E::G1Affine, Challenge255<E::G1Affine>, D>,
    ) -> Self {
        Self {
            c,
            instance_commitments,
            t,
            statements: vec![],
            exprs: vec![],
            values: vec![],
            finals: vec![],
            lifetime: vec![],
            deps: vec![],
            transcript_idx: 0,
            challenge_idx: 0,
            aux_index: 0,
            temp_idx_allocator: (BTreeSet::new(), TEMP_BUF_START),
            max_temp_buffer_index: 0,
            constant_scalars: vec![],
            div_res: vec![],
            challenges: vec![],
        }
    }

    fn tag_lifetime(&mut self, to: &EvalPos, curr: usize) {
        match to {
            EvalPos::Ops(i) => {
                self.lifetime[*i] = curr;
                self.deps[*i] += 1;
            }
            _ => {}
        }
    }

    fn try_release_temp_idx(&mut self, dep: &SolidityVar<E>) {
        match dep {
            SolidityVar::Temp(t, i) => {
                self.deps[*i] -= 1;
                if self.deps[*i] == 0 {
                    self.temp_idx_allocator.0.insert(*t);
                }
            }
            SolidityVar::Expression(_, _, dep) => {
                for (t, i) in dep {
                    self.deps[*i] -= 1;
                    if self.deps[*i] == 0 {
                        self.temp_idx_allocator.0.insert(*t);
                    }
                }
            }
            _ => {}
        }
    }

    fn alloc_temp_idx(&mut self) -> usize {
        if self.temp_idx_allocator.0.len() == 0 {
            self.temp_idx_allocator.1 += 1;
            if self.temp_idx_allocator.1 > self.max_temp_buffer_index {
                self.max_temp_buffer_index = self.temp_idx_allocator.1;
            }
            self.temp_idx_allocator.1.clone() - 1
        } else {
            self.temp_idx_allocator.0.pop_first().clone().unwrap()
        }
    }

    fn pos_is_constant_zero(&self, p: &EvalPos) -> bool {
        match p {
            EvalPos::Constant(i) => {
                let s = self.c.const_scalars[*i];
                s.is_zero_vartime()
            }
            _ => false,
        }
    }

    fn pos_to_scalar_var(&mut self, p: &EvalPos) -> SolidityVar<E> {
        match p {
            EvalPos::Constant(i) => {
                let s = self.c.const_scalars[*i];
                self.constant_scalars.push(s);
                SolidityVar::ConstantScalar(s)
            }
            EvalPos::Ops(i) => self.exprs[*i].clone().unwrap(),
            _ => unreachable!(),
        }
    }

    fn pos_to_point_var(&mut self, p: &EvalPos) -> SolidityVar<E> {
        match p {
            EvalPos::Constant(i) => SolidityVar::ConstantPoint::<E>(self.c.const_points[*i]),
            EvalPos::Instance(_, i) => SolidityVar::Instance(*i),
            EvalPos::Ops(i) => self.exprs[*i].clone().unwrap(),
            _ => unreachable!(),
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
                    self.div_res.push(t);
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

    pub fn code_gen(&mut self) {
        // first tag lifetime
        for (i, op) in self.c.ops.clone().iter().enumerate() {
            self.lifetime.push(i);
            self.deps.push(0);
            match op {
                EvalOps::ScalarMul(a, b, _) => {
                    self.tag_lifetime(a, i);
                    self.tag_lifetime(b, i);
                }
                EvalOps::ScalarAdd(a, b) => {
                    self.tag_lifetime(a, i);
                    self.tag_lifetime(b, i);
                }
                EvalOps::ScalarSub(a, b) => {
                    self.tag_lifetime(a, i);
                    self.tag_lifetime(b, i);
                }
                EvalOps::ScalarDiv(a, b) => {
                    self.tag_lifetime(a, i);
                    self.tag_lifetime(b, i);
                }
                EvalOps::ScalarPow(a, _) => {
                    self.tag_lifetime(a, i);
                }
                EvalOps::MSMSlice((a, b), c, _) => {
                    self.tag_lifetime(a, i);
                    self.tag_lifetime(b, i);
                    if let Some(c) = c {
                        self.tag_lifetime(c, i);
                    }
                }
                EvalOps::CheckPoint(_, a) => {
                    self.tag_lifetime(a, i);
                }
                _ => {}
            }
        }

        let get_combine_degree = |a, b| usize::max(a, b) + 1;

        for (i, op) in self.c.ops.clone().iter().enumerate() {
            let expr = match op {
                EvalOps::CheckPoint(_, _) => None,
                EvalOps::TranscriptReadScalar(_, _) => {
                    self.transcript_idx += 1;
                    Some(SolidityVar::Transcript(self.transcript_idx - 1))
                }
                EvalOps::TranscriptReadPoint(_, _) => {
                    self.transcript_idx += 2;
                    Some(SolidityVar::Transcript(self.transcript_idx - 2))
                }
                EvalOps::TranscriptSqueeze(_, _) => {
                    self.challenge_idx += 1;
                    Some(SolidityVar::Challenge(self.challenge_idx - 1))
                }
                EvalOps::ScalarMul(a, b, _) => {
                    let a = self.pos_to_scalar_var(a);
                    let b = self.pos_to_scalar_var(b);
                    let expr = format!(
                        "mulmod({}, {}, AggregatorLib.q_mod)",
                        a.to_string(true),
                        b.to_string(true)
                    );
                    if self.deps[i] == 1
                        && get_combine_degree(a.get_deep(), b.get_deep()) < DEEP_LIMIT
                    {
                        Some(SolidityVar::Expression(
                            expr,
                            get_combine_degree(a.get_deep(), b.get_deep()),
                            vec![a.get_dep(), b.get_dep()].concat(),
                        ))
                    } else {
                        self.try_release_temp_idx(&a);
                        self.try_release_temp_idx(&b);
                        let t = self.alloc_temp_idx();
                        self.statements.push(format!("buf[{}] = {};", t, expr));

                        if SOLIDITY_DEBUG {
                            self.statements.push(format!(
                                "require(buf[{}] == {}, \"ops {}\");",
                                t,
                                field_to_bn(self.values[i].1.as_ref().unwrap()).to_str_radix(10),
                                i
                            ));
                        }
                        Some(SolidityVar::Temp(t, i))
                    }
                }
                EvalOps::ScalarAdd(a, b) => {
                    let a = self.pos_to_scalar_var(a);
                    let b = self.pos_to_scalar_var(b);
                    let expr = format!(
                        "addmod({}, {}, AggregatorLib.q_mod)",
                        a.to_string(true),
                        b.to_string(true)
                    );
                    if self.deps[i] == 1
                        && get_combine_degree(a.get_deep(), b.get_deep()) < DEEP_LIMIT
                    {
                        Some(SolidityVar::Expression(
                            expr,
                            get_combine_degree(a.get_deep(), b.get_deep()),
                            vec![a.get_dep(), b.get_dep()].concat(),
                        ))
                    } else {
                        self.try_release_temp_idx(&a);
                        self.try_release_temp_idx(&b);
                        let t = self.alloc_temp_idx();
                        self.statements.push(format!("buf[{}] = {};", t, expr));
                        if SOLIDITY_DEBUG {
                            self.statements.push(format!(
                                "require(buf[{}] == {}, \"ops {}\");",
                                t,
                                field_to_bn(self.values[i].1.as_ref().unwrap()).to_str_radix(10),
                                i
                            ));
                        }
                        Some(SolidityVar::Temp(t, i))
                    }
                }
                EvalOps::ScalarSub(_a, b) => {
                    let a = self.pos_to_scalar_var(_a);
                    let b = self.pos_to_scalar_var(b);
                    let expr = if self.pos_is_constant_zero(_a) {
                        format!("AggregatorLib.q_mod - {}", b.to_string(true))
                    } else {
                        format!(
                            "addmod({}, AggregatorLib.q_mod - {}, AggregatorLib.q_mod)",
                            a.to_string(true),
                            b.to_string(true)
                        )
                    };

                    if self.deps[i] == 1
                        && get_combine_degree(a.get_deep(), b.get_deep()) < DEEP_LIMIT
                    {
                        Some(SolidityVar::Expression(
                            expr,
                            get_combine_degree(a.get_deep(), b.get_deep()),
                            vec![a.get_dep(), b.get_dep()].concat(),
                        ))
                    } else {
                        self.try_release_temp_idx(&a);
                        self.try_release_temp_idx(&b);
                        let t = self.alloc_temp_idx();
                        self.statements.push(format!("buf[{}] = {};", t, expr));

                        if SOLIDITY_DEBUG {
                            self.statements.push(format!(
                                "require(buf[{}] == {}, \"ops {}\");",
                                t,
                                field_to_bn(self.values[i].1.as_ref().unwrap()).to_str_radix(10),
                                i
                            ));
                        }
                        Some(SolidityVar::Temp(t, i))
                    }
                }
                EvalOps::ScalarDiv(a, b) => {
                    let aux_index = self.aux_index;
                    self.aux_index += 1;

                    let a = self.pos_to_scalar_var(a);
                    let b = self.pos_to_scalar_var(b);
                    let expr = format!(
                        "AggregatorLib.fr_div({}, {}, aux[{}])",
                        a.to_string(true),
                        b.to_string(true),
                        aux_index
                    );
                    if self.deps[i] == 1
                        && get_combine_degree(a.get_deep(), b.get_deep()) < DEEP_LIMIT
                    {
                        Some(SolidityVar::Expression(
                            expr,
                            get_combine_degree(a.get_deep(), b.get_deep()),
                            vec![a.get_dep(), b.get_dep()].concat(),
                        ))
                    } else {
                        self.try_release_temp_idx(&a);
                        self.try_release_temp_idx(&b);
                        let t = self.alloc_temp_idx();
                        self.statements.push(format!("buf[{}] = {};", t, expr));

                        if SOLIDITY_DEBUG {
                            self.statements.push(format!(
                                "require(buf[{}] == {}, \"ops {}\");",
                                t,
                                field_to_bn(self.values[i].1.as_ref().unwrap()).to_str_radix(10),
                                i
                            ));
                        }
                        Some(SolidityVar::Temp(t, i))
                    }
                }
                EvalOps::ScalarPow(a, n) => {
                    let a = self.pos_to_scalar_var(a);
                    self.try_release_temp_idx(&a);
                    let a = a.to_string(true);
                    let t = self.alloc_temp_idx();
                    self.statements
                        .push(format!("buf[{}] = AggregatorLib.fr_pow({}, {});", t, a, n));

                    if SOLIDITY_DEBUG {
                        self.statements.push(format!(
                            "require(buf[{}] == {}, \"ops {}\");",
                            t,
                            field_to_bn(self.values[i].1.as_ref().unwrap()).to_str_radix(10),
                            i
                        ));
                    }
                    Some(SolidityVar::Temp(t, i))
                }
                EvalOps::MSMSlice((p, s), last, group) => {
                    let p = self.pos_to_point_var(p);
                    let s = self.pos_to_scalar_var(s);
                    self.try_release_temp_idx(&s);
                    let start: usize = MSM_BUF_START + group * 2;
                    let p_str = p.to_string(false);
                    let s_str = s.to_string(true);
                    if last.is_some() {
                        let idx = 2;
                        self.statements.push(format!(
                            "(buf[{}], buf[{}]) = {};",
                            start + idx,
                            start + idx + 1,
                            p_str
                        ));
                        self.statements
                            .push(format!("buf[{}] = {};", start + idx + 2, s_str));
                        self.statements
                            .push(format!("AggregatorLib.ecc_mul_add(buf, {});", start));
                    } else {
                        let idx = 0;
                        self.statements.push(format!(
                            "(buf[{}], buf[{}]) = {};",
                            start + idx,
                            start + idx + 1,
                            p_str
                        ));
                        self.statements
                            .push(format!("buf[{}] = {};", start + idx + 2, s_str));
                        self.statements
                            .push(format!("AggregatorLib.ecc_mul(buf, {});", start));
                    }

                    None
                }
                EvalOps::MSM(_psl, _) => {
                    /*
                    assert!(self.msm_len.len() <= MAX_MSM_COUNT);
                    let start: usize = MSM_BUF_START + self.msm_len.len() * 2;

                    self.msm_index += 1;
                    self.msm_len.push(psl.len());

                    for (i, (p, s)) in psl.iter().enumerate() {
                        let p_str = self.pos_to_point_var(p).to_string(false);
                        let s_str = self.pos_to_scalar_var(s).to_string(true);

                        let idx = if i == 0 { 0 } else { 2 };

                        self.statements.push(format!(
                            "(buf[{}], buf[{}]) = {};",
                            start + idx,
                            start + idx + 1,
                            p_str
                        ));

                        self.statements
                            .push(format!("buf[{}] = {};", start + idx + 2, s_str));

                        if SOLIDITY_DEBUG {
                            let start = start + if i == 0 { 0 } else { 2 };
                            let p_value = self.eval_point_pos(p).coordinates().unwrap();
                            let s_value = self.eval_scalar_pos(s);
                            self.statements.push(format!(
                                "require(buf[{}] == {}, \"ops {}.0\");",
                                start,
                                field_to_bn(p_value.x()).to_str_radix(10),
                                i
                            ));
                            self.statements.push(format!(
                                "require(buf[{}] == {}, \"ops {}.1\");",
                                start + 1,
                                field_to_bn(p_value.y()).to_str_radix(10),
                                i
                            ));
                            self.statements.push(format!(
                                "require(buf[{}] == {}, \"ops {}.2\");",
                                start + 2,
                                field_to_bn(&s_value).to_str_radix(10),
                                i
                            ));
                        }

                        if i > 0 {
                            self.statements
                                .push(format!("AggregatorLib.ecc_mul_add(buf, {});", start));
                        } else {
                            self.statements
                                .push(format!("AggregatorLib.ecc_mul(buf, {});", start));
                        }
                    } */

                    None
                }
                _ => None,
            };
            self.exprs.push(expr);
        }
    }
}

pub fn solidity_codegen_with_proof<E: MultiMillerLoop, D: Digest + Clone>(
    params: &ParamsVerifier<E>,
    vkey: &VerifyingKey<E::G1Affine>,
    instances: &Vec<E::Scalar>,
    proofs: Vec<u8>,
    tera_context: &mut tera::Context,
    check: bool,
) -> Vec<String> {
    let (w_x, w_g, _) = verify_aggregation_proofs(params, &[vkey], &vec![], true, &vec![]);

    let instance_commitments =
        instance_to_instance_commitment(params, &[vkey], vec![&vec![instances.clone()]])[0].clone();

    let targets = vec![w_x.0, w_g.0];

    let c = EvalContext::translate(&targets[..]);

    let mut ctx = SolidityEvalContext::<_, E, D>::new(
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

    tera_context.insert("n_constant_scalars", &ctx.constant_scalars.len());

    tera_context.insert(
        "constant_scalars",
        &ctx.constant_scalars
            .iter()
            .map(|x| field_to_bn(x).to_str_radix(10))
            .collect::<Vec<_>>(),
    );

    tera_context.insert("msm_w_x_start", &MSM_BUF_START);
    tera_context.insert("msm_w_g_start", &(MSM_BUF_START + 2));

    if SOLIDITY_DEBUG {
        tera_context.insert(
            &format!("challenges"),
            &ctx.challenges
                .iter()
                .map(|x| field_to_bn(x).to_str_radix(10))
                .collect::<Vec<_>>(),
        );
    }

    let mut res = vec![ctx.statements[..SOLIDITY_VERIFY_FIRST_STEP_MAX_SIZE]
        .iter()
        .map(|x| format!("{}\n", x))
        .collect::<Vec<_>>()
        .concat()];

    res.append(
        &mut ctx.statements[SOLIDITY_VERIFY_FIRST_STEP_MAX_SIZE..]
            .chunks(SOLIDITY_VERIFY_STEP_MAX_SIZE)
            .map(|c| {
                c.iter()
                    .map(|x| format!("{}\n", x))
                    .collect::<Vec<_>>()
                    .concat()
            })
            .collect(),
    );
    res
}

pub fn solidity_aux_gen<E: MultiMillerLoop, D: Digest + Clone>(
    params: &ParamsVerifier<E>,
    vkey: &VerifyingKey<E::G1Affine>,
    instances: &Vec<E::Scalar>,
    proofs: Vec<u8>,
    aux_file: &Path,
) {
    let div_res = solidity_aux_gen_data::<_, D>(params, vkey, instances, proofs, true);
    let mut fd = std::fs::File::create(&aux_file).unwrap();
    div_res.iter().for_each(|res| res.write(&mut fd).unwrap());
}

pub fn solidity_aux_gen_data<E: MultiMillerLoop, D: Digest + Clone>(
    params: &ParamsVerifier<E>,
    vkey: &VerifyingKey<E::G1Affine>,
    instances: &Vec<E::Scalar>,
    proofs: Vec<u8>,
    check: bool,
) -> Vec<E::Scalar> {
    let (w_x, w_g, _) = verify_aggregation_proofs(params, &[vkey], &vec![], true, &vec![]);

    let instance_commitments =
        instance_to_instance_commitment(params, &[vkey], vec![&vec![instances.clone()]])[0].clone();

    let targets = vec![w_x.0, w_g.0];

    let c = EvalContext::translate(&targets[..]);

    let mut ctx = SolidityEvalContext::<_, E, D>::new(
        c,
        instance_commitments,
        ShaRead::<_, _, _, D>::init(&proofs[..]),
    );

    ctx.value_gen();

    let s_g2_prepared = E::G2Prepared::from(params.s_g2);
    let n_g2_prepared = E::G2Prepared::from(-params.g2);
    if check {
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
    ctx.div_res
}
