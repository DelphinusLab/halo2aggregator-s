use crate::api::ast_eval::EvalContext;
use crate::api::ast_eval::EvalOps;
use crate::api::ast_eval::EvalPos;
use crate::api::halo2::verify_aggregation_proofs;
use crate::circuits::utils::instance_to_instance_commitment;
use crate::transcript::sha256::ShaRead;
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
use halo2ecc_s::utils::field_to_bn;
use std::collections::BTreeSet;
use std::env;
use std::io::Read;
use std::path::Path;

const CHALLENGE_BUF_START: usize = 2;
const TEMP_BUF_START: usize = 16;
const DEEP_LIMIT: usize = 6;

lazy_static! {
    static ref TEMP_BUF_MAX: usize = usize::from_str_radix(
        &env::var("HALO2_AGGREGATOR_S_TEMP_BUF_MAX").unwrap_or("170".to_owned()),
        10
    )
    .unwrap();
    static ref MSM_BUF_SIZE: usize = usize::from_str_radix(
        &env::var("HALO2_AGGREGATOR_S_MSM_BUF_SIZE").unwrap_or("5".to_owned()),
        10
    )
    .unwrap();
}

const SOLIDITY_VERIFY_STEP_MAX_SIZE: usize = 128;

const SOLIDITY_DEBUG: bool = false;

#[derive(Clone)]
pub enum SolidityVar<E: MultiMillerLoop> {
    Transcript(usize),
    Instance(usize),
    Challenge(usize),
    Temp(usize),
    ConstantScalar(E::Scalar),
    ConstantPoint(E::G1Affine),
    Expression(String, usize),
}

impl<E: MultiMillerLoop> SolidityVar<E> {
    pub fn get_deep(&self) -> usize {
        match &self {
            SolidityVar::Expression(_, n) => *n,
            _ => 1,
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
            SolidityVar::Temp(i) => {
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
            SolidityVar::Expression(s, _) => s.to_owned(),
        }
    }
}

struct SolidityEvalContext<R: Read, E: MultiMillerLoop> {
    c: EvalContext<E::G1Affine>,
    instance_commitments: Vec<E::G1Affine>,
    t: ShaRead<R, E::G1Affine, Challenge255<E::G1Affine>, sha2::Sha256>,

    statements: Vec<String>,
    exprs: Vec<Option<SolidityVar<E>>>,
    values: Vec<(Option<E::G1Affine>, Option<E::Scalar>)>,
    finals: Vec<E::G1Affine>,
    lifetime: Vec<usize>,
    deps: Vec<usize>,
    aux_index: usize,
    transcript_idx: usize,
    challenge_idx: usize,
    msm_index: usize,
    temp_idx_allocator: (BTreeSet<usize>, usize),
    constant_scalars: Vec<E::Scalar>,
    div_res: Vec<E::Scalar>,
    challenges: Vec<E::Scalar>,
    msm_len: Vec<usize>,
}

impl<R: Read, E: MultiMillerLoop> SolidityEvalContext<R, E> {
    pub fn new(
        c: EvalContext<E::G1Affine>,
        instance_commitments: Vec<E::G1Affine>,
        t: ShaRead<R, E::G1Affine, Challenge255<E::G1Affine>, sha2::Sha256>,
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
            msm_index: 0,
            aux_index: 0,
            temp_idx_allocator: (BTreeSet::new(), TEMP_BUF_START),
            constant_scalars: vec![],
            div_res: vec![],
            challenges: vec![],
            msm_len: vec![],
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

    fn alloc_temp_idx(&mut self) -> usize {
        if self.temp_idx_allocator.0.len() == 0 {
            self.temp_idx_allocator.1 += 1;
            assert!(self.temp_idx_allocator.1 <= *TEMP_BUF_MAX);
            self.temp_idx_allocator.1.clone() - 1
        } else {
            self.temp_idx_allocator.0.pop_first().clone().unwrap()
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
                EvalOps::MSM(psl) => (
                    psl.into_iter()
                        .map(|(p, s)| {
                            (self.eval_point_pos(p) * self.eval_scalar_pos(s)).to_affine()
                        })
                        .reduce(|acc, p| (acc + p).to_affine()),
                    None,
                ),
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
                EvalOps::MSM(psl) => {
                    psl.iter().for_each(|(p, s)| {
                        self.tag_lifetime(p, i);
                        self.tag_lifetime(s, i);
                    });
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
                        "mulmod({}, {}, AggregatorLib.p_mod)",
                        a.to_string(true),
                        b.to_string(true)
                    );
                    if self.deps[i] == 1
                        && get_combine_degree(a.get_deep(), b.get_deep()) < DEEP_LIMIT
                    {
                        Some(SolidityVar::Expression(
                            expr,
                            get_combine_degree(a.get_deep(), b.get_deep()),
                        ))
                    } else {
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
                        Some(SolidityVar::Temp(t))
                    }
                }
                EvalOps::ScalarAdd(a, b) => {
                    let a = self.pos_to_scalar_var(a);
                    let b = self.pos_to_scalar_var(b);
                    let expr = format!(
                        "addmod({}, {}, AggregatorLib.p_mod)",
                        a.to_string(true),
                        b.to_string(true)
                    );
                    if self.deps[i] == 1
                        && get_combine_degree(a.get_deep(), b.get_deep()) < DEEP_LIMIT
                    {
                        Some(SolidityVar::Expression(
                            expr,
                            get_combine_degree(a.get_deep(), b.get_deep()),
                        ))
                    } else {
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
                        Some(SolidityVar::Temp(t))
                    }
                }
                EvalOps::ScalarSub(a, b) => {
                    let a = self.pos_to_scalar_var(a);
                    let b = self.pos_to_scalar_var(b);
                    let expr = format!(
                        "addmod({}, AggregatorLib.p_mod - {}, AggregatorLib.p_mod)",
                        a.to_string(true),
                        b.to_string(true)
                    );
                    if self.deps[i] == 1
                        && get_combine_degree(a.get_deep(), b.get_deep()) < DEEP_LIMIT
                    {
                        Some(SolidityVar::Expression(
                            expr,
                            get_combine_degree(a.get_deep(), b.get_deep()),
                        ))
                    } else {
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
                        Some(SolidityVar::Temp(t))
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
                        ))
                    } else {
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
                        Some(SolidityVar::Temp(t))
                    }
                }
                EvalOps::ScalarPow(a, n) => {
                    let a = self.pos_to_scalar_var(a).to_string(true);
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
                    Some(SolidityVar::Temp(t))
                }
                EvalOps::MSM(psl) => {
                    let start: usize = *TEMP_BUF_MAX + self.msm_len.len() * *MSM_BUF_SIZE;

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

                        if i > 0 {
                            self.statements
                                .push(format!("AggregatorLib.ecc_mul_add(buf, {});", start));
                        } else {
                            self.statements
                                .push(format!("AggregatorLib.ecc_mul(buf, {});", start));
                        }

                        if SOLIDITY_DEBUG {
                            let p_value = self.eval_point_pos(p).coordinates().unwrap();
                            let s_value = self.eval_scalar_pos(s);
                            self.statements.push(format!(
                                "require(buf[{}] == {}, \"ops {}.0\");",
                                start + i * 3,
                                field_to_bn(p_value.x()).to_str_radix(10),
                                i
                            ));
                            self.statements.push(format!(
                                "require(buf[{}] == {}, \"ops {}.1\");",
                                start + i * 3 + 1,
                                field_to_bn(p_value.y()).to_str_radix(10),
                                i
                            ));
                            self.statements.push(format!(
                                "require(buf[{}] == {}, \"ops {}.2\");",
                                start + i * 3 + 2,
                                field_to_bn(&s_value).to_str_radix(10),
                                i
                            ));
                        }
                    }

                    None
                }
                _ => None,
            };
            self.exprs.push(expr);
        }
    }
}

pub fn solidity_codegen_with_proof<E: MultiMillerLoop>(
    params: &ParamsVerifier<E>,
    vkey: &VerifyingKey<E::G1Affine>,
    instances: &Vec<E::Scalar>,
    proofs: Vec<u8>,
    tera_context: &mut tera::Context,
    check: bool,
) -> Vec<String> {
    let (w_x, w_g, _) = verify_aggregation_proofs(params, &[vkey], &vec![]);

    let instance_commitments =
        instance_to_instance_commitment(params, &[vkey], vec![&vec![instances.clone()]])[0].clone();

    let targets = vec![w_x.0, w_g.0];

    let c = EvalContext::translate(&targets[..]);

    let mut ctx = SolidityEvalContext::<_, E>::new(
        c,
        instance_commitments,
        ShaRead::<_, _, _, sha2::Sha256>::init(&proofs[..]),
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

    tera_context.insert("msm_w_x_len", &ctx.msm_len[0]);
    tera_context.insert("msm_w_g_len", &ctx.msm_len[1]);

    tera_context.insert("msm_w_x_start", &*TEMP_BUF_MAX);
    tera_context.insert("msm_w_g_start", &(*TEMP_BUF_MAX + *MSM_BUF_SIZE));

    if SOLIDITY_DEBUG {
        tera_context.insert(
            &format!("challenges"),
            &ctx.challenges
                .iter()
                .map(|x| field_to_bn(x).to_str_radix(10))
                .collect::<Vec<_>>(),
        );
    }

    ctx.statements
        .chunks(SOLIDITY_VERIFY_STEP_MAX_SIZE)
        .map(|c| {
            c.iter()
                .map(|x| format!("{}\n", x))
                .collect::<Vec<_>>()
                .concat()
        })
        .collect()
}

pub fn solidity_aux_gen<E: MultiMillerLoop>(
    params: &ParamsVerifier<E>,
    vkey: &VerifyingKey<E::G1Affine>,
    instances: &Vec<E::Scalar>,
    proofs: Vec<u8>,
    aux_file: &Path,
) {
    let div_res = solidity_aux_gen_data(params, vkey, instances, proofs, true);
    let mut fd = std::fs::File::create(&aux_file).unwrap();
    div_res.iter().for_each(|res| res.write(&mut fd).unwrap());
}

pub fn solidity_aux_gen_data<E: MultiMillerLoop>(
    params: &ParamsVerifier<E>,
    vkey: &VerifyingKey<E::G1Affine>,
    instances: &Vec<E::Scalar>,
    proofs: Vec<u8>,
    check: bool,
) -> Vec<E::Scalar> {
    let (w_x, w_g, _) = verify_aggregation_proofs(params, &[vkey], &vec![]);

    let instance_commitments =
        instance_to_instance_commitment(params, &[vkey], vec![&vec![instances.clone()]])[0].clone();

    let targets = vec![w_x.0, w_g.0];

    let c = EvalContext::translate(&targets[..]);

    let mut ctx = SolidityEvalContext::<_, E>::new(
        c,
        instance_commitments,
        ShaRead::<_, _, _, sha2::Sha256>::init(&proofs[..]),
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
