use crate::api::arith::AstPoint;
use crate::api::arith::AstScalar;
use crate::api::transcript::AstTranscript;
use halo2_proofs::arithmetic::CurveAffine;
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::collections::HashMap;
use std::collections::HashSet;
use std::rc::Rc;

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub enum EvalPos {
    Constant(usize),
    Empty,
    Instance(usize, usize),
    Ops(usize),
}

impl EvalPos {
    pub fn map(&self, reverse_order: &Vec<usize>) -> Self {
        match self {
            EvalPos::Ops(a) => EvalPos::Ops(reverse_order[*a]),
            _ => self.clone(),
        }
    }

    pub fn to_ops_index_unsafe(&self) -> usize {
        match self {
            EvalPos::Ops(a) => *a,
            _ => unreachable!(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub enum EvalOps {
    TranscriptReadScalar(usize, EvalPos),
    TranscriptReadPoint(usize, EvalPos),
    TranscriptCommonScalar(usize, EvalPos, EvalPos),
    TranscriptCommonPoint(usize, EvalPos, EvalPos),
    TranscriptSqueeze(usize, EvalPos),

    ScalarAdd(EvalPos, EvalPos),
    ScalarSub(EvalPos, EvalPos),
    ScalarMul(EvalPos, EvalPos, bool),
    ScalarDiv(EvalPos, EvalPos),
    ScalarPow(EvalPos, u32),

    MSM(Vec<(EvalPos, EvalPos)>, EvalPos), // add last MSMSlice for dependence
    MSMSlice((EvalPos, EvalPos), Option<EvalPos>, usize), // usize: msm group

    CheckPoint(String, EvalPos), // for debug purpose
}

impl EvalOps {
    pub fn deps(&self) -> Vec<&EvalPos> {
        match self {
            EvalOps::TranscriptReadScalar(_, a) => vec![a],
            EvalOps::TranscriptReadPoint(_, a) => vec![a],
            EvalOps::TranscriptCommonScalar(_, a, b) => vec![a, b],
            EvalOps::TranscriptCommonPoint(_, a, b) => vec![a, b],
            EvalOps::TranscriptSqueeze(_, a) => vec![a],
            EvalOps::ScalarAdd(a, b) => vec![a, b],
            EvalOps::ScalarSub(a, b) => vec![a, b],
            EvalOps::ScalarMul(a, b, _) => vec![a, b],
            EvalOps::ScalarDiv(a, b) => vec![a, b],
            EvalOps::ScalarPow(a, _) => vec![a],
            EvalOps::MSMSlice((a, b), last, _) => {
                let mut deps = last.as_ref().map(|x| vec![x]).unwrap_or(vec![]);
                deps.push(a);
                deps.push(b);
                deps
            }
            EvalOps::MSM(psl, a) => {
                let mut deps = vec![a];
                for (p, s) in psl {
                    deps.push(p);
                    deps.push(s);
                }
                deps
            }
            EvalOps::CheckPoint(_, a) => vec![a],
        }
    }

    pub fn map(&self, reverse_order: &Vec<usize>) -> Self {
        match self {
            EvalOps::TranscriptReadScalar(i, a) => {
                EvalOps::TranscriptReadScalar(*i, a.map(reverse_order))
            }
            EvalOps::TranscriptReadPoint(i, a) => {
                EvalOps::TranscriptReadPoint(*i, a.map(reverse_order))
            }
            EvalOps::TranscriptCommonScalar(i, a, b) => {
                EvalOps::TranscriptCommonScalar(*i, a.map(reverse_order), b.map(reverse_order))
            }
            EvalOps::TranscriptCommonPoint(i, a, b) => {
                EvalOps::TranscriptCommonPoint(*i, a.map(reverse_order), b.map(reverse_order))
            }
            EvalOps::TranscriptSqueeze(i, a) => {
                EvalOps::TranscriptSqueeze(*i, a.map(reverse_order))
            }
            EvalOps::ScalarAdd(a, b) => {
                EvalOps::ScalarAdd(a.map(reverse_order), b.map(reverse_order))
            }
            EvalOps::ScalarSub(a, b) => {
                EvalOps::ScalarSub(a.map(reverse_order), b.map(reverse_order))
            }
            EvalOps::ScalarMul(a, b, c) => {
                EvalOps::ScalarMul(a.map(reverse_order), b.map(reverse_order), *c)
            }
            EvalOps::ScalarDiv(a, b) => {
                EvalOps::ScalarDiv(a.map(reverse_order), b.map(reverse_order))
            }
            EvalOps::ScalarPow(a, n) => EvalOps::ScalarPow(a.map(reverse_order), *n),
            EvalOps::MSM(psl, last_msm_slice) => EvalOps::MSM(
                {
                    psl.iter()
                        .map(|(p, s)| (p.map(reverse_order), s.map(reverse_order)))
                        .collect()
                },
                last_msm_slice.map(reverse_order),
            ),
            EvalOps::MSMSlice((a, b), last, msm_group) => EvalOps::MSMSlice(
                (a.map(reverse_order), b.map(reverse_order)),
                last.as_ref().map(|x| x.map(reverse_order)),
                *msm_group,
            ),
            EvalOps::CheckPoint(n, a) => EvalOps::CheckPoint(n.clone(), a.map(reverse_order)),
        }
    }
}

#[derive(Clone, Default)]
pub struct EvalContext<C: CurveAffine> {
    pub ops: Vec<EvalOps>,
    pub const_points: Vec<C>,
    pub const_scalars: Vec<C::ScalarExt>,
    pub finals: Vec<usize>,

    transcript_cache: Vec<(Rc<AstTranscript<C>>, EvalPos)>,
    ops_cache: HashMap<EvalOps, usize>,
    deps: HashMap<usize, HashSet<usize>>,
    reverse_deps: HashMap<usize, HashSet<usize>>,
}

impl<C: CurveAffine> EvalContext<C> {
    pub fn translate(ast: &[Rc<AstPoint<C>>]) -> Self {
        let mut c = Self::default();
        c.full_translate_ast_point(ast);
        c
    }

    fn add_dep(&mut self, prev: &EvalPos, post: &EvalPos) {
        if let EvalPos::Ops(prev) = prev {
            if let EvalPos::Ops(post) = post {
                if let Some(set) = self.reverse_deps.get_mut(prev) {
                    set.insert(*post);
                } else {
                    self.reverse_deps.insert(*prev, HashSet::from([*post]));
                }

                if let Some(set) = self.deps.get_mut(post) {
                    set.insert(*prev);
                } else {
                    self.deps.insert(*post, HashSet::from([*prev]));
                }
            }
        }
    }

    fn push_op(&mut self, op: EvalOps) -> EvalPos {
        if let Some(pos) = self.ops_cache.get(&op) {
            EvalPos::Ops((*pos).try_into().unwrap())
        } else {
            self.ops_cache.insert(op.clone(), self.ops.len());
            let pos = EvalPos::Ops(self.ops.len().try_into().unwrap());
            for prev in op.deps() {
                self.add_dep(prev, &pos);
            }
            self.ops.push(op);
            pos
        }
    }

    fn translate_ast_scalar(&mut self, ast: &Rc<AstScalar<C>>) -> EvalPos {
        let ast: &AstScalar<C> = ast.as_ref();
        match ast {
            AstScalar::FromConst(x) => {
                let mut pos = self.const_scalars.len();
                for (i, s) in self.const_scalars.iter().enumerate() {
                    if s == x {
                        pos = i;
                    }
                }
                if pos == self.const_scalars.len() {
                    self.const_scalars.push(*x);
                }
                EvalPos::Constant(pos.try_into().unwrap())
            }
            AstScalar::FromTranscript(t) | AstScalar::FromChallenge(t) => {
                self.translate_ast_transcript(t)
            }
            AstScalar::Add(a, b) => {
                let a = self.translate_ast_scalar(a);
                let b = self.translate_ast_scalar(b);
                self.push_op(EvalOps::ScalarAdd(a, b))
            }
            AstScalar::Sub(a, b) => {
                let a = self.translate_ast_scalar(a);
                let b = self.translate_ast_scalar(b);
                self.push_op(EvalOps::ScalarSub(a, b))
            }
            AstScalar::Mul(a, b, is_cg) => {
                let a = self.translate_ast_scalar(a);
                let b = self.translate_ast_scalar(b);
                self.push_op(EvalOps::ScalarMul(a, b, *is_cg))
            }
            AstScalar::Div(a, b) => {
                let a = self.translate_ast_scalar(a);
                let b = self.translate_ast_scalar(b);
                self.push_op(EvalOps::ScalarDiv(a, b))
            }
            AstScalar::Pow(a, n) => {
                let a = self.translate_ast_scalar(a);
                self.push_op(EvalOps::ScalarPow(a, *n))
            }
            AstScalar::CheckPoint(tag, a) => {
                let a = self.translate_ast_scalar(a);
                self.push_op(EvalOps::CheckPoint(tag.clone(), a.clone()));
                a
            }
        }
    }

    fn translate_ast_transcript(&mut self, ast: &Rc<AstTranscript<C>>) -> EvalPos {
        for (t, pos) in self.transcript_cache.iter() {
            if Rc::ptr_eq(t, ast) {
                return pos.clone();
            }
        }

        let ast_inner: &AstTranscript<C> = ast.as_ref();
        let pos = match ast_inner {
            AstTranscript::CommonScalar(i, t, s) => {
                let t = self.translate_ast_transcript(t);
                let s = self.translate_ast_scalar(s);
                self.push_op(EvalOps::TranscriptCommonScalar(*i, t, s))
            }
            AstTranscript::CommonPoint(i, t, p) => {
                let t = self.translate_ast_transcript(t);
                let p = self.translate_ast_point(p);
                self.push_op(EvalOps::TranscriptCommonPoint(*i, t, p))
            }
            AstTranscript::ReadScalar(i, t) => {
                let t = self.translate_ast_transcript(t);
                self.push_op(EvalOps::TranscriptReadScalar(*i, t))
            }
            AstTranscript::ReadPoint(i, t) => {
                let t = self.translate_ast_transcript(t);
                self.push_op(EvalOps::TranscriptReadPoint(*i, t))
            }
            AstTranscript::SqueezeChallenge(i, t) => {
                let t = self.translate_ast_transcript(t);
                self.push_op(EvalOps::TranscriptSqueeze(*i, t))
            }
            AstTranscript::Init(_) => EvalPos::Empty,
        };

        self.transcript_cache.push((ast.clone(), pos.clone()));
        pos
    }

    fn translate_ast_point(&mut self, ast: &Rc<AstPoint<C>>) -> EvalPos {
        let ast: &AstPoint<C> = ast.as_ref();
        match ast {
            AstPoint::FromConst(c) => {
                let mut pos = self.const_points.len();
                for (i, p) in self.const_points.iter().enumerate() {
                    if p == c {
                        pos = i;
                    }
                }
                if pos == self.const_points.len() {
                    self.const_points.push(*c);
                }
                EvalPos::Constant(pos.try_into().unwrap())
            }
            AstPoint::FromTranscript(t) => self.translate_ast_transcript(t),
            AstPoint::FromInstance(i, j) => EvalPos::Instance(*i, *j),
            AstPoint::MultiExp(psl, group) => {
                let mut sl = vec![];
                let mut pl = vec![];
                let mut last = None;
                for (p, s) in psl {
                    let s = self.translate_ast_scalar(s);
                    let p = self.translate_ast_point(p);
                    sl.push(s.clone());
                    pl.push(p.clone());
                    let v = self.push_op(EvalOps::MSMSlice((p, s), last, *group));
                    last = Some(v);
                }
                self.push_op(EvalOps::MSM(
                    pl.into_iter().zip(sl.into_iter()).collect(),
                    last.unwrap(),
                ))
            }
            AstPoint::CheckPoint(tag, a) => {
                let a = self.translate_ast_point(a);
                self.push_op(EvalOps::CheckPoint(tag.clone(), a.clone()));
                a
            }
        }
    }

    // Translate AST into small ops & Dedup & Topological sorting
    fn full_translate_ast_point(&mut self, asts: &[Rc<AstPoint<C>>]) {
        // Translate & Dedup
        for ast in asts {
            let pos = self.translate_ast_point(ast);
            match pos {
                EvalPos::Ops(pos) => self.finals.push(pos),
                _ => unreachable!(),
            }
        }

        // Topological sorting
        let mut dep_counts = (0..self.ops.len())
            .into_iter()
            .map(|i| self.deps.get(&(i as usize)).map_or(0, |set| set.len()))
            .collect::<Vec<_>>();

        let mut nodes = BTreeMap::<usize, BTreeSet<usize>>::new();
        for i in 0..self.ops.len() {
            nodes.insert(i, BTreeSet::new());
        }
        for (i, dep_count) in dep_counts.iter().enumerate() {
            nodes
                .get_mut(dep_count)
                .unwrap()
                .insert(i.try_into().unwrap());
        }

        let mut order = vec![];

        for _ in 0..self.ops.len() {
            let node = nodes.get_mut(&0usize).unwrap().pop_first().unwrap();
            assert_eq!(dep_counts[node as usize], 0);
            order.push(node);
            if let Some(deps) = self.reverse_deps.get(&node) {
                for dep in deps {
                    let count = dep_counts[(*dep) as usize];
                    assert!(count > 0);
                    nodes.get_mut(&count).unwrap().remove(dep);

                    dep_counts[(*dep) as usize] -= 1;
                    let count = count - 1;
                    nodes.get_mut(&count).unwrap().insert(*dep);
                }
            }
        }

        // Reconstruct ops queue with new order
        let mut reverse_order = vec![0; order.len()];
        for (i, o) in order.iter().enumerate() {
            reverse_order[*o] = i;
        }

        let mut ops = vec![];
        for o in order {
            ops.push(self.ops[o].map(&reverse_order));
        }

        self.ops = ops;
        self.ops_cache.clear();
        self.deps.clear();
        self.reverse_deps.clear();
        self.transcript_cache.clear();

        for f in self.finals.iter_mut() {
            *f = reverse_order[*f];
        }
    }
}
