#[cfg(test)]
pub mod tests;

use std::borrow::Borrow;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::rc::Rc;

use id_arena::Arena;
use indexmap::{IndexMap, IndexSet};
use rue_compiler::{Compiler, FileTree, SyntaxItemKind, normalize_path};
use rue_diagnostic::{DiagnosticSeverity, Source, SourceKind, SrcLoc};
use rue_hir::{
    BinaryOp, BindingSymbol, ConstantSymbol, Database, DependencyGraph, Environment, ExprStatement,
    FunctionCall, FunctionKind, FunctionSymbol, Hir, HirId, IfStatement, PathError, Statement,
    Symbol, SymbolId, UnaryOp,
};
use rue_lir::{ClvmOp, Lir, LirId, bigint_atom};
use rue_options::find_project;

use clvm_to_arm_generate::clvmr_node::{ClvmrAllocator, ClvmrWrapper};
use clvm_to_arm_generate::code::{ElfObject, Program, TARGET_ADDR};
use clvm_to_arm_generate::sexp::{CreateSExp, HasSrcloc, SExp, SExpValue, Srcloc, Until};

use chialisp::classic::clvm_tools::binutils::assemble;
use chialisp::classic::clvm_tools::sha256tree::sha256tree;
use chialisp::compiler::sexp::decode_string;
use chialisp::util::Number;

pub struct Args {
    pub filename: String,
    pub env: String,
    pub output: String,
}

#[derive(Clone)]
struct RueSrcLoc {
    raw: Rc<SrcLoc>,
}

impl RueSrcLoc {
    pub fn new(sl: SrcLoc) -> Self {
        RueSrcLoc { raw: Rc::new(sl) }
    }
}

#[derive(Clone)]
enum RueSExpKind {
    Atom,
    Cons(Rc<RueSExp>, Rc<RueSExp>),
}

#[derive(Clone)]
struct RueSExp {
    kind: RueSExpKind,
    clvm: ClvmrWrapper,
    loc: RueSrcLoc,
}

impl RueSExp {
    fn from_node(allocator: ClvmrAllocator, loc: &RueSrcLoc, node: clvmr::NodePtr) -> Self {
        let alloc_copy = allocator.clone();
        if let Some((a, b)) = allocator.with_allocator(|allocator| match allocator.sexp(node) {
            clvmr::allocator::SExp::Pair(a, b) => Some((a, b)),
            _ => None,
        }) {
            let sexp_a = RueSExp::from_node(alloc_copy.clone(), loc, a);
            let sexp_b = RueSExp::from_node(alloc_copy.clone(), loc, b);
            RueSExp {
                kind: RueSExpKind::Cons(Rc::new(sexp_a), Rc::new(sexp_b)),
                clvm: ClvmrWrapper {
                    a: alloc_copy,
                    n: node,
                },
                loc: loc.clone(),
            }
        } else {
            RueSExp {
                kind: RueSExpKind::Atom,
                clvm: ClvmrWrapper {
                    a: alloc_copy,
                    n: node,
                },
                loc: loc.clone(),
            }
        }
    }
}

impl SExp for RueSExp {
    fn to_number(&self) -> Option<Number> {
        todo!();
    }
    fn proper_list(&self) -> Option<Vec<Self>> {
        let mut result = Vec::new();
        let mut examine = self.clone();
        loop {
            match examine.explode() {
                SExpValue::Nil => {
                    return Some(result);
                }
                SExpValue::Atom(_) => {
                    return None;
                }
                SExpValue::Cons(a, b) => {
                    result.push(a.clone());
                    examine = b.clone();
                }
            }
        }
    }
    fn sha256tree(&self) -> Vec<u8> {
        self.clvm
            .a
            .with_allocator_mut(|a| sha256tree(a, self.clvm.n).data().to_vec())
    }
    fn explode(&self) -> SExpValue<Self> {
        if let RueSExpKind::Cons(a, b) = &self.kind {
            let a_borrow: &RueSExp = a.borrow();
            let b_borrow: &RueSExp = b.borrow();
            return SExpValue::Cons(a_borrow.clone(), b_borrow.clone());
        }
        self.clvm.a.with_allocator(|allocator| {
            let buf = allocator.atom(self.clvm.n);
            if buf.is_empty() {
                SExpValue::Nil
            } else {
                SExpValue::Atom(buf.to_vec())
            }
        })
    }

    fn nilp(&self) -> bool {
        matches!(self.atom_bytes::<Self>(), Some(bytes) if bytes.is_empty())
    }

    fn atom_bytes<T: SExp>(&self) -> Option<Vec<u8>> {
        match self.explode() {
            SExpValue::Cons(_, _) => None,
            SExpValue::Nil => Some(Vec::new()),
            SExpValue::Atom(bytes) => Some(bytes),
        }
    }
}

impl HasSrcloc for RueSExp {
    type Srcloc = RueSrcLoc;

    fn loc(&self) -> Self::Srcloc {
        self.loc.clone()
    }
}

impl Srcloc for RueSrcLoc {
    fn start(filename: &str) -> Self {
        RueSrcLoc {
            raw: Rc::new(SrcLoc::new(
                Source::new(
                    "".to_string().into(),
                    SourceKind::File(filename.to_string()),
                ),
                std::ops::Range { start: 0, end: 0 },
            )),
        }
    }
    fn filename(&self) -> String {
        self.raw.source.kind.display(Path::new("."))
    }
    fn line(&self) -> usize {
        self.raw.start().line + 1
    }
    fn col(&self) -> usize {
        self.raw.start().col + 1
    }
    fn overlap(&self, other: &Self) -> bool {
        if other.raw.source.kind != self.raw.source.kind {
            return false;
        }
        let other_start = other.raw.span.start;
        let other_end = other.raw.span.end;
        let contains = |s, e, mid| mid >= s && mid <= e;
        contains(other_start, other_end, self.raw.span.start)
            || contains(other_start, other_end, self.raw.span.end)
    }
    fn until(&self) -> Option<Until> {
        if self.raw.span.end != self.raw.span.start {
            let cl = self.raw.end();
            return Some(Until {
                line: cl.line as u32 + 1,
                col: cl.col as u32 + 1,
            });
        }

        None
    }
}

impl std::fmt::Display for RueSrcLoc {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        let lc = self.raw.start();
        let end = self.raw.end();
        if end.line != lc.line || end.col != lc.col {
            write!(
                formatter,
                "{}({}):{}-{}({}):{}",
                self.raw.source.kind.display(Path::new(".")),
                lc.line + 1,
                lc.col + 1,
                self.raw.source.kind.display(Path::new(".")),
                end.line + 1,
                end.col + 1
            )
        } else {
            write!(
                formatter,
                "{}({}):{}",
                self.raw.source.kind.display(Path::new(".")),
                lc.line + 1,
                lc.col + 1,
            )
        }
    }
}

impl std::fmt::Display for RueSExp {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        self.clvm.fmt(formatter)
    }
}

#[derive(Debug, Clone)]
enum SymbolGroup {
    Sequential(Vec<SymbolId>),
    Tree(Environment),
}

impl SymbolGroup {
    fn is_empty(&self) -> bool {
        match self {
            Self::Sequential(symbols) => symbols.is_empty(),
            Self::Tree(Environment::Nil) => true,
            Self::Tree(_) => false,
        }
    }
}

struct DebugLowerer<'d, 'a, 'g> {
    db: &'d mut Database,
    arena: &'a mut Arena<Lir>,
    graph: &'g DependencyGraph,
    lir_locations: &'a mut HashMap<LirId, RueSrcLoc>,
    function_body_lirs: &'a mut HashMap<SymbolId, LirId>,
    function_argument_trees: &'a mut HashMap<SymbolId, String>,
    inline_symbols: Vec<HashMap<SymbolId, HirId>>,
    options: rue_options::CompilerOptions,
    main: SymbolId,
    base_path: PathBuf,
    symbol_locs: &'a HashMap<SymbolId, RueSrcLoc>,
    current_loc: RueSrcLoc,
}

impl<'d, 'a, 'g> DebugLowerer<'d, 'a, 'g> {
    #[allow(clippy::too_many_arguments)]
    fn new(
        db: &'d mut Database,
        arena: &'a mut Arena<Lir>,
        graph: &'g DependencyGraph,
        lir_locations: &'a mut HashMap<LirId, RueSrcLoc>,
        function_body_lirs: &'a mut HashMap<SymbolId, LirId>,
        function_argument_trees: &'a mut HashMap<SymbolId, String>,
        options: rue_options::CompilerOptions,
        main: SymbolId,
        base_path: PathBuf,
        symbol_locs: &'a HashMap<SymbolId, RueSrcLoc>,
        fallback_loc: RueSrcLoc,
    ) -> Self {
        Self {
            db,
            arena,
            graph,
            lir_locations,
            function_body_lirs,
            function_argument_trees,
            inline_symbols: Vec::new(),
            options,
            main,
            base_path,
            symbol_locs,
            current_loc: fallback_loc,
        }
    }

    fn alloc(&mut self, lir: Lir) -> LirId {
        self.arena.alloc(lir)
    }

    fn alloc_here(&mut self, lir: Lir) -> LirId {
        let id = self.alloc(lir);
        self.lir_locations.insert(id, self.current_loc.clone());
        id
    }

    fn with_loc<R>(&mut self, loc: RueSrcLoc, f: impl FnOnce(&mut Self) -> R) -> R {
        let previous = self.current_loc.clone();
        self.current_loc = loc;
        let result = f(self);
        self.current_loc = previous;
        result
    }

    fn lower_symbol_value(&mut self, env: &Environment, symbol: SymbolId) -> LirId {
        for inline_symbols in self.inline_symbols.iter().rev() {
            if let Some(hir) = inline_symbols.get(&symbol) {
                return self.lower_hir(env, *hir);
            }
        }

        let loc = self
            .symbol_locs
            .get(&symbol)
            .cloned()
            .unwrap_or_else(|| self.current_loc.clone());
        self.with_loc(loc.clone(), |lowerer| {
            let sym = lowerer.db.symbol(symbol);
            match sym.clone() {
                Symbol::Unresolved
                | Symbol::Module(_)
                | Symbol::Parameter(_)
                | Symbol::Builtin(_) => {
                    unreachable!()
                }
                Symbol::Function(function) => lowerer.lower_function(env, symbol, function),
                Symbol::Constant(constant) => lowerer.lower_constant(env, constant),
                Symbol::Binding(binding) => lowerer.lower_binding(env, binding),
            }
        })
    }

    fn function_groups(
        &mut self,
        symbol: SymbolId,
        function: &FunctionSymbol,
    ) -> (Vec<SymbolGroup>, SymbolGroup) {
        let captures: Vec<SymbolId> = self
            .graph
            .dependencies(symbol, true)
            .into_iter()
            .filter(|&symbol| !self.should_inline(symbol))
            .collect();

        let capture_groups = self.group_symbols(
            captures.into_iter().collect(),
            symbol != self.main,
            !self.graph.is_closure(symbol),
        );

        let param_group = self.create_group(
            function.parameters.values().copied().collect(),
            function.kind == FunctionKind::BinaryTree
                && !self.graph.is_closure(symbol)
                && symbol != self.main,
        );

        (capture_groups, param_group)
    }

    fn lower_function(
        &mut self,
        parent_env: &Environment,
        symbol: SymbolId,
        function: FunctionSymbol,
    ) -> LirId {
        let (capture_groups, param_group) = self.function_groups(symbol, &function);

        let mut function_env = Self::apply_group(
            Environment::Nil,
            &param_group,
            function.nil_terminated && matches!(param_group, SymbolGroup::Sequential(_)),
        );

        for group in &capture_groups {
            function_env = Self::apply_group(function_env, group, true);
        }
        self.function_argument_trees.insert(
            symbol,
            argument_tree_expression(&function_env, &function.parameters, symbol == self.main)
        );

        let mut expr = self.lower_hir(&function_env, function.body);

        if symbol == self.main {
            let mut map = HashMap::new();

            if self
                .graph
                .dependencies(symbol, true)
                .iter()
                .any(|dependency| *dependency == symbol)
            {
                let quoted = self.alloc_here(Lir::Quote(expr));
                map.insert(symbol, quoted);
                let reference = self.lower_symbol_reference(&function_env, symbol);
                let entire_env = self.alloc_here(Lir::Path(1));
                expr = self.alloc_here(Lir::Run(reference, entire_env));
            }

            for (i, group) in capture_groups.iter().enumerate().rev() {
                expr = self.alloc_here(Lir::Quote(expr));

                let mut bind_env = parent_env.clone();

                for existing_group in capture_groups.iter().take(i) {
                    bind_env = Self::apply_group(bind_env, existing_group, true);
                }

                let rest = if param_group.is_empty() {
                    self.alloc_here(Lir::Atom(vec![]))
                } else {
                    self.alloc_here(Lir::Path(1))
                };

                let group_env =
                    self.lower_group_environment(&bind_env, group, rest, false, Some(&map), true);

                expr = self.alloc_here(Lir::Run(expr, group_env));
            }

            self.function_body_lirs.insert(symbol, expr);
            expr
        } else {
            self.function_body_lirs.insert(symbol, expr);
            self.alloc_here(Lir::Quote(expr))
        }
    }

    fn lower_constant(&mut self, env: &Environment, constant: ConstantSymbol) -> LirId {
        self.lower_hir(env, constant.value.hir)
    }

    fn lower_binding(&mut self, env: &Environment, binding: BindingSymbol) -> LirId {
        self.lower_hir(env, binding.value.hir)
    }

    fn lower_hir(&mut self, env: &Environment, hir: HirId) -> LirId {
        match self.db.hir(hir).clone() {
            Hir::Unresolved => unreachable!(),
            Hir::Nil => self.alloc_here(Lir::Atom(vec![])),
            Hir::String(value) => self.alloc_here(Lir::Atom(value.as_bytes().to_vec())),
            Hir::Int(value) => self.alloc_here(Lir::Atom(bigint_atom(value.clone()))),
            Hir::Bool(value) => self.alloc_here(Lir::Atom(if value { vec![1] } else { vec![] })),
            Hir::Bytes(atom) => self.alloc_here(Lir::Atom(atom)),
            Hir::Pair(first, rest) => {
                let first = self.lower_hir(env, first);
                let rest = self.lower_hir(env, rest);
                self.alloc_here(Lir::Cons(first, rest))
            }
            Hir::Reference(symbol) => self.lower_symbol(env, symbol, false),
            Hir::Block(block) => self.lower_block(env, block.statements, block.body),
            Hir::Lambda(lambda) => self.lower_symbol(env, lambda, true),
            Hir::If(condition, then, else_, inline) => {
                let condition = self.lower_hir(env, condition);
                let then = self.lower_hir(env, then);
                let else_ = self.lower_hir(env, else_);
                self.alloc_here(Lir::If(condition, then, else_, inline))
            }
            Hir::FunctionCall(call) => self.lower_function_call(env, call),
            Hir::Unary(op, hir) => {
                let lir = self.lower_hir(env, hir);
                match op {
                    UnaryOp::Listp { can_be_truthy } => {
                        self.alloc_here(Lir::Listp(lir, can_be_truthy))
                    }
                    UnaryOp::First => self.alloc_here(Lir::First(lir)),
                    UnaryOp::Rest => self.alloc_here(Lir::Rest(lir)),
                    UnaryOp::Strlen => self.alloc_here(Lir::Strlen(lir)),
                    UnaryOp::Not => self.alloc_here(Lir::Not(lir)),
                    UnaryOp::Neg => {
                        let zero = self.alloc_here(Lir::Atom(vec![]));
                        self.alloc_here(Lir::Sub(vec![zero, lir]))
                    }
                    UnaryOp::BitwiseNot => self.alloc_here(Lir::Lognot(lir)),
                    UnaryOp::G1Negate => self.alloc_here(Lir::G1Negate(lir)),
                    UnaryOp::G2Negate => self.alloc_here(Lir::G2Negate(lir)),
                    UnaryOp::Sha256 => self.alloc_here(Lir::Sha256(vec![lir])),
                    UnaryOp::Sha256Inline => self.alloc_here(Lir::Sha256Inline(vec![lir])),
                    UnaryOp::Keccak256 => self.alloc_here(Lir::Keccak256(vec![lir])),
                    UnaryOp::Keccak256Inline => self.alloc_here(Lir::Keccak256Inline(vec![lir])),
                    UnaryOp::PubkeyForExp => self.alloc_here(Lir::PubkeyForExp(lir)),
                }
            }
            Hir::Binary(op, left, right) => {
                let left = self.lower_hir(env, left);
                let right = self.lower_hir(env, right);
                self.lower_binary(op, left, right)
            }
            Hir::CoinId(parent, puzzle, amount) => {
                let parent = self.lower_hir(env, parent);
                let puzzle = self.lower_hir(env, puzzle);
                let amount = self.lower_hir(env, amount);
                self.alloc_here(Lir::CoinId(parent, puzzle, amount))
            }
            Hir::Substr(hir, start, end) => {
                let hir = self.lower_hir(env, hir);
                let start = self.lower_hir(env, start);
                let end = end.map(|end| self.lower_hir(env, end));
                self.alloc_here(Lir::Substr(hir, start, end))
            }
            Hir::G1Map(data, dst) => {
                let data = self.lower_hir(env, data);
                let dst = dst.map(|dst| self.lower_hir(env, dst));
                self.alloc_here(Lir::G1Map(data, dst))
            }
            Hir::G2Map(data, dst) => {
                let data = self.lower_hir(env, data);
                let dst = dst.map(|dst| self.lower_hir(env, dst));
                self.alloc_here(Lir::G2Map(data, dst))
            }
            Hir::Modpow(base, exponent, modulus) => {
                let base = self.lower_hir(env, base);
                let exponent = self.lower_hir(env, exponent);
                let modulus = self.lower_hir(env, modulus);
                self.alloc_here(Lir::Modpow(base, exponent, modulus))
            }
            Hir::BlsPairingIdentity(args) => {
                let args = args
                    .into_iter()
                    .map(|arg| self.lower_hir(env, arg))
                    .collect();
                self.alloc_here(Lir::BlsPairingIdentity(args))
            }
            Hir::BlsVerify(sig, args) => {
                let sig = self.lower_hir(env, sig);
                let args = args
                    .into_iter()
                    .map(|arg| self.lower_hir(env, arg))
                    .collect();
                self.alloc_here(Lir::BlsVerify(sig, args))
            }
            Hir::Secp256K1Verify(sig, pk, msg) => {
                let sig = self.lower_hir(env, sig);
                let pk = self.lower_hir(env, pk);
                let msg = self.lower_hir(env, msg);
                self.alloc_here(Lir::K1Verify(sig, pk, msg))
            }
            Hir::Secp256R1Verify(sig, pk, msg) => {
                let sig = self.lower_hir(env, sig);
                let pk = self.lower_hir(env, pk);
                let msg = self.lower_hir(env, msg);
                self.alloc_here(Lir::R1Verify(sig, pk, msg))
            }
            Hir::InfinityG1 => self.alloc_here(Lir::G1Add(vec![])),
            Hir::InfinityG2 => self.alloc_here(Lir::G2Add(vec![])),
            Hir::ClvmOp(op, args) => {
                let args = self.lower_hir(env, args);
                self.alloc_here(Lir::Op(op, args))
            }
        }
    }

    fn lower_binary(&mut self, op: BinaryOp, left: LirId, right: LirId) -> LirId {
        match op {
            BinaryOp::Add => self.alloc_here(Lir::Add(vec![left, right])),
            BinaryOp::Sub => self.alloc_here(Lir::Sub(vec![left, right])),
            BinaryOp::Mul => self.alloc_here(Lir::Mul(vec![left, right])),
            BinaryOp::Div => self.alloc_here(Lir::Div(left, right)),
            BinaryOp::Mod => self.alloc_here(Lir::Mod(left, right)),
            BinaryOp::Divmod => self.alloc_here(Lir::Divmod(left, right)),
            BinaryOp::Concat => self.alloc_here(Lir::Concat(vec![left, right])),
            BinaryOp::G1Add => self.alloc_here(Lir::G1Add(vec![left, right])),
            BinaryOp::G1Subtract => self.alloc_here(Lir::G1Subtract(vec![left, right])),
            BinaryOp::G1Multiply => self.alloc_here(Lir::G1Multiply(left, right)),
            BinaryOp::G2Add => self.alloc_here(Lir::G2Add(vec![left, right])),
            BinaryOp::G2Subtract => self.alloc_here(Lir::G2Subtract(vec![left, right])),
            BinaryOp::G2Multiply => self.alloc_here(Lir::G2Multiply(left, right)),
            BinaryOp::BitwiseAnd => self.alloc_here(Lir::Logand(vec![left, right])),
            BinaryOp::BitwiseOr => self.alloc_here(Lir::Logior(vec![left, right])),
            BinaryOp::BitwiseXor => self.alloc_here(Lir::Logxor(vec![left, right])),
            BinaryOp::RightLogicalShift => {
                let zero = self.alloc_here(Lir::Atom(vec![]));
                let neg = self.alloc_here(Lir::Sub(vec![zero, right]));
                self.alloc_here(Lir::Lsh(left, neg))
            }
            BinaryOp::RightArithmeticShift => {
                let zero = self.alloc_here(Lir::Atom(vec![]));
                let neg = self.alloc_here(Lir::Sub(vec![zero, right]));
                self.alloc_here(Lir::Ash(left, neg))
            }
            BinaryOp::LeftArithmeticShift => self.alloc_here(Lir::Ash(left, right)),
            BinaryOp::Gt => self.alloc_here(Lir::Gt(left, right)),
            BinaryOp::Lt => self.alloc_here(Lir::Gt(right, left)),
            BinaryOp::Gte => {
                let gt = self.alloc_here(Lir::Gt(left, right));
                let eq = self.alloc_here(Lir::Eq(left, right));
                self.alloc_here(Lir::Any(vec![gt, eq]))
            }
            BinaryOp::Lte => {
                let lt = self.alloc_here(Lir::Gt(right, left));
                let eq = self.alloc_here(Lir::Eq(left, right));
                self.alloc_here(Lir::Any(vec![lt, eq]))
            }
            BinaryOp::GtBytes => self.alloc_here(Lir::GtBytes(left, right)),
            BinaryOp::LtBytes => self.alloc_here(Lir::GtBytes(right, left)),
            BinaryOp::GteBytes => {
                let gt = self.alloc_here(Lir::GtBytes(left, right));
                let eq = self.alloc_here(Lir::Eq(left, right));
                self.alloc_here(Lir::Any(vec![gt, eq]))
            }
            BinaryOp::LteBytes => {
                let lt = self.alloc_here(Lir::GtBytes(right, left));
                let eq = self.alloc_here(Lir::Eq(left, right));
                self.alloc_here(Lir::Any(vec![lt, eq]))
            }
            BinaryOp::Eq => self.alloc_here(Lir::Eq(left, right)),
            BinaryOp::Ne => {
                let eq = self.alloc_here(Lir::Eq(left, right));
                self.alloc_here(Lir::Not(eq))
            }
            BinaryOp::And => {
                let true_atom = self.alloc_here(Lir::Atom(vec![1]));
                let false_atom = self.alloc_here(Lir::Atom(vec![]));
                let right = self.alloc_here(Lir::If(right, true_atom, false_atom, false));
                self.alloc_here(Lir::If(left, right, false_atom, false))
            }
            BinaryOp::Or => {
                let true_atom = self.alloc_here(Lir::Atom(vec![1]));
                let false_atom = self.alloc_here(Lir::Atom(vec![]));
                let right = self.alloc_here(Lir::If(right, true_atom, false_atom, false));
                self.alloc_here(Lir::If(left, true_atom, right, false))
            }
            BinaryOp::All => self.alloc_here(Lir::All(vec![left, right])),
            BinaryOp::Any => self.alloc_here(Lir::Any(vec![left, right])),
        }
    }

    fn lower_function_call(&mut self, env: &Environment, call: FunctionCall) -> LirId {
        if let Some((symbol, function)) = match self.db.hir(call.function).clone() {
            Hir::Reference(symbol) => match self.db.symbol(symbol).clone() {
                Symbol::Function(function) => Some((symbol, function)),
                _ => None,
            },
            _ => None,
        } {
            let mut args = HashMap::new();

            if function.nil_terminated {
                for (i, arg) in call.args.into_iter().enumerate() {
                    args.insert(function.parameters[i], arg);
                }
            } else {
                let mut arg_iter = call.args.into_iter().enumerate();

                for (i, arg) in (&mut arg_iter).take(function.parameters.len() - 1) {
                    args.insert(function.parameters[i], arg);
                }

                let mut last_arg = self.db.alloc_hir(Hir::Nil);

                for (i, (_, arg)) in arg_iter.rev().enumerate() {
                    if i == 0 && !call.nil_terminated {
                        last_arg = arg;
                    } else {
                        last_arg = self.db.alloc_hir(Hir::Pair(arg, last_arg));
                    }
                }

                if let Some(last_param) = function.parameters.last() {
                    args.insert(*last_param.1, last_arg);
                }
            }

            if self.should_inline(symbol) {
                self.inline_symbols.push(args);
                let result = self.lower_hir(env, function.body);
                self.inline_symbols.pop().unwrap();
                return result;
            }

            let (capture_groups, param_group) = self.function_groups(symbol, &function);
            let function_lir = self.lower_symbol_reference(env, symbol);
            let rest = self.alloc_here(Lir::Atom(vec![]));

            let mut lir_args = HashMap::new();
            for (symbol, hir) in &args {
                lir_args.insert(*symbol, self.lower_hir(env, *hir));
            }

            let mut arg_env = self.lower_group_environment(
                env,
                &param_group,
                rest,
                false,
                Some(&lir_args),
                function.nil_terminated && matches!(param_group, SymbolGroup::Sequential(_)),
            );

            for group in &capture_groups {
                arg_env = self.lower_group_environment(env, group, arg_env, true, None, true);
            }

            return self.alloc_here(Lir::Run(function_lir, arg_env));
        }

        let function = self.lower_hir(env, call.function);
        let mut args = Vec::new();

        for arg in call.args {
            args.push(self.lower_hir(env, arg));
        }

        let mut env = self.alloc_here(Lir::Atom(Vec::new()));

        for (i, &arg) in args.iter().rev().enumerate() {
            if i == 0 && !call.nil_terminated {
                env = arg;
            } else {
                env = self.alloc_here(Lir::Cons(arg, env));
            }
        }

        self.alloc_here(Lir::Run(function, env))
    }

    fn lower_symbol_reference(&mut self, env: &Environment, symbol: SymbolId) -> LirId {
        for inline_symbols in self.inline_symbols.iter().rev() {
            if let Some(hir) = inline_symbols.get(&symbol) {
                return self.lower_hir(env, *hir);
            }
        }

        self.lower_path(env, symbol)
    }

    fn lower_symbol(&mut self, env: &Environment, symbol: SymbolId, is_lambda: bool) -> LirId {
        let mut reference = if self.should_inline(symbol) || is_lambda {
            self.lower_symbol_value(env, symbol)
        } else {
            self.lower_symbol_reference(env, symbol)
        };

        if let Symbol::Function(function) = self.db.symbol(symbol).clone() {
            let captures: Vec<SymbolId> = self
                .graph
                .dependencies(symbol, true)
                .into_iter()
                .filter(|&symbol| !self.should_inline(symbol))
                .collect();

            let mut refs = Vec::new();
            for capture in captures {
                refs.push(self.lower_symbol_reference(env, capture));
            }

            reference = self.alloc_here(Lir::Closure(
                reference,
                refs,
                !function.parameters.is_empty(),
            ));
        }

        reference
    }

    fn lower_path(&mut self, env: &Environment, symbol: SymbolId) -> LirId {
        self.alloc_here(Lir::Path(env.path(symbol).unwrap_or_else(
            |error| match error {
                PathError::SymbolNotFound => panic!(
                    "clvm path in environment not found for symbol {}",
                    self.db.debug_symbol(symbol)
                ),
                PathError::PathTooLarge => panic!(
                    "calculated clvm path too large for symbol {}",
                    self.db.debug_symbol(symbol)
                ),
            },
        )))
    }

    fn lower_block(
        &mut self,
        env: &Environment,
        mut stmts: Vec<Statement>,
        body: Option<HirId>,
    ) -> LirId {
        if !self.options.debug_symbols {
            stmts.retain(|stmt| !matches!(stmt, Statement::Debug(..)));
        }

        let Some(stmt) = stmts.first().cloned() else {
            return if let Some(body) = body {
                self.lower_hir(env, body)
            } else {
                self.alloc_here(Lir::Atom(vec![]))
            };
        };

        match stmt {
            Statement::Let(_) => self.lower_let_stmts(env, stmts, body),
            Statement::Return(hir) => self.lower_block(env, vec![], Some(hir)),
            Statement::Assert(condition, srcloc) => {
                self.lower_assert(env, stmts, condition, srcloc, body)
            }
            Statement::Expr(stmt) => self.lower_expr_stmts(env, stmt, stmts, body),
            Statement::Raise(hir, srcloc) => self.lower_raise(env, hir, srcloc),
            Statement::If(stmt) => self.lower_if(env, stmts, stmt, body),
            Statement::Debug(hir, srcloc) => self.lower_debug(env, stmts, hir, srcloc, body),
        }
    }

    fn lower_let_stmts(
        &mut self,
        env: &Environment,
        mut stmts: Vec<Statement>,
        body: Option<HirId>,
    ) -> LirId {
        let mut symbols = IndexSet::new();

        while let Some(Statement::Let(symbol)) = stmts.first() {
            symbols.insert(*symbol);
            stmts.remove(0);
        }

        let binding_groups = self.group_symbols(symbols, false, true);
        let mut body_env = env.clone();

        for group in &binding_groups {
            body_env = Self::apply_group(body_env, group, true);
        }

        let mut expr = self.lower_block(&body_env, stmts, body);

        for (i, group) in binding_groups.iter().enumerate().rev() {
            expr = self.alloc_here(Lir::Quote(expr));
            let mut bind_env = env.clone();

            for group in binding_groups.iter().take(i) {
                bind_env = Self::apply_group(bind_env, group, true);
            }

            let rest = self.alloc_here(Lir::Path(1));
            let group_env = self.lower_group_environment(&bind_env, group, rest, false, None, true);
            expr = self.alloc_here(Lir::Run(expr, group_env));
        }

        expr
    }

    fn lower_group_environment(
        &mut self,
        env: &Environment,
        group: &SymbolGroup,
        rest: LirId,
        by_reference: bool,
        map: Option<&HashMap<SymbolId, LirId>>,
        include_rest: bool,
    ) -> LirId {
        match group {
            SymbolGroup::Sequential(symbols) => {
                let mut result = rest;

                for (i, &symbol) in symbols.iter().rev().enumerate() {
                    let value = if let Some(lir) = map.and_then(|map| map.get(&symbol)) {
                        *lir
                    } else if by_reference {
                        self.lower_symbol_reference(env, symbol)
                    } else {
                        self.lower_symbol_value(env, symbol)
                    };
                    if !include_rest && i == 0 {
                        result = value;
                    } else {
                        result = self.alloc_here(Lir::Cons(value, result));
                    }
                }

                result
            }
            SymbolGroup::Tree(tree) => {
                let tree = self.lower_tree(env, tree, by_reference, map);
                if include_rest {
                    self.alloc_here(Lir::Cons(tree, rest))
                } else {
                    tree
                }
            }
        }
    }

    fn lower_tree(
        &mut self,
        env: &Environment,
        tree: &Environment,
        by_reference: bool,
        map: Option<&HashMap<SymbolId, LirId>>,
    ) -> LirId {
        match tree {
            Environment::Nil => self.alloc_here(Lir::Atom(vec![])),
            Environment::Leaf(symbol) => {
                if let Some(lir) = map.and_then(|map| map.get(symbol)) {
                    *lir
                } else if by_reference {
                    self.lower_symbol_reference(env, *symbol)
                } else {
                    self.lower_symbol_value(env, *symbol)
                }
            }
            Environment::Pair(first, rest) => {
                let first = self.lower_tree(env, first, by_reference, map);
                let rest = self.lower_tree(env, rest, by_reference, map);
                self.alloc_here(Lir::Cons(first, rest))
            }
        }
    }

    fn lower_assert(
        &mut self,
        env: &Environment,
        mut stmts: Vec<Statement>,
        condition: HirId,
        srcloc: SrcLoc,
        body: Option<HirId>,
    ) -> LirId {
        stmts.remove(0);
        let loc = rue_srcloc_to_chialisp(&srcloc);
        self.with_loc(loc, |lowerer| {
            let raise = if lowerer.options.debug_symbols {
                let error = lowerer.alloc_here(Lir::Atom(
                    format!("assertion failed at {}", srcloc.display(&lowerer.base_path))
                        .into_bytes(),
                ));
                vec![error]
            } else {
                vec![]
            };

            let condition = lowerer.lower_hir(env, condition);
            let then_branch = lowerer.lower_block(env, stmts, body);
            let else_branch = lowerer.alloc_here(Lir::Raise(raise));
            lowerer.alloc_here(Lir::If(condition, then_branch, else_branch, false))
        })
    }

    fn lower_raise(&mut self, env: &Environment, hir: Option<HirId>, srcloc: SrcLoc) -> LirId {
        let loc = rue_srcloc_to_chialisp(&srcloc);
        self.with_loc(loc, |lowerer| {
            if !lowerer.options.debug_symbols {
                return lowerer.alloc_here(Lir::Raise(vec![]));
            }

            let error = lowerer.alloc_here(Lir::Atom(
                format!("raise called at {}", srcloc.display(&lowerer.base_path)).into_bytes(),
            ));
            let lir = hir.map(|hir| lowerer.lower_hir(env, hir));
            let mut args = vec![error];

            if let Some(hir) = lir {
                args.push(hir);
            }

            lowerer.alloc_here(Lir::Raise(args))
        })
    }

    fn lower_debug(
        &mut self,
        env: &Environment,
        mut stmts: Vec<Statement>,
        value: HirId,
        srcloc: SrcLoc,
        body: Option<HirId>,
    ) -> LirId {
        stmts.remove(0);
        let loc = rue_srcloc_to_chialisp(&srcloc);
        self.with_loc(loc, |lowerer| {
            let rest = lowerer.lower_block(env, stmts, body);
            let value = lowerer.lower_hir(env, value);
            let print =
                lowerer.alloc_here(Lir::DebugPrint(srcloc.display(&lowerer.base_path), value));
            let nil = lowerer.alloc_here(Lir::Atom(vec![]));
            lowerer.alloc_here(Lir::If(print, nil, rest, false))
        })
    }

    fn lower_if(
        &mut self,
        env: &Environment,
        mut stmts: Vec<Statement>,
        stmt: IfStatement,
        body: Option<HirId>,
    ) -> LirId {
        stmts.remove(0);
        let condition = self.lower_hir(env, stmt.condition);
        let then_branch = self.lower_hir(env, stmt.then);
        let else_branch = self.lower_block(env, stmts, body);
        self.alloc_here(Lir::If(condition, then_branch, else_branch, stmt.inline))
    }

    fn lower_expr_stmts(
        &mut self,
        env: &Environment,
        stmt: ExprStatement,
        mut stmts: Vec<Statement>,
        body: Option<HirId>,
    ) -> LirId {
        if self.options.debug_symbols {
            stmts.remove(0);

            let rest = self.lower_block(env, stmts, body);
            let value = self.lower_hir(env, stmt.hir);
            let one = self.alloc_here(Lir::Atom(vec![1]));
            return self.alloc_here(Lir::If(one, rest, value, true));
        }

        let mut ids = Vec::new();

        while let Some(Statement::Expr(expr)) = stmts.first().cloned() {
            ids.push((self.lower_hir(env, expr.hir), expr.always_nil));
            stmts.remove(0);
        }

        let expr = self.lower_block(env, stmts, body);

        if ids.is_empty() {
            return expr;
        }

        let (condition, verifications) = if ids.len() == 1 {
            let condition = self.alloc_here(Lir::Atom(vec![]));
            (condition, ids[0].0)
        } else if let Some(index) = ids.iter().position(|(_, always_nil)| *always_nil) {
            let (condition, _) = ids.remove(index);
            let id = if ids.len() == 1 {
                ids[0].0
            } else {
                self.alloc_here(Lir::All(ids.iter().map(|(id, _)| *id).collect()))
            };
            (condition, id)
        } else {
            let condition = self.alloc_here(Lir::Atom(vec![]));
            let id = if ids.len() == 1 {
                ids[0].0
            } else {
                self.alloc_here(Lir::All(ids.iter().map(|(id, _)| *id).collect()))
            };
            (condition, id)
        };

        self.alloc_here(Lir::If(condition, verifications, expr, true))
    }

    fn group_symbols(
        &mut self,
        mut symbols: IndexSet<SymbolId>,
        by_reference: bool,
        is_tree: bool,
    ) -> Vec<SymbolGroup> {
        let mut groups = Vec::new();

        while !symbols.is_empty() {
            let mut group = Vec::new();
            let remaining = symbols.clone();

            symbols.retain(|&symbol| {
                if self
                    .graph
                    .dependencies(symbol, true)
                    .iter()
                    .all(|symbol| !remaining.contains(symbol))
                    || matches!(self.db.symbol(symbol), Symbol::Function(_))
                    || by_reference
                {
                    if !self.should_inline(symbol) && self.graph.references(symbol) > 0 {
                        group.push(symbol);
                    }
                    false
                } else {
                    true
                }
            });

            if !group.is_empty() {
                groups.push(self.create_group(group, is_tree));
            }
        }

        groups
    }

    fn create_group(&self, symbols: Vec<SymbolId>, is_tree: bool) -> SymbolGroup {
        if is_tree {
            let mut referenced_symbols = IndexMap::new();

            for symbol in symbols {
                referenced_symbols.insert(symbol, self.graph.references(symbol));
            }

            SymbolGroup::Tree(Environment::tree(referenced_symbols))
        } else {
            SymbolGroup::Sequential(symbols)
        }
    }

    fn apply_group(mut env: Environment, group: &SymbolGroup, include_rest: bool) -> Environment {
        match group {
            SymbolGroup::Sequential(symbols) => {
                for (i, &symbol) in symbols.iter().rev().enumerate() {
                    if i == 0 && !include_rest {
                        env = Environment::Leaf(symbol);
                    } else {
                        env = Environment::Pair(Box::new(Environment::Leaf(symbol)), Box::new(env));
                    }
                }

                env
            }
            SymbolGroup::Tree(tree) => {
                if include_rest {
                    Environment::Pair(Box::new(tree.clone()), Box::new(env))
                } else {
                    tree.clone()
                }
            }
        }
    }

    fn should_inline(&self, symbol: SymbolId) -> bool {
        if self
            .inline_symbols
            .iter()
            .any(|symbols| symbols.contains_key(&symbol))
        {
            return true;
        }

        let references = self.graph.references(symbol);

        match self.db.symbol(symbol) {
            Symbol::Unresolved | Symbol::Module(_) | Symbol::Parameter(_) | Symbol::Builtin(_) => {
                false
            }
            Symbol::Function(function) => {
                if self.graph.dependencies(symbol, false).contains(&symbol) {
                    return false;
                }

                if function.kind == FunctionKind::Inline {
                    return true;
                }

                for (_, parameter) in &function.parameters {
                    if self.graph.references(*parameter) > 1 {
                        return false;
                    }
                }

                references <= 1 && self.options.auto_inline
            }
            Symbol::Constant(constant) => {
                if constant.inline {
                    return true;
                }

                references <= 1 && self.options.auto_inline
            }
            Symbol::Binding(binding) => {
                if binding.inline {
                    return true;
                }

                references <= 1 && self.options.auto_inline
            }
        }
    }
}

fn list(creator: &mut CreateRueSExp, loc: &RueSrcLoc, items: &[RueSExp]) -> RueSExp {
    let mut term = creator.atom(loc.clone(), &[]);
    for item in items.iter().rev() {
        term = creator.cons(loc.clone(), item.clone(), term);
    }
    term
}

fn quote(creator: &mut CreateRueSExp, loc: &RueSrcLoc, value: RueSExp) -> RueSExp {
    let left = creator.atom(loc.clone(), &ClvmOp::Quote.to_atom());
    creator.cons(loc.clone(), left, value)
}

fn rue_srcloc_to_chialisp(loc: &SrcLoc) -> RueSrcLoc {
    RueSrcLoc::new(loc.clone())
}

fn source_to_start_loc(source: &Source) -> RueSrcLoc {
    RueSrcLoc {
        raw: Rc::new(SrcLoc::new(
            source.clone(),
            std::ops::Range { start: 0, end: 0 },
        )),
    }
}

fn syntax_item_loc(
    sources: &HashMap<SourceKind, Source>,
    source_kind: &SourceKind,
    span: rowan::TextRange,
) -> Option<RueSrcLoc> {
    sources.get(source_kind).map(|source| RueSrcLoc {
        raw: Rc::new(SrcLoc::new(
            source.clone(),
            std::ops::Range {
                start: span.start().into(),
                end: span.end().into(),
            },
        )),
    })
}

fn build_symbol_locs(ctx: &Compiler, tree: &FileTree) -> HashMap<SymbolId, RueSrcLoc> {
    let sources: HashMap<SourceKind, Source> = tree
        .all_files()
        .into_iter()
        .map(|file| (file.source.kind.clone(), file.source.clone()))
        .collect();

    let mut result = HashMap::new();

    for item in ctx.syntax_map().items() {
        if let SyntaxItemKind::SymbolDeclaration(symbol) = item.kind
            && let Some(loc) = syntax_item_loc(&sources, &item.source_kind, item.span)
        {
            result.insert(symbol, loc);
        }
    }

    result
}

fn parameter_expression(names: &[String]) -> String {
    if std::env::var_os("ARMTX_RUE_FORCE_ENV_ARGS").is_some() {
        return "ENV".to_string();
    }
    match names {
        [] => "()".to_string(),
        [name] => name.clone(),
        _ => format!("({})", names.join(" ")),
    }
}

fn argument_tree_expression(env: &Environment, parameters: &IndexMap<String, SymbolId>, is_main: bool) -> String {
    match env {
        Environment::Nil => "()".to_string(),
        Environment::Leaf(symbol) => parameters
            .iter()
            .find_map(|(name, parameter)| {
                if parameter == symbol {
                    Some(name.clone())
                } else {
                    None
                }
            })
            .unwrap_or_else(|| "()".to_string()),
        Environment::Pair(first, rest) => {
            if is_main {
                return argument_tree_expression(rest, parameters, false);
            }

            format!(
                "({} . {})",
                argument_tree_expression(first, parameters, false),
                argument_tree_expression(rest, parameters, false)
            )
        }
    }
}

struct CodegenContext<'a> {
    creator: &'a mut CreateRueSExp,
    arena: &'a Arena<Lir>,
    lir_locations: &'a HashMap<LirId, RueSrcLoc>,
    current_loc: Vec<&'a RueSrcLoc>,
}

impl<'a> CodegenContext<'a> {
    fn codegen_debug(self: &mut CodegenContext<'a>, lir: LirId) -> RueSExp {
        let restore = if let Some(new_location) = self.lir_locations.get(&lir) {
            self.current_loc.push(new_location);
            true
        } else {
            false
        };
        let result = self.codegen_debug_(lir);
        if restore {
            self.current_loc.pop();
        }
        result
    }

    fn codegen_debug_(self: &mut CodegenContext<'a>, lir: LirId) -> RueSExp {
        let loc = self.current_loc[self.current_loc.len() - 1];
        match &self.arena[lir] {
            Lir::Atom(bytes) => {
                if bytes.is_empty() {
                    self.creator.atom(loc.clone(), &[])
                } else {
                    let quoted = self.creator.atom(loc.clone(), bytes);
                    quote(self.creator, loc, quoted)
                }
            }
            Lir::Quote(arg) => {
                let arg = self.codegen_debug(*arg);
                quote(self.creator, loc, arg)
            }
            Lir::Path(path) => {
                let mut bytes = bigint_atom((*path).into());
                while !bytes.is_empty() && bytes[0] == 0 {
                    bytes = bytes[1..].to_vec();
                }
                self.creator.atom(loc.clone(), &bytes)
            }
            Lir::Run(callee, env) => {
                let list_vec = vec![self.codegen_debug(*callee), self.codegen_debug(*env)];

                self.op_list(ClvmOp::Apply, list_vec)
            }
            Lir::Closure(function, captures, has_parameters) => {
                let function = self.codegen_debug(*function);
                let mut args = if *has_parameters {
                    let quoted_atom = self.creator.atom(loc.clone(), &[1]);
                    quote(self.creator, loc, quoted_atom)
                } else {
                    self.creator.atom(loc.clone(), &[])
                };

                for capture in captures.iter().rev() {
                    let capture = self.codegen_debug(*capture);
                    let quoted_atom = self.creator.atom(loc.clone(), &ClvmOp::Cons.to_atom());
                    let quoted_head_atom = quote(self.creator, loc, quoted_atom);
                    let quoted_op_quote = self.creator.atom(loc.clone(), &ClvmOp::Quote.to_atom());
                    let quoted_head = quote(self.creator, loc, quoted_op_quote);
                    let inner_cons_quote = self.op_list(ClvmOp::Cons, vec![quoted_head, capture]);
                    let nil_tail = self.creator.atom(loc.clone(), &[]);
                    let inner_cons_tail = self.op_list(ClvmOp::Cons, vec![args, nil_tail]);
                    let list_tail =
                        self.op_list(ClvmOp::Cons, vec![inner_cons_quote, inner_cons_tail]);

                    args = self.op_list(ClvmOp::Cons, vec![quoted_head_atom, list_tail]);
                }

                let nil = self.creator.atom(loc.clone(), &ClvmOp::Apply.to_atom());
                let quote_op = self.creator.atom(loc.clone(), &ClvmOp::Quote.to_atom());
                let quoted_quote = quote(self.creator, loc, quote_op);
                let cons_first = self.op_list(ClvmOp::Cons, vec![quoted_quote, function]);
                let cons_rest = self.op_list(ClvmOp::Cons, vec![args, nil.clone()]);
                let cons_arguments = self.op_list(ClvmOp::Cons, vec![cons_first, cons_rest]);
                let quoted_nil = quote(self.creator, loc, nil.clone());

                self.op_list(ClvmOp::Cons, vec![quoted_nil, cons_arguments])
            }
            Lir::First(arg) => {
                let first_arg = self.codegen_debug(*arg);
                self.op_list(ClvmOp::First, vec![first_arg])
            }
            Lir::Rest(arg) => {
                let rest_arg = self.codegen_debug(*arg);
                self.op_list(ClvmOp::Rest, vec![rest_arg])
            }
            Lir::Cons(first, rest) => {
                let cons_first = self.codegen_debug(*first);
                let cons_rest = self.codegen_debug(*rest);
                self.op_list(ClvmOp::Cons, vec![cons_first, cons_rest])
            }
            Lir::Listp(arg, _) => {
                let listp_arg = self.codegen_debug(*arg);
                self.op_list(ClvmOp::Listp, vec![listp_arg])
            }
            Lir::Add(args) => self.op_list_args(ClvmOp::Add, args),
            Lir::Sub(args) => self.op_list_args(ClvmOp::Sub, args),
            Lir::Mul(args) => self.op_list_args(ClvmOp::Mul, args),
            Lir::Div(first, second) => self.op_list_binary(ClvmOp::Div, *first, *second),
            Lir::Divmod(first, second) => self.op_list_binary(ClvmOp::Divmod, *first, *second),
            Lir::Mod(first, second) => self.op_list_binary(ClvmOp::Mod, *first, *second),
            Lir::Modpow(a, b, c) => {
                let modpow_a = self.codegen_debug(*a);
                let modpow_b = self.codegen_debug(*b);
                let modpow_c = self.codegen_debug(*c);
                self.op_list(ClvmOp::Modpow, vec![modpow_a, modpow_b, modpow_c])
            }
            Lir::Eq(first, second) => self.op_list_binary(ClvmOp::Eq, *first, *second),
            Lir::Gt(first, second) => self.op_list_binary(ClvmOp::Gt, *first, *second),
            Lir::GtBytes(first, second) => self.op_list_binary(ClvmOp::GtBytes, *first, *second),
            Lir::Not(arg) => {
                let not_arg = self.codegen_debug(*arg);
                self.op_list(ClvmOp::Not, vec![not_arg])
            }
            Lir::All(args) => self.op_list_args(ClvmOp::All, args),
            Lir::Any(args) => self.op_list_args(ClvmOp::Any, args),
            Lir::If(cond, then_lir, else_lir, inline) => {
                let cond = self.codegen_debug(*cond);
                let then_ptr = self.codegen_debug(*then_lir);
                let else_ptr = self.codegen_debug(*else_lir);
                if *inline {
                    self.op_list(ClvmOp::If, vec![cond, then_ptr, else_ptr])
                } else {
                    let then_quoted = quote(self.creator, loc, then_ptr);
                    let else_quoted = quote(self.creator, loc, else_ptr);
                    let apply_prog = self.op_list(ClvmOp::If, vec![cond, then_quoted, else_quoted]);

                    let env_atom = self.creator.atom(loc.clone(), &[1]);
                    self.op_list(ClvmOp::Apply, vec![apply_prog, env_atom])
                }
            }
            Lir::Raise(args) => self.op_list_args(ClvmOp::Raise, args),
            Lir::Concat(args) => self.op_list_args(ClvmOp::Concat, args),
            Lir::Strlen(arg) => {
                let strlen_arg = self.codegen_debug(*arg);
                self.op_list(ClvmOp::Strlen, vec![strlen_arg])
            }
            Lir::Substr(arg, start, end) => {
                let mut args = vec![self.codegen_debug(*arg), self.codegen_debug(*start)];
                if let Some(end) = end {
                    args.push(self.codegen_debug(*end));
                }
                self.op_list(ClvmOp::Substr, args)
            }
            Lir::Logand(args) => self.op_list_args(ClvmOp::Logand, args),
            Lir::Logior(args) => self.op_list_args(ClvmOp::Logior, args),
            Lir::Logxor(args) => self.op_list_args(ClvmOp::Logxor, args),
            Lir::Lognot(arg) => {
                let lognot_arg = self.codegen_debug(*arg);
                self.op_list(ClvmOp::Lognot, vec![lognot_arg])
            }
            Lir::Ash(arg, shift) => self.op_list_binary(ClvmOp::Ash, *arg, *shift),
            Lir::Lsh(arg, shift) => self.op_list_binary(ClvmOp::Lsh, *arg, *shift),
            Lir::PubkeyForExp(arg) => {
                let pke_arg = self.codegen_debug(*arg);
                self.op_list(ClvmOp::PubkeyForExp, vec![pke_arg])
            }
            Lir::G1Add(args) => self.op_list_args(ClvmOp::G1Add, args),
            Lir::G1Subtract(args) => self.op_list_args(ClvmOp::G1Subtract, args),
            Lir::G1Multiply(first, second) => {
                self.op_list_binary(ClvmOp::G1Multiply, *first, *second)
            }
            Lir::G1Negate(arg) => {
                let g1neg_arg = self.codegen_debug(*arg);
                self.op_list(ClvmOp::G1Negate, vec![g1neg_arg])
            }
            Lir::G1Map(value, dst) => {
                let mut args = vec![self.codegen_debug(*value)];
                if let Some(dst) = dst {
                    args.push(self.codegen_debug(*dst));
                }
                self.op_list(ClvmOp::G1Map, args)
            }
            Lir::G2Add(args) => self.op_list_args(ClvmOp::G2Add, args),
            Lir::G2Subtract(args) => self.op_list_args(ClvmOp::G2Subtract, args),
            Lir::G2Multiply(first, second) => {
                self.op_list_binary(ClvmOp::G2Multiply, *first, *second)
            }
            Lir::G2Negate(arg) => {
                let g2neg_arg = self.codegen_debug(*arg);
                self.op_list(ClvmOp::G2Negate, vec![g2neg_arg])
            }
            Lir::G2Map(value, dst) => {
                let mut args = vec![self.codegen_debug(*value)];
                if let Some(dst) = dst {
                    args.push(self.codegen_debug(*dst));
                }
                self.op_list(ClvmOp::G2Map, args)
            }
            Lir::BlsPairingIdentity(args) => self.op_list_args(ClvmOp::BlsPairingIdentity, args),
            Lir::BlsVerify(arg, args) => {
                let mut items = vec![self.codegen_debug(*arg)];
                items.extend(args.iter().map(|arg| self.codegen_debug(*arg)));
                self.op_list(ClvmOp::BlsVerify, items)
            }
            Lir::Sha256(args) | Lir::Sha256Inline(args) => self.op_list_args(ClvmOp::Sha256, args),
            Lir::Keccak256(args) | Lir::Keccak256Inline(args) => {
                self.op_list_args(ClvmOp::Keccak256, args)
            }
            Lir::CoinId(parent, puzzle, amount) => {
                let coinid_parent = self.codegen_debug(*parent);
                let coinid_puzzle = self.codegen_debug(*puzzle);
                let coinid_amount = self.codegen_debug(*amount);
                self.op_list(
                    ClvmOp::CoinId,
                    vec![coinid_parent, coinid_puzzle, coinid_amount],
                )
            }
            Lir::K1Verify(pubkey, message, signature) => {
                let k1v_pubkey = self.codegen_debug(*pubkey);
                let k1v_message = self.codegen_debug(*message);
                let k1v_sig = self.codegen_debug(*signature);
                self.op_list(
                    ClvmOp::Secp256K1Verify,
                    vec![k1v_pubkey, k1v_message, k1v_sig],
                )
            }
            Lir::R1Verify(pubkey, message, signature) => {
                let r1v_pubkey = self.codegen_debug(*pubkey);
                let r1v_message = self.codegen_debug(*message);
                let r1v_sig = self.codegen_debug(*signature);
                self.op_list(
                    ClvmOp::Secp256R1Verify,
                    vec![r1v_pubkey, r1v_message, r1v_sig],
                )
            }
            Lir::Op(op, args) => {
                let args = self.codegen_debug(*args);
                let op_nil_args = self.creator.atom(loc.clone(), &[]);
                let op_data = self.creator.atom(loc.clone(), &op.to_atom());
                let quoted_atom_head = quote(self.creator, loc, op_data);
                let op_head_prog =
                    self.op_list(ClvmOp::Cons, vec![quoted_atom_head, op_nil_args.clone()]);

                let op_head = self.op_list(ClvmOp::Cons, vec![op_head_prog, args]);

                self.op_list(ClvmOp::Apply, vec![op_head, op_nil_args])
            }
            Lir::DebugPrint(srcloc, value) => {
                let quoted_prog_atom = self.creator.atom(loc.clone(), srcloc.as_bytes());
                let quoted_prog = quote(self.creator, loc, quoted_prog_atom);
                let args = self.codegen_debug(*value);
                self.op_list(ClvmOp::DebugPrint, vec![quoted_prog, args])
            }
        }
    }

    fn op_list(&mut self, op: ClvmOp, args: Vec<RueSExp>) -> RueSExp {
        let loc = self.current_loc[self.current_loc.len() - 1];
        let mut items = Vec::with_capacity(args.len() + 1);
        items.push(self.creator.atom(loc.clone(), &op.to_atom()));
        items.extend(args);
        list(self.creator, loc, &items)
    }

    fn op_list_binary(&mut self, op: ClvmOp, first: LirId, second: LirId) -> RueSExp {
        let op_first = self.codegen_debug(first);
        let op_rest = self.codegen_debug(second);
        self.op_list(op, vec![op_first, op_rest])
    }

    fn op_list_args(&mut self, op: ClvmOp, args: &[LirId]) -> RueSExp {
        let converted_args = args.iter().map(|arg| self.codegen_debug(*arg)).collect();
        self.op_list(op, converted_args)
    }
}

fn add_function_symbol_metadata(
    symbol_table: &mut HashMap<String, String>,
    hash: String,
    name: &str,
    arguments: &str,
) {
    symbol_table.insert(hash.clone(), name.to_string());
    let mut key = format!("{hash}_arguments");
    symbol_table.insert(key, arguments.to_string());
    key = format!("{hash}_left_env");
    if name == "main" {
        symbol_table.insert(key, "0".to_string());
    } else {
        symbol_table.insert(key, "1".to_string());
    }
}

struct RueCompileOutput {
    program: RueSExp,
    symbols: HashMap<String, String>,
    srclocs: HashMap<String, RueSrcLoc>,
}

fn compile_main(
    creator: &mut CreateRueSExp,
    ctx: &mut Compiler,
    tree: &FileTree,
    main: SymbolId,
    base_path: PathBuf,
    symbol_locs: &HashMap<SymbolId, RueSrcLoc>,
) -> Result<RueCompileOutput, String> {
    let options = *ctx.options();
    let graph = DependencyGraph::build(ctx, main, options);
    let mut arena = Arena::new();
    let mut lir_locations = HashMap::new();
    let mut function_body_lirs = HashMap::new();
    let mut function_argument_trees = HashMap::new();
    let source = base_path.display().to_string();
    let fallback_loc = tree
        .all_files()
        .first()
        .map(|file| source_to_start_loc(&file.source))
        .unwrap_or_else(|| {
            RueSrcLoc::new(SrcLoc::new(
                Source::new(source.into(), SourceKind::Std("*rue*".to_string())),
                std::ops::Range { start: 0, end: 0 },
            ))
        });
    let lir = {
        let mut lowerer = DebugLowerer::new(
            ctx,
            &mut arena,
            &graph,
            &mut lir_locations,
            &mut function_body_lirs,
            &mut function_argument_trees,
            options,
            main,
            base_path.clone(),
            symbol_locs,
            fallback_loc,
        );
        lowerer.lower_symbol_value(&Environment::default(), main)
    };

    let default_loc = RueSrcLoc::start(&base_path.display().to_string());
    let mut cgctx = CodegenContext {
        creator,
        arena: &arena,
        current_loc: vec![&default_loc],
        lir_locations: &lir_locations,
    };
    let compiled = cgctx.codegen_debug(lir);

    let mut symbol_table = HashMap::new();
    let program_locations = HashMap::new();

    let relevant_declarations = ctx.relevant_declarations().collect::<Vec<_>>();
    for item in relevant_declarations {
        let rue_hir::Declaration::Symbol(symbol) = item else {
            continue;
        };
        let Symbol::Function(function) = ctx.symbol(symbol).clone() else {
            continue;
        };
        let Some(name) = function.name.as_ref().map(|name| name.text().to_string()) else {
            continue;
        };

        let Some(body_lir) = function_body_lirs.get(&symbol).cloned() else {
            continue;
        };
        let arguments = function_argument_trees
            .get(&symbol)
            .cloned()
            .unwrap_or_else(|| {
                parameter_expression(&function.parameters.keys().cloned().collect::<Vec<_>>())
            });
        let function_sexp = cgctx.codegen_debug(body_lir);
        let function_hash = hex::encode(function_sexp.sha256tree());
        add_function_symbol_metadata(&mut symbol_table, function_hash, &name, &arguments);
    }

    Ok(RueCompileOutput {
        program: compiled,
        symbols: symbol_table,
        srclocs: program_locations,
    })
}

struct CreateRueSExp {
    allocator: ClvmrAllocator,
}

impl CreateRueSExp {
    fn new() -> Self {
        CreateRueSExp {
            allocator: ClvmrAllocator::default(),
        }
    }
}

impl CreateSExp for CreateRueSExp {
    type S = RueSExp;
    type SL = RueSrcLoc;

    fn atom(&mut self, loc: Self::SL, bytes: &[u8]) -> Self::S {
        let acopy = self.allocator.clone();
        self.allocator.with_allocator_mut(|a| RueSExp {
            kind: RueSExpKind::Atom,
            clvm: ClvmrWrapper {
                a: acopy,
                n: a.new_atom(bytes).unwrap(),
            },
            loc,
        })
    }
    fn cons(&mut self, loc: Self::SL, a: Self::S, b: Self::S) -> Self::S {
        let alloc_copy = self.allocator.clone();
        self.allocator.with_allocator_mut(|allocator| RueSExp {
            kind: RueSExpKind::Cons(Rc::new(a.clone()), Rc::new(b.clone())),
            clvm: ClvmrWrapper {
                a: alloc_copy,
                n: allocator.new_pair(a.clvm.n, b.clvm.n).unwrap(),
            },
            loc,
        })
    }
    fn start_srcloc(&mut self, name: &str) -> Self::SL {
        RueSrcLoc::start(name)
    }
    fn loc(&self, s: Self::S) -> Self::SL {
        s.loc()
    }

    fn parse_sexp<I>(
        &mut self,
        start: Self::SL,
        input: I,
    ) -> Result<Vec<Self::S>, (Self::SL, String)>
    where
        I: Iterator<Item = u8>,
    {
        let data: Vec<u8> = input.collect();
        let allocator_new_ref = self.allocator.clone();
        let parsed_node = self.allocator.with_allocator_mut(
            |a| -> Result<clvmr::NodePtr, (Self::SL, String)> {
                let decoded = decode_string(&data);
                assemble(a, &decoded).map_err(|e| (start.clone(), format!("{e:?}")))
            },
        )?;
        Ok(vec![RueSExp::from_node(
            allocator_new_ref,
            &start.clone(),
            parsed_node,
        )])
    }
}

pub struct RueGenerateOutput {
    pub object: ElfObject,
    pub symbols: Rc<HashMap<String, String>>,
}

pub fn compile_rue_to_arm_elf(args: &Args) -> Result<RueGenerateOutput, String> {
    let mut creator = CreateRueSExp::new();
    let search_path = Path::new(&args.filename)
        .canonicalize()
        .map_err(|e| format!("failed to canonicalize {}: {e:?}", args.filename))?;
    let project = find_project(&search_path, true)
        .map_err(|e| format!("failed to find rue project: {e:?}"))?
        .ok_or_else(|| format!("no rue project found for {}", args.filename))?;

    let file_kind = Some(normalize_path(Path::new(&args.filename)).map_err(|e| format!("{e:?}"))?);
    let main_kind = file_kind.clone().or_else(|| {
        let main = project.entrypoint.join("main.rue");
        if main.exists() {
            normalize_path(&main).ok()
        } else {
            None
        }
    });

    let mut ctx = Compiler::new(project.options);
    let tree = FileTree::compile_path(&mut ctx, &project.entrypoint, &mut HashMap::new())
        .map_err(|e| format!("failed to compile rue: {e:?}"))?;
    let base_path = if project.entrypoint.is_file() {
        project
            .entrypoint
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .canonicalize()
            .map_err(|e| format!("failed to canonicalize rue base path: {e:?}"))?
    } else {
        project
            .entrypoint
            .canonicalize()
            .map_err(|e| format!("failed to canonicalize rue entrypoint: {e:?}"))?
    };

    let mut codegen_allowed = true;
    for diagnostic in ctx.take_diagnostics() {
        let message = diagnostic.message(&base_path);
        if diagnostic.kind.severity() == DiagnosticSeverity::Error {
            codegen_allowed = false;
            eprintln!("Error: {message}");
        } else {
            eprintln!("Warning: {message}");
        }
    }
    if !codegen_allowed {
        return Err("rue compilation failed".to_string());
    }

    let main_kind = main_kind.ok_or_else(|| "no rue main function found".to_string())?;
    let file = tree
        .find(&main_kind)
        .ok_or_else(|| format!("source not found in rue compilation unit: {main_kind:?}"))?;
    let scope = ctx.module(file.module).scope;
    let main = ctx
        .scope(scope)
        .symbol("main")
        .ok_or_else(|| "no `main` function found in rue file".to_string())?;
    let symbol_locs = build_symbol_locs(&ctx, &tree);
    let output = compile_main(&mut creator, &mut ctx, &tree, main, base_path, &symbol_locs)?;

    let env = creator.allocator.with_allocator_mut(|a| {
        assemble(a, &args.env).map_err(|e| format!("failed to read env: {e:?}"))
    })?;
    let env_loc = RueSrcLoc {
        raw: Rc::new(SrcLoc::new(
            Source::new("".to_string().into(), SourceKind::Std("*env*".to_string())),
            std::ops::Range { start: 0, end: 0 },
        )),
    };
    let symbols = Rc::new(output.symbols.clone());

    let mut creator = CreateRueSExp {
        allocator: creator.allocator.clone(),
    };
    let rue_env = RueSExp::from_node(creator.allocator.clone(), &env_loc, env);
    let program = Program::new(
        &mut creator,
        output.srclocs,
        &args.filename,
        &args.output,
        output.program,
        rue_env,
        TARGET_ADDR,
        symbols.clone(),
    )?;

    program
        .to_elf(&args.output)
        .map(|p| RueGenerateOutput { object: p, symbols })
        .map_err(|e| format!("failed to create elf output: {e:?}"))
}
