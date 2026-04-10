//! Recursive-descent parser for SIGMA detection condition expressions.
//!
//! Grammar (simplified):
//!
//! ```text
//! expr       = or_expr
//! or_expr    = and_expr ("or" and_expr)*
//! and_expr   = not_expr ("and" not_expr)*
//! not_expr   = "not" not_expr | atom
//! atom       = "(" expr ")"
//!            | "1 of" IDENT_GLOB
//!            | "all of" (IDENT_GLOB | "them")
//!            | IDENT
//! ```
//!
//! Identifiers may contain `[a-zA-Z0-9_]` characters.  Glob patterns in
//! `1 of`/`all of` match against selection names via prefix (`selection*`).

use std::fmt;

/// Parsed condition AST node.
#[derive(Debug, Clone, PartialEq)]
pub enum ConditionExpr {
    /// Reference to a named selection (e.g. `"selection"`).
    Ref(String),
    /// Logical AND of two sub-expressions.
    And(Box<ConditionExpr>, Box<ConditionExpr>),
    /// Logical OR of two sub-expressions.
    Or(Box<ConditionExpr>, Box<ConditionExpr>),
    /// Logical NOT of a sub-expression.
    Not(Box<ConditionExpr>),
    /// `1 of <prefix>*` — true if at least one selection matching prefix is true.
    OneOf(String),
    /// `all of <prefix>*` — true if every selection matching prefix is true.
    /// Empty string means "all of them".
    AllOf(String),
}

impl fmt::Display for ConditionExpr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ref(name) => write!(f, "{name}"),
            Self::And(a, b) => write!(f, "({a} and {b})"),
            Self::Or(a, b) => write!(f, "({a} or {b})"),
            Self::Not(inner) => write!(f, "(not {inner})"),
            Self::OneOf(prefix) => write!(f, "1 of {prefix}*"),
            Self::AllOf(prefix) => write!(f, "all of {prefix}*"),
        }
    }
}

/// Errors produced by the condition parser.
#[derive(Debug, Clone)]
pub enum ConditionParseError {
    UnexpectedEnd,
    UnexpectedToken(String),
    UnclosedParen,
}

impl fmt::Display for ConditionParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnexpectedEnd => write!(f, "unexpected end of condition expression"),
            Self::UnexpectedToken(tok) => write!(f, "unexpected token: `{tok}`"),
            Self::UnclosedParen => write!(f, "unclosed parenthesis in condition"),
        }
    }
}

impl std::error::Error for ConditionParseError {}

// ── Tokeniser ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
enum Token {
    Ident(String),
    LParen,
    RParen,
    And,
    Or,
    Not,
    OneOf,
    AllOf,
    Them,
    Pipe, // `|` — currently unused but reserved
}

fn tokenise(input: &str) -> Vec<Token> {
    let mut tokens = Vec::new();
    let words: Vec<&str> = input.split_whitespace().collect();
    let mut i = 0;
    while i < words.len() {
        let word = words[i];

        // Handle parentheses stuck to identifiers: `(selection1` or `selection2)`
        if word.starts_with('(') && word.len() > 1 {
            tokens.push(Token::LParen);
            // Re-process the remainder
            let rest = &word[1..];
            push_word(&mut tokens, rest, &words, &mut i);
            i += 1;
            continue;
        }
        if word.ends_with(')') && word.len() > 1 {
            let rest = &word[..word.len() - 1];
            push_word(&mut tokens, rest, &words, &mut i);
            tokens.push(Token::RParen);
            i += 1;
            continue;
        }

        match word.to_lowercase().as_str() {
            "and" => tokens.push(Token::And),
            "or" => tokens.push(Token::Or),
            "not" => tokens.push(Token::Not),
            "(" => tokens.push(Token::LParen),
            ")" => tokens.push(Token::RParen),
            "|" => tokens.push(Token::Pipe),
            "them" => tokens.push(Token::Them),
            "1" => {
                // Expect "1 of <pattern>"
                if i + 1 < words.len() && words[i + 1].eq_ignore_ascii_case("of") {
                    tokens.push(Token::OneOf);
                    i += 1; // skip "of"
                } else {
                    tokens.push(Token::Ident(word.to_string()));
                }
            }
            "all" => {
                // Expect "all of <pattern>"
                if i + 1 < words.len() && words[i + 1].eq_ignore_ascii_case("of") {
                    tokens.push(Token::AllOf);
                    i += 1; // skip "of"
                } else {
                    tokens.push(Token::Ident(word.to_string()));
                }
            }
            _ => tokens.push(Token::Ident(word.to_string())),
        }
        i += 1;
    }
    tokens
}

fn push_word(tokens: &mut Vec<Token>, word: &str, _words: &[&str], _i: &mut usize) {
    match word.to_lowercase().as_str() {
        "and" => tokens.push(Token::And),
        "or" => tokens.push(Token::Or),
        "not" => tokens.push(Token::Not),
        "them" => tokens.push(Token::Them),
        _ => tokens.push(Token::Ident(word.to_string())),
    }
}

// ── Parser ───────────────────────────────────────────────────────────────────

struct Parser {
    tokens: Vec<Token>,
    pos: usize,
}

impl Parser {
    fn new(tokens: Vec<Token>) -> Self {
        Self { tokens, pos: 0 }
    }

    fn peek(&self) -> Option<&Token> {
        self.tokens.get(self.pos)
    }

    fn advance(&mut self) -> Option<Token> {
        let tok = self.tokens.get(self.pos).cloned();
        self.pos += 1;
        tok
    }

    fn parse_expr(&mut self) -> Result<ConditionExpr, ConditionParseError> {
        self.parse_or()
    }

    fn parse_or(&mut self) -> Result<ConditionExpr, ConditionParseError> {
        let mut left = self.parse_and()?;
        while self.peek() == Some(&Token::Or) {
            self.advance(); // consume "or"
            let right = self.parse_and()?;
            left = ConditionExpr::Or(Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn parse_and(&mut self) -> Result<ConditionExpr, ConditionParseError> {
        let mut left = self.parse_not()?;
        while self.peek() == Some(&Token::And) {
            self.advance(); // consume "and"
            let right = self.parse_not()?;
            left = ConditionExpr::And(Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn parse_not(&mut self) -> Result<ConditionExpr, ConditionParseError> {
        if self.peek() == Some(&Token::Not) {
            self.advance(); // consume "not"
            let inner = self.parse_not()?;
            return Ok(ConditionExpr::Not(Box::new(inner)));
        }
        self.parse_atom()
    }

    fn parse_atom(&mut self) -> Result<ConditionExpr, ConditionParseError> {
        match self.peek().cloned() {
            Some(Token::LParen) => {
                self.advance(); // consume "("
                let expr = self.parse_expr()?;
                match self.advance() {
                    Some(Token::RParen) => Ok(expr),
                    _ => Err(ConditionParseError::UnclosedParen),
                }
            }
            Some(Token::OneOf) => {
                self.advance(); // consume "1 of"
                let prefix = self.parse_glob_pattern()?;
                Ok(ConditionExpr::OneOf(prefix))
            }
            Some(Token::AllOf) => {
                self.advance(); // consume "all of"
                let prefix = self.parse_glob_pattern()?;
                Ok(ConditionExpr::AllOf(prefix))
            }
            Some(Token::Ident(name)) => {
                self.advance();
                Ok(ConditionExpr::Ref(name))
            }
            Some(other) => Err(ConditionParseError::UnexpectedToken(format!("{other:?}"))),
            None => Err(ConditionParseError::UnexpectedEnd),
        }
    }

    /// Parse a glob pattern after `1 of` / `all of`.
    /// Accepts: `them` (→ empty prefix, matches all), or `name*` (→ prefix `name`).
    fn parse_glob_pattern(&mut self) -> Result<String, ConditionParseError> {
        match self.peek().cloned() {
            Some(Token::Them) => {
                self.advance();
                Ok(String::new()) // empty = match all selections
            }
            Some(Token::Ident(name)) => {
                self.advance();
                // Strip trailing `*` if present
                let prefix = name.trim_end_matches('*').to_string();
                Ok(prefix)
            }
            _ => Err(ConditionParseError::UnexpectedEnd),
        }
    }
}

/// Parse a SIGMA condition string into an AST.
///
/// # Examples
///
/// ```ignore
/// parse("selection")?                          // Ref("selection")
/// parse("selection and not filter")?           // And(Ref, Not(Ref))
/// parse("1 of selection*")?                    // OneOf("selection")
/// parse("all of them")?                        // AllOf("")
/// parse("(sel1 or sel2) and not filter")?      // And(Or(...), Not(...))
/// ```
pub fn parse(input: &str) -> Result<ConditionExpr, ConditionParseError> {
    let tokens = tokenise(input);
    if tokens.is_empty() {
        return Err(ConditionParseError::UnexpectedEnd);
    }
    let mut parser = Parser::new(tokens);
    let expr = parser.parse_expr()?;
    // Ensure we consumed all tokens
    if parser.pos < parser.tokens.len() {
        return Err(ConditionParseError::UnexpectedToken(
            format!("{:?}", parser.tokens[parser.pos]),
        ));
    }
    Ok(expr)
}

/// Evaluate a condition AST against a set of named selection results.
///
/// `selections` maps selection name → whether the selection matched the event.
pub fn evaluate(
    expr: &ConditionExpr,
    selections: &std::collections::HashMap<String, bool>,
) -> bool {
    match expr {
        ConditionExpr::Ref(name) => *selections.get(name.as_str()).unwrap_or(&false),
        ConditionExpr::And(a, b) => evaluate(a, selections) && evaluate(b, selections),
        ConditionExpr::Or(a, b) => evaluate(a, selections) || evaluate(b, selections),
        ConditionExpr::Not(inner) => !evaluate(inner, selections),
        ConditionExpr::OneOf(prefix) => {
            if prefix.is_empty() {
                // "all of them" variant for 1 of — any selection
                selections.values().any(|&v| v)
            } else {
                selections
                    .iter()
                    .filter(|(k, _)| k.starts_with(prefix.as_str()))
                    .any(|(_, &v)| v)
            }
        }
        ConditionExpr::AllOf(prefix) => {
            if prefix.is_empty() {
                selections.values().all(|&v| v)
            } else {
                let matching: Vec<_> = selections
                    .iter()
                    .filter(|(k, _)| k.starts_with(prefix.as_str()))
                    .collect();
                !matching.is_empty() && matching.iter().all(|(_, &v)| v)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simple_ref() {
        let expr = parse("selection").unwrap();
        assert_eq!(expr, ConditionExpr::Ref("selection".into()));
    }

    #[test]
    fn test_and_not() {
        let expr = parse("selection and not filter").unwrap();
        assert_eq!(
            expr,
            ConditionExpr::And(
                Box::new(ConditionExpr::Ref("selection".into())),
                Box::new(ConditionExpr::Not(Box::new(ConditionExpr::Ref("filter".into())))),
            )
        );
    }

    #[test]
    fn test_one_of() {
        let expr = parse("1 of selection*").unwrap();
        assert_eq!(expr, ConditionExpr::OneOf("selection".into()));
    }

    #[test]
    fn test_all_of_them() {
        let expr = parse("all of them").unwrap();
        assert_eq!(expr, ConditionExpr::AllOf(String::new()));
    }

    #[test]
    fn test_parens() {
        let expr = parse("(sel1 or sel2) and not filter").unwrap();
        match expr {
            ConditionExpr::And(left, right) => {
                assert!(matches!(*left, ConditionExpr::Or(_, _)));
                assert!(matches!(*right, ConditionExpr::Not(_)));
            }
            other => panic!("expected And, got {other:?}"),
        }
    }

    #[test]
    fn test_evaluate_simple() {
        let expr = parse("selection and not filter").unwrap();
        let mut sels = std::collections::HashMap::new();
        sels.insert("selection".into(), true);
        sels.insert("filter".into(), false);
        assert!(evaluate(&expr, &sels));

        sels.insert("filter".into(), true);
        assert!(!evaluate(&expr, &sels));
    }
}
