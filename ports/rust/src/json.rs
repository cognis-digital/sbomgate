// Minimal zero-dependency JSON value parser — just enough for SBOM input.
use std::collections::BTreeMap;

#[derive(Clone, Debug)]
pub enum Json {
    Null,
    Bool(bool),
    Num(f64),
    Str(String),
    Array(Vec<Json>),
    Object(BTreeMap<String, Json>),
}

impl Json {
    pub fn as_str_lossy(&self) -> String {
        match self {
            Json::Str(s) => s.clone(),
            Json::Num(n) => {
                if n.fract() == 0.0 {
                    format!("{}", *n as i64)
                } else {
                    format!("{n}")
                }
            }
            Json::Bool(b) => b.to_string(),
            _ => String::new(),
        }
    }

    pub fn parse(s: &str) -> Option<Json> {
        let chars: Vec<char> = s.chars().collect();
        let mut p = Parser { c: chars, i: 0 };
        p.skip_ws();
        let v = p.value()?;
        p.skip_ws();
        Some(v)
    }
}

struct Parser {
    c: Vec<char>,
    i: usize,
}

impl Parser {
    fn peek(&self) -> Option<char> {
        self.c.get(self.i).copied()
    }
    fn next(&mut self) -> Option<char> {
        let ch = self.c.get(self.i).copied();
        self.i += 1;
        ch
    }
    fn skip_ws(&mut self) {
        while matches!(self.peek(), Some(c) if c.is_whitespace()) {
            self.i += 1;
        }
    }
    fn value(&mut self) -> Option<Json> {
        self.skip_ws();
        match self.peek()? {
            '{' => self.object(),
            '[' => self.array(),
            '"' => Some(Json::Str(self.string()?)),
            't' | 'f' => self.boolean(),
            'n' => {
                self.expect("null")?;
                Some(Json::Null)
            }
            _ => self.number(),
        }
    }
    fn expect(&mut self, lit: &str) -> Option<()> {
        for ch in lit.chars() {
            if self.next()? != ch {
                return None;
            }
        }
        Some(())
    }
    fn boolean(&mut self) -> Option<Json> {
        if self.peek()? == 't' {
            self.expect("true")?;
            Some(Json::Bool(true))
        } else {
            self.expect("false")?;
            Some(Json::Bool(false))
        }
    }
    fn number(&mut self) -> Option<Json> {
        let start = self.i;
        while matches!(self.peek(), Some(c) if c.is_ascii_digit() || "+-.eE".contains(c)) {
            self.i += 1;
        }
        let s: String = self.c[start..self.i].iter().collect();
        s.parse::<f64>().ok().map(Json::Num)
    }
    fn string(&mut self) -> Option<String> {
        self.next()?; // opening quote
        let mut out = String::new();
        loop {
            match self.next()? {
                '"' => return Some(out),
                '\\' => match self.next()? {
                    '"' => out.push('"'),
                    '\\' => out.push('\\'),
                    '/' => out.push('/'),
                    'n' => out.push('\n'),
                    't' => out.push('\t'),
                    'r' => out.push('\r'),
                    'b' => out.push('\u{0008}'),
                    'f' => out.push('\u{000C}'),
                    'u' => {
                        let hex: String = (0..4).filter_map(|_| self.next()).collect();
                        if let Ok(n) = u32::from_str_radix(&hex, 16) {
                            if let Some(ch) = char::from_u32(n) {
                                out.push(ch);
                            }
                        }
                    }
                    other => out.push(other),
                },
                c => out.push(c),
            }
        }
    }
    fn array(&mut self) -> Option<Json> {
        self.next()?; // [
        let mut out = vec![];
        self.skip_ws();
        if self.peek()? == ']' {
            self.next();
            return Some(Json::Array(out));
        }
        loop {
            out.push(self.value()?);
            self.skip_ws();
            match self.next()? {
                ',' => self.skip_ws(),
                ']' => return Some(Json::Array(out)),
                _ => return None,
            }
        }
    }
    fn object(&mut self) -> Option<Json> {
        self.next()?; // {
        let mut map = BTreeMap::new();
        self.skip_ws();
        if self.peek()? == '}' {
            self.next();
            return Some(Json::Object(map));
        }
        loop {
            self.skip_ws();
            let k = self.string()?;
            self.skip_ws();
            if self.next()? != ':' {
                return None;
            }
            let v = self.value()?;
            map.insert(k, v);
            self.skip_ws();
            match self.next()? {
                ',' => {}
                '}' => return Some(Json::Object(map)),
                _ => return None,
            }
        }
    }
}
