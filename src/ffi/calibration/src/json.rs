//! A minimal JSON object writer for result lines (the workspace carries no serializer).

use std::fmt::Write;

#[derive(Default)]
pub struct Obj {
    out: String,
}

fn escape(s: &str) -> String {
    let mut o = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => o.push_str("\\\""),
            '\\' => o.push_str("\\\\"),
            '\n' => o.push_str("\\n"),
            c if (c as u32) < 0x20 => {
                let _ = write!(o, "\\u{:04x}", c as u32);
            }
            c => o.push(c),
        }
    }
    o
}

impl Obj {
    fn key(&mut self, k: &str) {
        self.out.push(if self.out.is_empty() { '{' } else { ',' });
        let _ = write!(self.out, "\"{}\":", escape(k));
    }
    pub fn num(&mut self, k: &str, v: impl std::fmt::Display) -> &mut Self {
        self.key(k);
        let _ = write!(self.out, "{v}");
        self
    }
    pub fn float(&mut self, k: &str, v: f64) -> &mut Self {
        self.key(k);
        if v.is_finite() {
            let _ = write!(self.out, "{v:.6}");
        } else {
            self.out.push_str("null");
        }
        self
    }
    pub fn str(&mut self, k: &str, v: &str) -> &mut Self {
        self.key(k);
        let _ = write!(self.out, "\"{}\"", escape(v));
        self
    }
    pub fn bool(&mut self, k: &str, v: bool) -> &mut Self {
        self.key(k);
        self.out.push_str(if v { "true" } else { "false" });
        self
    }
    /// A value that is already JSON.
    pub fn raw(&mut self, k: &str, v: &str) -> &mut Self {
        self.key(k);
        self.out.push_str(v);
        self
    }
    pub fn finish(&self) -> String {
        if self.out.is_empty() {
            "{}".into()
        } else {
            format!("{}}}", self.out)
        }
    }
}

pub fn array(items: impl IntoIterator<Item = String>) -> String {
    format!("[{}]", items.into_iter().collect::<Vec<_>>().join(","))
}

#[cfg(test)]
mod tests {
    #[test]
    fn writes_valid_objects() {
        let mut o = super::Obj::default();
        o.num("a", 1)
            .float("b", 0.5)
            .str("c", "x\"y")
            .bool("d", true)
            .raw("e", &super::array(["1".into(), "2".into()]));
        assert_eq!(
            o.finish(),
            r#"{"a":1,"b":0.500000,"c":"x\"y","d":true,"e":[1,2]}"#
        );
        assert_eq!(super::Obj::default().finish(), "{}");
    }
}
