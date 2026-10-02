//! Call variables, with SIPp's types and its notion of "set".

use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::rc::Rc;

#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    /// Assigned by <ereg>: counts as set once it has matched.
    Regexp(String),
    Str(String),
    Double(f64),
    Bool(bool),
}

pub type Table = Rc<RefCell<HashMap<String, Value>>>;

/// The variables a scenario shares: <Global variables="..."/> across all
/// calls, <User variables="..."/> across a -users user's calls.
#[derive(Debug, Clone)]
pub struct Scopes {
    pub global_names: Rc<HashSet<String>>,
    pub user_names: Rc<HashSet<String>>,
    pub global: Table,
}

impl Scopes {
    pub fn new(global_names: HashSet<String>, user_names: HashSet<String>) -> Scopes {
        Scopes { global_names: Rc::new(global_names), user_names: Rc::new(user_names), global: Table::default() }
    }
}

impl Default for Scopes {
    /// None: the same empty ones each time, whose table nothing names.
    fn default() -> Scopes {
        thread_local! {
            static NONE: Scopes = Scopes::new(HashSet::new(), HashSet::new());
        }
        NONE.with(Scopes::clone)
    }
}

#[derive(Debug, Default)]
pub struct Vars {
    own: HashMap<String, Value>,
    scopes: Scopes,
    /// This call's user's table (a fresh one for a call without a user,
    /// made when it first sets one).
    user: Option<Table>,
}

impl Vars {
    pub fn new(scopes: Scopes, user: Option<Table>) -> Vars {
        Vars { own: HashMap::new(), scopes, user }
    }

    pub fn set_regexp(&mut self, name: &str, v: &str) {
        self.set(name, Value::Regexp(v.to_string()));
    }
    pub fn set_string(&mut self, name: &str, v: &str) {
        self.set(name, Value::Str(v.to_string()));
    }
    pub fn set_double(&mut self, name: &str, v: f64) {
        self.set(name, Value::Double(v));
    }
    pub fn set_bool(&mut self, name: &str, v: bool) {
        self.set(name, Value::Bool(v));
    }
    fn set(&mut self, name: &str, v: Value) {
        // "_" is SIPp's placeholder for a match nobody wants.
        if name == "_" {
            return;
        }
        if self.scopes.global_names.contains(name) {
            self.scopes.global.borrow_mut().insert(name.to_string(), v);
        } else if self.scopes.user_names.contains(name) {
            self.user.get_or_insert_default().borrow_mut().insert(name.to_string(), v);
        } else {
            self.own.insert(name.to_string(), v);
        }
    }

    pub fn get(&self, name: &str) -> Option<Value> {
        if self.scopes.global_names.contains(name) {
            self.scopes.global.borrow().get(name).cloned()
        } else if self.scopes.user_names.contains(name) {
            self.user.as_ref()?.borrow().get(name).cloned()
        } else {
            self.own.get(name).cloned()
        }
    }

    /// SIPp's isSet(): matched, true, non-zero, or any string.
    pub fn is_set(&self, name: &str) -> bool {
        match self.get(name) {
            None => false,
            Some(Value::Regexp(_) | Value::Str(_)) => true,
            Some(Value::Double(d)) => d != 0.0,
            Some(Value::Bool(b)) => b,
        }
    }

    /// getString(): the text of a string or match, else "".
    pub fn string(&self, name: &str) -> String {
        match self.get(name) {
            Some(Value::Regexp(s) | Value::Str(s)) => s,
            _ => String::new(),
        }
    }

    /// getDouble(): 0 for anything that isn't a number.
    pub fn double(&self, name: &str) -> f64 {
        match self.get(name) {
            Some(Value::Double(d)) => d,
            _ => 0.0,
        }
    }

    /// toDouble(): a number, or a string or match that is one in full.
    pub fn to_double(&self, name: &str) -> Option<f64> {
        match self.get(name)? {
            Value::Double(d) => Some(d),
            Value::Bool(b) => Some(b as u8 as f64),
            // An empty string or match is no number.
            Value::Regexp(s) | Value::Str(s) => s.trim_start().parse().ok(),
        }
    }

    /// [$name]: a zero number renders empty and an unset bool as "false".
    pub fn render(&self, name: &str) -> String {
        match self.get(name) {
            Some(Value::Regexp(s) | Value::Str(s)) => s,
            Some(Value::Double(d)) if d != 0.0 => format!("{d:.6}"),
            Some(Value::Bool(true)) => "true".into(),
            Some(Value::Bool(false)) => "false".into(),
            _ => String::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_empty_string_is_no_double() {
        let mut v = Vars::default();
        v.set_string("empty", "");
        v.set_regexp("m", "");
        v.set_string("n", " 2.5");
        assert_eq!((v.to_double("empty"), v.to_double("m"), v.to_double("n")), (None, None, Some(2.5)));
    }

    #[test]
    fn set_and_render_like_sipp() {
        let mut v = Vars::default();
        v.set_double("zero", 0.0);
        v.set_double("one", 1.0);
        v.set_string("empty", "");
        v.set_bool("no", false);
        v.set_regexp("_", "ignored");
        assert!(!v.is_set("zero") && v.is_set("one") && v.is_set("empty") && !v.is_set("no"));
        assert!(!v.is_set("_") && !v.is_set("missing"));
        assert_eq!(v.render("zero"), "");
        assert_eq!(v.render("one"), "1.000000");
        assert_eq!(v.render("no"), "false");
        assert_eq!(v.double("empty"), 0.0);
    }

    #[test]
    fn global_and_user_variables_are_shared() {
        let scopes = Scopes::new(["g".to_string()].into(), ["u".to_string()].into());
        let alice = Table::default();
        let mut a1 = Vars::new(scopes.clone(), Some(alice.clone()));
        let mut b = Vars::new(scopes.clone(), None);
        a1.set_double("g", 1.0);
        a1.set_double("u", 2.0);
        a1.set_double("c", 3.0);
        assert_eq!((b.double("g"), b.double("u"), b.double("c")), (1.0, 0.0, 0.0));
        b.set_double("g", 4.0);
        let a2 = Vars::new(scopes, Some(alice));
        assert_eq!((a2.double("g"), a2.double("u"), a2.double("c")), (4.0, 2.0, 0.0));
    }
}
