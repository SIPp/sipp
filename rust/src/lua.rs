//! Lua scripting: -lua_file loads a Lua file, and <exec lua="function arg
//! ..."/> calls one of its functions, which reads and writes the call's
//! variables with sipp.get and sipp.set, as C SIPp's luascript.cpp does.
//! Without the `lua` feature both are errors.

use crate::vars::Vars;
use std::collections::HashSet;

/// -v shows it, as C does.
pub const BUILT_IN: bool = cfg!(feature = "lua");

#[cfg(feature = "lua")]
mod imp {
    use super::*;
    use crate::vars::Value;
    use mlua::{Function, Lua, Result as LuaResult};
    use std::cell::RefCell;

    thread_local! {
        /// The one Lua state: its globals are the same for every call.
        static STATE: RefCell<Option<Lua>> = const { RefCell::new(None) };
    }

    /// What C's lua_pcall() returns: the message, with no traceback.
    fn message(e: &mlua::Error) -> String {
        match e {
            mlua::Error::CallbackError { cause, .. } => message(cause),
            mlua::Error::RuntimeError(m) => m.split("\nstack traceback:").next().unwrap_or(m).to_string(),
            e => e.to_string(),
        }
    }

    /// luaL_error(): "file:line:" of the Lua function that called us, then
    /// the text.
    fn error(lua: &Lua, text: String) -> mlua::Error {
        let at = lua.inspect_stack(1, |d| d.current_line().map(|l| format!("{}:{l}: ", d.source().short_src.unwrap_or_default())));
        mlua::Error::runtime(format!("{}{text}", at.flatten().unwrap_or_default()))
    }

    pub fn load(file: &str) -> Result<(), String> {
        let lua = Lua::new();
        let code = std::fs::read(file).map_err(|e| format!("Lua file {file}: cannot open {file}: {}", crate::net::os_error(&e)))?;
        // chunk names as luaL_dofile() gives them: the file name.
        lua.load(code).set_name(format!("@{file}")).exec().map_err(|e| format!("Lua file {file}: {}", message(&e)))?;
        STATE.set(Some(lua));
        Ok(())
    }

    pub fn exec(command: &str, vars: &mut Vars, names: &HashSet<String>, log: &mut dyn FnMut(&str)) -> Result<(), String> {
        let mut words = command.split_whitespace();
        let function = words.next().unwrap_or("");
        STATE.with_borrow(|state| {
            let Some(lua) = state.as_ref().filter(|_| !function.is_empty()) else {
                return Err(format!("<exec lua=\"{command}\"> needs a function name, and a Lua file with it given with -lua_file"));
            };
            let Ok(f) = lua.globals().get::<Function>(function) else {
                return Err(format!("Lua function {function} is not defined"));
            };
            let args = mlua::Variadic::from_iter(words.map(str::to_string));
            let (vars, log) = (RefCell::new(vars), RefCell::new(log));
            let known = |lua: &Lua, name: &str| -> LuaResult<()> {
                match names.contains(name) {
                    true => Ok(()),
                    false => Err(error(lua, format!("unknown SIPp variable '{name}'"))),
                }
            };
            lua.scope(|scope| {
                let sipp = lua.create_table()?;
                // sipp.get(name): the value, or nil if it has none.
                sipp.set(
                    "get",
                    scope.create_function(|lua, name: String| {
                        known(lua, &name)?;
                        Ok(match vars.borrow().get(&name) {
                            Some(Value::Regexp(s) | Value::Str(s)) => mlua::Value::String(lua.create_string(s)?),
                            Some(Value::Double(d)) => mlua::Value::Number(d),
                            Some(Value::Bool(b)) => mlua::Value::Boolean(b),
                            None => mlua::Value::Nil,
                        })
                    })?,
                )?;
                // sipp.set(name, value): a string, a number or a boolean.
                sipp.set(
                    "set",
                    scope.create_function(|lua, (name, value): (String, mlua::Value)| {
                        known(lua, &name)?;
                        let mut vars = vars.borrow_mut();
                        match value {
                            // A C string ends at its NUL.
                            mlua::Value::String(s) => vars.set_string(&name, s.to_string_lossy().split('\0').next().unwrap_or("")),
                            mlua::Value::Integer(n) => vars.set_double(&name, n as f64),
                            mlua::Value::Number(n) => vars.set_double(&name, n),
                            mlua::Value::Boolean(b) => vars.set_bool(&name, b),
                            _ => return Err(error(lua, "SIPp variables hold a string, a number or a boolean".into())),
                        }
                        Ok(())
                    })?,
                )?;
                // sipp.log(message): the -trace_logs file, as <log> does.
                sipp.set("log", scope.create_function(|_, msg: String| {
                    (*log.borrow_mut())(&msg);
                    Ok(())
                })?)?;
                lua.globals().set("sipp", sipp)?;
                f.call::<()>(args)
            })
            .map_err(|e| format!("Lua function {function}: {}", message(&e)))
        })
    }
}

#[cfg(feature = "lua")]
pub use imp::{exec, load};

#[cfg(not(feature = "lua"))]
pub fn load(_: &str) -> Result<(), String> {
    Err("-lua_file given, but this version of SIPp does not have Lua support".into())
}

#[cfg(not(feature = "lua"))]
pub fn exec(_: &str, _: &mut Vars, _: &HashSet<String>, _: &mut dyn FnMut(&str)) -> Result<(), String> {
    Err("Scenario specifies a lua action, but this version of SIPp does not have Lua support".into())
}
