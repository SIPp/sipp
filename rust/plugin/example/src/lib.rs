//! An example sipp-rs plugin: `-plugin target/release/libsipp_plugin_example.so`.

use std::sync::atomic::{AtomicU64, Ordering};

fn init(p: &mut sipp_plugin::Registrar) -> Result<(), String> {
    // [shout text]: the text, rendered for the call, in capitals, as in
    // [shout [call_id]].
    p.keyword("shout", |call| call.render(call.args()).unwrap_or_else(|e| e).to_uppercase())?;
    // [sent]: how many messages used it so far, over all calls.
    static SENT: AtomicU64 = AtomicU64::new(0);
    p.keyword("sent", |_| (SENT.fetch_add(1, Ordering::Relaxed) + 1).to_string())?;
    Ok(())
}

sipp_plugin::plugin!(init);
