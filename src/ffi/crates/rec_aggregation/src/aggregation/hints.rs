//! Hint streams and the raw signatures' witnesses.

use super::error::AggregationError;
use lean_sphincs::{LeanSphincsPublicKey, LeanSphincsSignature};
use leanvm_core::cpu::Program;
use primitives::field::F128;

/// Named hint entries for a single sub-proof, ordered within each stream.
pub(super) type SubHints = Vec<(&'static str, Vec<F128>)>;

/// An edit to a node's hints: how a test hands the guest a witness the honest host
/// would not.
#[cfg(test)]
pub(super) type Forgery = Box<dyn FnOnce(&mut Hints)>;

#[cfg(test)]
thread_local! {
    /// The forgery the next node this thread aggregates gets.
    pub(super) static FORGE: std::cell::RefCell<Option<Forgery>> = const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
thread_local! {
    /// Lets the next nodes this thread aggregates take more batch leaves than the cap and invalid claim lists, to see the
    /// guest refuse them.
    pub(super) static SKIP_LEAF_CHECKS: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    /// An honest leanSTARK `(statement, witness)` whose proof the next nodes' leanSTARK sub-proof hints
    /// come from, whatever claim and witness they are handed: how a test shows the guest a false claim.
    pub(super) static HONEST_GENERIC: std::cell::RefCell<Option<([u8; 32], Vec<u8>)>> = const { std::cell::RefCell::new(None) };
    /// The IV a forged leanSTARK proof was made under: its hints are replayed under it, unchecked.
    pub(super) static FORGED_IV: std::cell::Cell<Option<[u8; 32]>> = const { std::cell::Cell::new(None) };
}

/// One `hint_witness` stream: a name and its entries, in the order the guest
/// pops them.
#[derive(Default)]
pub(super) struct Hints(Vec<(String, Vec<Vec<F128>>)>);

impl Hints {
    pub(super) fn push(&mut self, name: &str, entry: Vec<F128>) {
        match self.0.iter_mut().find(|(n, _)| n == name) {
            Some((_, entries)) => entries.push(entry),
            None => self.0.push((name.to_string(), vec![entry])),
        }
    }

    /// Entry `i` of stream `name`, for a test to forge.
    #[cfg(test)]
    pub(super) fn entry_mut(&mut self, name: &str, i: usize) -> &mut Vec<F128> {
        let (_, entries) = self.0.iter_mut().find(|(n, _)| n == name).expect("a hinted stream");
        &mut entries[i]
    }

    /// How many entries stream `name` holds, for a test to forge the last.
    #[cfg(test)]
    pub(super) fn len(&self, name: &str) -> usize {
        self.0
            .iter()
            .find(|(n, _)| n == name)
            .map_or(0, |(_, entries)| entries.len())
    }

    pub(super) fn install(self, guest: &mut Program) {
        for (name, entries) in self.0 {
            guest.set_witness(name, entries);
        }
    }
}

/// One leanSPHINCS signature's witness: the hook the guest's `verify_sig_lean_sphincs` reads its streams through.
///
/// A stub until the guest verifies the NiceTry v2 scheme over the 128-bit field again: the guest refuses every raw
/// leanSPHINCS signature, so this builds no witness and refuses it first.
pub(super) fn lean_sphincs_hints(
    _pk: &LeanSphincsPublicKey,
    _sig: &LeanSphincsSignature,
    _message: &lean_sphincs::Message,
) -> Result<SubHints, AggregationError> {
    Err(AggregationError::MalformedRawSignature)
}
