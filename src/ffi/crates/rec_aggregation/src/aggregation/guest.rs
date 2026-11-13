//! Compiling the guest to a fixed point on its own size.

use super::deferred::{scalar_bytecode, stacked_bytecode};
use super::generic::MAX_CLAIMS_PER_BATCH_LEAF;
use super::placeholders::placeholder_map;
use lean_compiler::{compile, parse_with_replacements};
use leanvm_core::cpu::Program;

/// Which aggregation program a proof is of. Both compile from one source, so each has its own `AGGREGATED_VK`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum Guest {
    /// EIP-8288: each leanSTARK (`0x11`) dependency is proved by a one-claim leaf.
    #[default]
    Base,
    /// ethereum/EIPs#12664 on top of EIP-8288: leaves of up to [`MAX_CLAIMS_PER_BATCH_LEAF`] claims, which also
    /// establish `BATCHED_LEANSTARK_SCHEME` (`0x12`) dependencies.
    Batched,
}

impl Guest {
    pub(super) const fn index(self) -> usize {
        self as usize
    }

    /// The most claims one leaf proves.
    pub const fn max_claims_per_leaf(self) -> usize {
        match self {
            Self::Base => 1,
            Self::Batched => MAX_CLAIMS_PER_BATCH_LEAF,
        }
    }
}

/// Build `guest`'s bytecode and the stacked table its claims are about. Both are
/// cached, so this only moves the cost out of the first prove or verify.
pub fn warm_up(guest: Guest) {
    unified_guest(guest);
    stacked_bytecode(guest);
    scalar_bytecode(guest);
}

/// The aggregation bytecode, compiled to a fixed point on its own size.
///
/// The recursion placeholders are a function of the inner bytecode's log size,
/// and here the inner bytecode is this one, so the size has to agree with
/// itself. Its *digest* needs no such loop: it rides the statement rather than
/// the code. The guess converges in one or two rounds because the map's only
/// size-dependent part is a handful of unrolled sumcheck rounds.
pub fn unified_guest(guest: Guest) -> &'static Program {
    static GUESTS: [std::sync::OnceLock<Program>; 2] = [const { std::sync::OnceLock::new() }; 2];
    GUESTS[guest.index()].get_or_init(|| {
        // A guess at the guest's own size: right, it compiles once; wrong, one more round.
        let mut guess = 19;
        for _ in 0..8 {
            let program = compile_guest(guess, guest);
            let actual = program.prog().len().trailing_zeros() as usize;
            if actual == guess {
                return program;
            }
            guess = actual;
        }
        panic!("the aggregation bytecode's self-referential compile did not converge");
    })
}

pub(super) fn compile_guest(kbc: usize, guest: Guest) -> Program {
    let replacements = placeholder_map(kbc, guest);
    // `DBG_PLACEHOLDERS=path`: dump the baked guest constants, to read alongside
    // a `DBG_PROF_DUMP` profile (the guest's shape is entirely in these).
    if let Ok(path) = std::env::var("DBG_PLACEHOLDERS") {
        let dump: String = replacements.iter().map(|(k, v)| format!("{k} = {v}\n")).collect();
        std::fs::write(&path, dump).expect("write DBG_PLACEHOLDERS");
    }
    let guest = compile(
        &parse_with_replacements(include_str!("../../guests/lean_ethereum.py"), &replacements)
            .expect("the repository aggregation guest must parse"),
    );
    // `DBG_DISASM=path`: dump the guest's disassembly, to read alongside a
    // `DBG_PROF_DUMP` per-pc profile. Function boundaries lead the dump, so the
    // pc a failed guest check reports can be resolved to a source function
    // without re-deriving the layout by hand.
    if let Ok(path) = std::env::var("DBG_DISASM") {
        let mut ranges: Vec<_> = guest.fn_ranges.iter().collect();
        ranges.sort_by_key(|(_, entry, _)| *entry);
        let mut dump = String::new();
        for (name, entry, len) in ranges {
            dump += &format!("# fn {entry:>7}..{:<7} {name}\n", entry + len);
        }
        dump += &lean_compiler::disassemble(guest.prog());
        std::fs::write(&path, dump).expect("write DBG_DISASM");
    }
    guest
}
