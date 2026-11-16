//! Activation gas calibration for EIP-8288 and the batch-pricing draft (ethereum/EIPs#12664).
//!
//! The binaries measure single aggregation steps (`calib-node`) and whole blocks proved by a coordinator across
//! workers (`calib-coord`, `calib-worker`); `calib.py` turns the measurements into constants and checks them.

pub mod api;
pub mod channel;
pub mod inputs;
pub mod json;
pub mod proto;
pub mod sched;
pub mod sys;
pub mod wire;

/// A JSON object of what this build supports, for every result's header.
pub fn capabilities() -> String {
    let mut o = json::Obj::default();
    o.bool("batch", api::BATCH)
        .bool("committed", api::COMMITTED)
        .num(
            "library_max_inner_proofs_per_step",
            api::library_max_inner_proofs_per_step(),
        )
        .num(
            "max_claims_per_batched_leaf",
            api::max_claims_per_leaf(api::GuestKind::Batched),
        )
        .num("outer_log_inv_rate", api::OUTER_LOG_INV_RATE)
        .num("threads", sys::threads())
        .num("mem_total", sys::memory_bytes().0)
        .str("host", &sys::hostname())
        .str("os", std::env::consts::OS)
        .str("arch", std::env::consts::ARCH);
    o.finish()
}
