//! The coordinator/worker protocol: one length-prefixed frame per message, the first byte its tag.
//!
//! The coordinator keeps one connection per worker and sends it one task at a time. A task names its children by
//! node id and the address of the worker holding each; the worker fetches them from those peers itself, so proofs
//! move worker to worker as they would between machines, and every byte is counted.

use crate::api::{GuestKind, Leaf, RawSig};
use crate::wire::{Reader, Writer, get_claims, get_leaf, get_sigs, put_claims, put_leaf, put_sigs};
use rec_aggregation::EthereumClaims;
use std::io;

pub const HELLO: u8 = 1;
pub const INFO: u8 = 2;
pub const TASK: u8 = 3;
pub const DONE: u8 = 4;
pub const FETCH: u8 = 5;
pub const PROOF: u8 = 6;
pub const RESET: u8 = 7;
pub const SHUTDOWN: u8 = 8;

pub struct Child {
    pub id: u64,
    /// `host:port` of the worker holding it.
    pub addr: String,
}

pub struct Task {
    pub id: u64,
    pub guest: GuestKind,
    pub finalize: bool,
    pub leaves: Vec<Leaf>,
    pub sigs: Vec<RawSig>,
    pub children: Vec<Child>,
    /// `None` publishes the union of what the inputs establish.
    pub declare: Option<EthereumClaims>,
    pub sources: Vec<([u8; 32], [u8; 32])>,
}

#[derive(Debug, Default, Clone, PartialEq)]
pub struct Done {
    pub id: u64,
    pub error: String,
    pub fetch_s: f64,
    pub decode_s: f64,
    pub prove_s: f64,
    pub cycles: u64,
    pub log_committed: f64,
    pub proof_bytes: u64,
    pub claims_bytes: u64,
    pub fetched_bytes: u64,
    pub peak_rss: u64,
}

pub fn encode_task(t: &Task) -> Vec<u8> {
    let mut w = Writer::default();
    w.u8(TASK)
        .u64(t.id)
        .u8(t.guest.index())
        .u8(t.finalize as u8);
    w.u32(t.leaves.len() as u32);
    for l in &t.leaves {
        put_leaf(&mut w, l);
    }
    put_sigs(&mut w, &t.sigs);
    w.u32(t.children.len() as u32);
    for c in &t.children {
        w.u64(c.id).str(&c.addr);
    }
    match &t.declare {
        Some(d) => {
            w.u8(1);
            put_claims(&mut w, d);
        }
        None => {
            w.u8(0);
        }
    }
    w.u32(t.sources.len() as u32);
    for (a, b) in &t.sources {
        w.fixed(a).fixed(b);
    }
    w.buf
}

/// Decodes a task frame after its tag byte.
pub fn decode_task(r: &mut Reader) -> io::Result<Task> {
    let id = r.u64()?;
    let guest = GuestKind::from_index(r.u8()?)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "guest"))?;
    let finalize = r.u8()? != 0;
    let n = r.count(36)?;
    let leaves = (0..n).map(|_| get_leaf(r)).collect::<io::Result<_>>()?;
    let sigs = get_sigs(r)?;
    let n = r.count(12)?;
    let children = (0..n)
        .map(|_| {
            Ok(Child {
                id: r.u64()?,
                addr: r.str()?,
            })
        })
        .collect::<io::Result<_>>()?;
    let declare = if r.u8()? == 1 {
        Some(get_claims(r)?)
    } else {
        None
    };
    let n = r.count(64)?;
    let sources = (0..n)
        .map(|_| Ok((r.fixed()?, r.fixed()?)))
        .collect::<io::Result<_>>()?;
    r.end()?;
    Ok(Task {
        id,
        guest,
        finalize,
        leaves,
        sigs,
        children,
        declare,
        sources,
    })
}

pub fn encode_done(d: &Done) -> Vec<u8> {
    let mut w = Writer::default();
    w.u8(DONE)
        .u64(d.id)
        .str(&d.error)
        .f64(d.fetch_s)
        .f64(d.decode_s)
        .f64(d.prove_s);
    w.u64(d.cycles)
        .f64(d.log_committed)
        .u64(d.proof_bytes)
        .u64(d.claims_bytes)
        .u64(d.fetched_bytes)
        .u64(d.peak_rss);
    w.buf
}

pub fn decode_done(r: &mut Reader) -> io::Result<Done> {
    let d = Done {
        id: r.u64()?,
        error: r.str()?,
        fetch_s: r.f64()?,
        decode_s: r.f64()?,
        prove_s: r.f64()?,
        cycles: r.u64()?,
        log_committed: r.f64()?,
        proof_bytes: r.u64()?,
        claims_bytes: r.u64()?,
        fetched_bytes: r.u64()?,
        peak_rss: r.u64()?,
    };
    r.end()?;
    Ok(d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tasks_and_results_round_trip() {
        let t = Task {
            id: 9,
            guest: GuestKind::Batched,
            finalize: true,
            leaves: vec![Leaf {
                claims: vec![[1; 32]],
                vk: [2; 32],
                witness: vec![3; 10],
            }],
            sigs: vec![],
            children: vec![Child {
                id: 4,
                addr: "127.0.0.1:1".into(),
            }],
            declare: Some(EthereumClaims {
                generic: vec![([5; 32], [6; 32])],
                ..Default::default()
            }),
            sources: vec![([7; 32], [8; 32])],
        };
        let bytes = encode_task(&t);
        let mut r = Reader::new(&bytes);
        assert_eq!(r.u8().unwrap(), TASK);
        let u = decode_task(&mut r).unwrap();
        assert_eq!(
            (
                u.id,
                u.guest,
                u.finalize,
                u.leaves,
                u.children[0].addr.clone()
            ),
            (9, t.guest, true, t.leaves, t.children[0].addr.clone())
        );
        assert_eq!((u.declare, u.sources), (t.declare, t.sources));
        let d = Done {
            id: 3,
            error: "e".into(),
            prove_s: 1.5,
            proof_bytes: 7,
            ..Default::default()
        };
        let bytes = encode_done(&d);
        let mut r = Reader::new(&bytes);
        assert_eq!(r.u8().unwrap(), DONE);
        assert_eq!(decode_done(&mut r).unwrap(), d);
    }
}
