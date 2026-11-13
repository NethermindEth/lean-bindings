//! A proving worker: `calib-worker LISTEN [ADVERTISE]`.
//!
//! Proves one task at a time for the coordinator, fetching each child proof from the worker that holds it, and serves
//! its own finished proofs to peers. `LEANVM_NUM_THREADS` sets its prover threads. `ADVERTISE` is the `host:port`
//! peers reach it at (default `LISTEN`).

use gas_calibration::api;
use gas_calibration::proto::{self, Done, Task};
use gas_calibration::wire::{Reader, Writer, get_claims, put_claims, read_frame, write_frame};
use gas_calibration::{capabilities, sys};
use rec_aggregation::EthereumClaims;
use std::collections::HashMap;
use std::io;
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::Instant;

#[global_allocator]
static ALLOC: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

/// Finished proofs by node id: the proof's wire bytes and its encoded claims.
type Store = Arc<Mutex<HashMap<u64, Arc<(Vec<u8>, Vec<u8>)>>>>;

struct Worker {
    advertise: String,
    store: Store,
    prover: Mutex<()>,
}

fn fetch(addr: &str, id: u64) -> io::Result<(Vec<u8>, Vec<u8>)> {
    let mut s = TcpStream::connect(addr)?;
    s.set_nodelay(true)?;
    let mut w = Writer::default();
    w.u8(proto::FETCH).u64(id);
    write_frame(&mut s, &w.buf)?;
    let frame = read_frame(&mut s)?;
    let mut r = Reader::new(&frame);
    if r.u8()? != proto::PROOF || r.u8()? != 1 {
        return Err(io::Error::other(format!(
            "worker {addr} does not hold node {id}"
        )));
    }
    Ok((r.bytes()?.to_vec(), r.bytes()?.to_vec()))
}

fn union(children: &[rec_aggregation::EthereumProof]) -> EthereumClaims {
    let mut out = EthereumClaims::default();
    for c in children {
        out.generic.extend(c.claims().generic.iter().copied());
        out.lean_sphincs
            .extend(c.claims().lean_sphincs.iter().copied());
    }
    out.generic.sort();
    out.generic.dedup();
    out.lean_sphincs.sort();
    out.lean_sphincs.dedup();
    out
}

impl Worker {
    fn run(&self, task: Task) -> Done {
        let _one_at_a_time = self.prover.lock().unwrap();
        let mut done = Done {
            id: task.id,
            ..Default::default()
        };
        let start = Instant::now();
        let mut raw = Vec::with_capacity(task.children.len());
        for c in &task.children {
            if c.addr == self.advertise {
                let held = self.store.lock().unwrap().get(&c.id).cloned();
                match held {
                    Some(p) => raw.push((p.0.clone(), p.1.clone())),
                    None => {
                        return Done {
                            error: format!("node {} is not here", c.id),
                            ..done
                        };
                    }
                }
            } else {
                match fetch(&c.addr, c.id) {
                    Ok(p) => {
                        done.fetched_bytes += (p.0.len() + p.1.len()) as u64;
                        raw.push(p);
                    }
                    Err(e) => {
                        return Done {
                            error: e.to_string(),
                            ..done
                        };
                    }
                }
            }
        }
        done.fetch_s = start.elapsed().as_secs_f64();
        let start = Instant::now();
        let mut children = Vec::with_capacity(raw.len());
        for (bytes, claims) in &raw {
            let claims = match get_claims(&mut Reader::new(claims)) {
                Ok(c) => c,
                Err(e) => {
                    return Done {
                        error: e.to_string(),
                        ..done
                    };
                }
            };
            match api::proof_from_bytes(task.guest, bytes, claims) {
                Ok(p) => children.push(p),
                Err(e) => return Done { error: e, ..done },
            }
        }
        drop(raw);
        done.decode_s = start.elapsed().as_secs_f64();
        let start = Instant::now();
        let result = if task.finalize {
            let declare = task.declare.clone().unwrap_or_else(|| union(&children));
            api::finalize(&children, task.leaves, task.sigs, &declare, &task.sources)
        } else {
            api::prove(
                task.guest,
                &children,
                task.leaves,
                task.sigs,
                task.declare.as_ref(),
            )
        };
        done.prove_s = start.elapsed().as_secs_f64();
        match result {
            Ok((proof, stats)) => {
                let bytes = api::proof_bytes(&proof);
                let mut w = Writer::default();
                put_claims(&mut w, proof.claims());
                done.cycles = stats.cycles as u64;
                done.log_committed = (stats.committed.max(1) as f64).log2();
                done.proof_bytes = bytes.len() as u64;
                done.claims_bytes = w.buf.len() as u64;
                self.store
                    .lock()
                    .unwrap()
                    .insert(task.id, Arc::new((bytes, w.buf)));
            }
            Err(e) => done.error = e,
        }
        done.peak_rss = sys::peak_rss_bytes();
        done
    }

    fn serve(self: Arc<Self>, mut s: TcpStream) -> io::Result<()> {
        s.set_nodelay(true)?;
        loop {
            let frame = match read_frame(&mut s) {
                Ok(f) => f,
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(()),
                Err(e) => return Err(e),
            };
            let mut r = Reader::new(&frame);
            match r.u8()? {
                proto::HELLO => {
                    let mut w = Writer::default();
                    let (total, avail) = sys::memory_bytes();
                    w.u8(proto::INFO)
                        .str(&self.advertise)
                        .str(&capabilities())
                        .u64(total)
                        .u64(avail);
                    write_frame(&mut s, &w.buf)?;
                }
                proto::RESET => {
                    self.store.lock().unwrap().clear();
                    write_frame(&mut s, &[proto::RESET])?;
                }
                proto::TASK => {
                    let done = match proto::decode_task(&mut r) {
                        Ok(task) => self.run(task),
                        Err(e) => Done {
                            error: format!("bad task: {e}"),
                            ..Default::default()
                        },
                    };
                    write_frame(&mut s, &proto::encode_done(&done))?;
                }
                proto::FETCH => {
                    let id = r.u64()?;
                    let held = self.store.lock().unwrap().get(&id).cloned();
                    let mut w = Writer::default();
                    w.u8(proto::PROOF);
                    match held {
                        Some(p) => w.u8(1).bytes(&p.0).bytes(&p.1),
                        None => w.u8(0),
                    };
                    write_frame(&mut s, &w.buf)?;
                }
                proto::SHUTDOWN => std::process::exit(0),
                t => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("unknown message {t}"),
                    ));
                }
            }
        }
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some(listen) = args.first() else {
        eprintln!("usage: calib-worker LISTEN [ADVERTISE]");
        std::process::exit(2)
    };
    let advertise = args.get(1).unwrap_or(listen).clone();
    api::warm_up();
    let listener = TcpListener::bind(listen).expect("binds the listen address");
    eprintln!(
        "calib-worker ready on {listen} as {advertise}: {}",
        capabilities()
    );
    let worker = Arc::new(Worker {
        advertise,
        store: Store::default(),
        prover: Mutex::new(()),
    });
    for stream in listener.incoming() {
        let Ok(stream) = stream else { continue };
        let w = worker.clone();
        std::thread::spawn(move || {
            if let Err(e) = w.serve(stream) {
                eprintln!("connection closed: {e}");
            }
        });
    }
}
