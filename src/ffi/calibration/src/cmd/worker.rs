//! A proving worker: `calib-worker [--remote --allow IP,...] LISTEN [ADVERTISE]`.
//!
//! Proves one task at a time for the coordinator, fetching each child proof from the worker that holds it, and serves
//! its own finished proofs to peers. `LEANVM_NUM_THREADS` sets its prover threads. `ADVERTISE` is the `host:port`
//! peers reach it at (default `LISTEN`).
//!
//! Every connection authenticates under the run key (`CALIB_TOKEN` or `CALIB_TOKEN_FILE`, see the `channel` module).
//! `LISTEN` must be a loopback address and only loopback peers connect, unless `--remote` is given with the IPs that may
//! connect (the coordinator and the other workers); others are dropped at accept, before taking a handshake slot. Children are fetched only from this worker or the
//! workers the coordinator listed in HELLO.

use gas_calibration::api;
use gas_calibration::channel::{self, Admission, Channel, Key, Slot};
use gas_calibration::proto::{self, Done, Task};
use gas_calibration::wire::{Reader, Writer, get_claims, put_claims};
use gas_calibration::{capabilities, sys};
use rec_aggregation::EthereumClaims;
use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

#[global_allocator]
static ALLOC: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

/// Authenticated connections served at once: the coordinator's and one per peer fetching, with room to spare.
const MAX_AUTHENTICATED: usize = 64;
/// Handshakes one allowlisted IP may have open at once.
const HANDSHAKES_PER_IP: usize = 4;
/// The whole handshake, not each read, must finish within this.
const HANDSHAKE_LIMIT: Duration = Duration::from_secs(5);

/// Finished proofs by node id: the proof's wire bytes and its encoded claims.
type Store = Arc<Mutex<HashMap<u64, Arc<(Vec<u8>, Vec<u8>)>>>>;

struct Worker {
    advertise: String,
    key: Key,
    peers: RwLock<Vec<String>>,
    store: Store,
    prover: Mutex<()>,
    authenticated: AtomicUsize,
}

fn fetch(key: Key, addr: &str, id: u64) -> io::Result<(Vec<u8>, Vec<u8>)> {
    let s = TcpStream::connect(addr)?;
    s.set_nodelay(true)?;
    let mut c = Channel::client(s, key)?;
    let mut w = Writer::default();
    w.u8(proto::FETCH).u64(id);
    c.send(&w.buf)?;
    let frame = c.recv()?;
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
        let fail = |done: Done, error: String| Done { error, ..done };
        let start = Instant::now();
        let mut raw = Vec::with_capacity(task.children.len());
        for c in &task.children {
            if !proto::child_allowed(&c.addr, &self.advertise, &self.peers.read().unwrap()) {
                return fail(done, format!("{} is not a listed worker", c.addr));
            }
            if c.addr == self.advertise {
                match self.store.lock().unwrap().get(&c.id).cloned() {
                    Some(p) => raw.push((p.0.clone(), p.1.clone())),
                    None => return fail(done, format!("node {} is not here", c.id)),
                }
            } else {
                match fetch(self.key, &c.addr, c.id) {
                    Ok(p) => {
                        done.fetched_bytes += (p.0.len() + p.1.len()) as u64;
                        raw.push(p);
                    }
                    Err(e) => return fail(done, e.to_string()),
                }
            }
        }
        done.fetch_s = start.elapsed().as_secs_f64();
        let start = Instant::now();
        let mut children = Vec::with_capacity(raw.len());
        for (bytes, claims) in &raw {
            let claims = match get_claims(&mut Reader::new(claims)) {
                Ok(c) => c,
                Err(e) => return fail(done, e.to_string()),
            };
            match api::proof_from_bytes(task.guest, bytes, claims) {
                Ok(p) => children.push(p),
                Err(e) => return fail(done, e),
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

    /// Authenticates a connection (it holds a handshake slot until here), then serves it in an authenticated slot.
    fn serve(self: Arc<Self>, s: TcpStream, slot: Slot<'_>) -> io::Result<()> {
        let handshake = s
            .set_nodelay(true)
            .and_then(|_| Channel::server(s, self.key, HANDSHAKE_LIMIT));
        drop(slot);
        let c = handshake?;
        if self.authenticated.fetch_add(1, Ordering::SeqCst) >= MAX_AUTHENTICATED {
            self.authenticated.fetch_sub(1, Ordering::SeqCst);
            return Err(io::Error::other("too many connections"));
        }
        let result = self.clone().session(c);
        self.authenticated.fetch_sub(1, Ordering::SeqCst);
        result
    }

    fn session(self: Arc<Self>, mut c: Channel<TcpStream>) -> io::Result<()> {
        loop {
            let frame = match c.recv() {
                Ok(f) => f,
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(()),
                Err(e) => return Err(e),
            };
            let mut r = Reader::new(&frame);
            match r.u8()? {
                proto::HELLO => {
                    *self.peers.write().unwrap() = proto::decode_hello(&mut r)?;
                    let mut w = Writer::default();
                    let (total, avail) = sys::memory_bytes();
                    w.u8(proto::INFO)
                        .str(&self.advertise)
                        .str(&capabilities())
                        .u64(total)
                        .u64(avail);
                    c.send(&w.buf)?;
                }
                proto::RESET => {
                    self.store.lock().unwrap().clear();
                    c.send(&[proto::RESET])?;
                }
                proto::TASK => {
                    let done = match proto::decode_task(&mut r) {
                        Ok(task) => self.run(task),
                        Err(e) => Done {
                            error: format!("bad task: {e}"),
                            ..Default::default()
                        },
                    };
                    c.send(&proto::encode_done(&done))?;
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
                    c.send(&w.buf)?;
                }
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
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    let mut allow: Vec<IpAddr> = vec![];
    let remote = args.first().is_some_and(|a| a == "--remote");
    if remote {
        args.remove(0);
        if args.len() < 2 || args[0] != "--allow" {
            eprintln!(
                "calib-worker: --remote needs --allow IP[,IP...] (the coordinator and the other workers)"
            );
            std::process::exit(2);
        }
        allow = args[1]
            .split(',')
            .map(|ip| {
                ip.trim().parse().unwrap_or_else(|_| {
                    eprintln!("calib-worker: {ip} is not an IP address");
                    std::process::exit(2)
                })
            })
            .collect();
        args.drain(..2);
    }
    let Some(listen) = args.first().cloned() else {
        eprintln!("usage: calib-worker [--remote --allow IP,...] LISTEN [ADVERTISE]");
        std::process::exit(2)
    };
    let loopback = listen
        .parse::<SocketAddr>()
        .is_ok_and(|a| a.ip().is_loopback());
    if !loopback && !remote {
        eprintln!(
            "calib-worker: {listen} is not a loopback address; pass --remote to listen on a network"
        );
        std::process::exit(2);
    }
    let key = channel::key_from_env().unwrap_or_else(|e| {
        eprintln!("calib-worker: {e}");
        std::process::exit(2)
    });
    let advertise = args.get(1).unwrap_or(&listen).clone();
    api::warm_up();
    let listener = TcpListener::bind(&listen).expect("binds the listen address");
    eprintln!(
        "calib-worker ready on {listen} as {advertise}: {}",
        capabilities()
    );
    let worker = Arc::new(Worker {
        advertise,
        key,
        peers: RwLock::new(vec![]),
        store: Store::default(),
        prover: Mutex::new(()),
        authenticated: AtomicUsize::new(0),
    });
    let admission: &'static Admission =
        Box::leak(Box::new(Admission::new(allow, HANDSHAKES_PER_IP)));
    for stream in listener.incoming() {
        let Ok(stream) = stream else { continue };
        // Refused before any slot is taken: peers off the allowlist, and an allowlisted IP's surplus handshakes.
        let Some(slot) = stream
            .peer_addr()
            .ok()
            .and_then(|a| admission.admit(a.ip()))
        else {
            continue;
        };
        let w = worker.clone();
        std::thread::spawn(move || {
            if let Err(e) = w.serve(stream, slot) {
                eprintln!("connection closed: {e}");
            }
        });
    }
}
