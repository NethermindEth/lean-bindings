//! Proves one block across workers and measures it: `calib-coord PLAN WORKERS OUT`.
//!
//! `WORKERS` is a comma-separated list of `host:port`. `PLAN` has one directive a line:
//!
//! ```text
//! label NAME
//! guest base|batched
//! fanin F
//! max_inner N          MAX_INNER_PROOFS_PER_STEP the plan must respect
//! sigs_per_node L
//! sigs FILE [COUNT]
//! generic FILE         one leaf, its claims as ordinary leanSTARK dependencies
//! batch FILE RETAIN    one sponsored leaf: its first RETAIN claims and its payment
//! ```
//!
//! The makespan is wall-clock time from the first dispatch to the root's completion, transfers included; the root is
//! then fetched and verified natively (the validator's verification). The output JSON also carries a list schedule of
//! the measured node times without transfers, labelled as modelled.

use gas_calibration::api::{self, GuestKind, Leaf, RawSig};
use gas_calibration::json::{Obj, array};
use gas_calibration::proto::{self, Child, Done, Task};
use gas_calibration::sched::{self, Input, PlanSpec, Scheduler};
use gas_calibration::wire::{Reader, Writer, get_claims, read_frame, write_frame};
use gas_calibration::{capabilities, inputs, sys};
use rec_aggregation::EthereumClaims;
use std::net::TcpStream;
use std::sync::mpsc;
use std::time::Instant;

#[global_allocator]
static ALLOC: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

enum File {
    Leaf(Leaf),
    Sigs(Vec<RawSig>),
}

struct Plan {
    label: String,
    guest: GuestKind,
    spec: PlanSpec,
    files: Vec<(String, File)>,
}

fn parse_plan(text: &str) -> Result<Plan, String> {
    let mut plan = Plan {
        label: "block".into(),
        guest: GuestKind::Base,
        spec: PlanSpec {
            sigs: vec![],
            generic: vec![],
            batch: vec![],
            sigs_per_node: 64,
            fanin: 4,
            max_inner_proofs_per_step: 16,
            finalize: false,
        },
        files: vec![],
    };
    for (n, line) in text.lines().enumerate() {
        let w: Vec<&str> = line.split_whitespace().collect();
        if w.is_empty() || w[0].starts_with('#') {
            continue;
        }
        let bad = || format!("plan line {}: {line}", n + 1);
        let num = |i: usize| {
            w.get(i)
                .and_then(|v| v.parse::<usize>().ok())
                .ok_or_else(bad)
        };
        let path = |i: usize| w.get(i).map(|s| s.to_string()).ok_or_else(bad);
        match w[0] {
            "label" => plan.label = path(1)?,
            "guest" => {
                plan.guest = match w.get(1) {
                    Some(&"base") => GuestKind::Base,
                    Some(&"batched") => GuestKind::Batched,
                    _ => return Err(bad()),
                }
            }
            "fanin" => plan.spec.fanin = num(1)?,
            "max_inner" => plan.spec.max_inner_proofs_per_step = num(1)?,
            "sigs_per_node" => plan.spec.sigs_per_node = num(1)?,
            "sigs" => {
                let p = path(1)?;
                let mut sigs = inputs::read_sigs_file(&p).map_err(|e| format!("{p}: {e}"))?;
                if w.len() > 2 {
                    let c = num(2)?;
                    if c > sigs.len() {
                        return Err(format!("{p} holds {} signatures, {c} asked", sigs.len()));
                    }
                    sigs.truncate(c);
                }
                plan.spec.sigs.push((plan.files.len(), sigs.len()));
                plan.files.push((p, File::Sigs(sigs)));
            }
            "generic" | "batch" => {
                let p = path(1)?;
                let leaf = inputs::read_leaf_file(&p).map_err(|e| format!("{p}: {e}"))?;
                if w[0] == "generic" {
                    plan.spec.generic.push(plan.files.len());
                } else {
                    let retain = num(2)?;
                    if retain > leaf.claims.len() {
                        return Err(bad());
                    }
                    plan.spec.batch.push((plan.files.len(), retain));
                }
                plan.files.push((p, File::Leaf(leaf)));
            }
            _ => return Err(bad()),
        }
    }
    plan.spec.finalize = !plan.spec.batch.is_empty();
    if plan.spec.finalize && plan.guest != GuestKind::Batched {
        return Err("batch leaves need `guest batched`".into());
    }
    Ok(plan)
}

struct WorkerConn {
    addr: String,
    info: String,
    mem_total: u64,
    stream: TcpStream,
}

fn connect(addr: &str) -> Result<WorkerConn, String> {
    let mut stream = TcpStream::connect(addr).map_err(|e| format!("{addr}: {e}"))?;
    stream.set_nodelay(true).ok();
    write_frame(&mut stream, &[proto::HELLO]).map_err(|e| e.to_string())?;
    let frame = read_frame(&mut stream).map_err(|e| e.to_string())?;
    let mut r = Reader::new(&frame);
    let parse = |r: &mut Reader| -> std::io::Result<(String, String, u64)> {
        if r.u8()? != proto::INFO {
            return Err(std::io::Error::other("not a worker"));
        }
        let (advertise, info, total) = (r.str()?, r.str()?, r.u64()?);
        Ok((advertise, info, total))
    };
    let (advertise, info, mem_total) = parse(&mut r).map_err(|e| format!("{addr}: {e}"))?;
    write_frame(&mut stream, &[proto::RESET]).map_err(|e| e.to_string())?;
    read_frame(&mut stream).map_err(|e| e.to_string())?;
    Ok(WorkerConn {
        addr: advertise,
        info,
        mem_total,
        stream,
    })
}

fn sponsored(leaf: &Leaf, retain: usize) -> EthereumClaims {
    let mut generic = api::batch::sponsored(leaf, &leaf.claims[..retain])
        .expect("checked: the build has batch leaves");
    generic.sort();
    EthereumClaims {
        generic,
        ..Default::default()
    }
}

fn task_for(plan: &Plan, s: &Scheduler, id: usize, addrs: &[String]) -> Task {
    let node = &s.nodes()[id];
    let mut task = Task {
        id: id as u64,
        guest: plan.guest,
        finalize: node.finalize,
        leaves: vec![],
        sigs: vec![],
        children: node
            .children
            .iter()
            .map(|&c| Child {
                id: c as u64,
                addr: addrs[s.location(c).expect("a finished child")].clone(),
            })
            .collect(),
        declare: None,
        sources: vec![],
    };
    for input in &node.inputs {
        match (
            input,
            &plan.files[match input {
                Input::Sigs { file, .. } | Input::Generic { file } | Input::Batch { file, .. } => {
                    *file
                }
            }]
            .1,
        ) {
            (Input::Sigs { from, count, .. }, File::Sigs(sigs)) => {
                task.sigs.extend_from_slice(&sigs[*from..from + count])
            }
            (Input::Generic { .. }, File::Leaf(l)) => task.leaves.push(l.clone()),
            (Input::Batch { retain, .. }, File::Leaf(l)) => {
                task.declare = Some(sponsored(l, *retain));
                task.leaves.push(l.clone());
            }
            _ => unreachable!("plan inputs match their files"),
        }
    }
    if node.finalize && !node.children.is_empty() {
        task.sources = plan
            .spec
            .batch
            .iter()
            .map(|&(f, _)| match &plan.files[f].1 {
                File::Leaf(l) => api::batch::source(l),
                File::Sigs(_) => unreachable!(),
            })
            .collect();
    }
    task
}

struct Record {
    worker: usize,
    dispatch_s: f64,
    done_s: f64,
    input_bytes: u64,
    done: Done,
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.len() != 3 {
        eprintln!("usage: calib-coord PLAN WORKERS OUT");
        std::process::exit(2);
    }
    let fail = |e: String| -> ! {
        eprintln!("calib-coord: {e}");
        std::process::exit(1)
    };
    let plan =
        parse_plan(&std::fs::read_to_string(&args[0]).unwrap_or_else(|e| fail(e.to_string())))
            .unwrap_or_else(|e| fail(e));
    if plan.guest == GuestKind::Batched && !api::BATCH {
        let mut o = Obj::default();
        o.str("label", &plan.label).str("status", "skipped").str(
            "reason",
            "the batch-pricing guest is not in this library revision",
        );
        std::fs::write(&args[2], o.finish()).ok();
        println!("skipped: no batch-pricing guest in this build");
        return;
    }
    let nodes = sched::plan(&plan.spec).unwrap_or_else(|e| fail(e));
    let mut conns: Vec<WorkerConn> = args[1]
        .split(',')
        .map(|a| connect(a).unwrap_or_else(|e| fail(e)))
        .collect();
    let addrs: Vec<String> = conns.iter().map(|c| c.addr.clone()).collect();
    let workers = conns.len();

    // One thread a worker: it sends a task, waits for the result and reports it with coordinator timestamps.
    let (result_tx, result_rx) = mpsc::channel::<(usize, Result<Done, String>, f64)>();
    let mut task_txs = Vec::new();
    let epoch = Instant::now();
    for (w, conn) in conns.iter_mut().enumerate() {
        let (tx, rx) = mpsc::channel::<Vec<u8>>();
        task_txs.push(tx);
        let mut stream = conn.stream.try_clone().expect("clones the socket");
        let results = result_tx.clone();
        std::thread::spawn(move || {
            for frame in rx {
                let reply = write_frame(&mut stream, &frame)
                    .and_then(|_| read_frame(&mut stream))
                    .map_err(|e| e.to_string());
                let done = reply.and_then(|f| {
                    let mut r = Reader::new(&f);
                    match r.u8() {
                        Ok(proto::DONE) => proto::decode_done(&mut r).map_err(|e| e.to_string()),
                        _ => Err("unexpected reply".into()),
                    }
                });
                if results
                    .send((w, done, epoch.elapsed().as_secs_f64()))
                    .is_err()
                {
                    return;
                }
            }
        });
    }

    let mut s = Scheduler::new(nodes.clone());
    let mut records: Vec<Option<Record>> = (0..nodes.len()).map(|_| None).collect();
    let mut running: Vec<Option<(usize, f64, u64)>> = vec![None; workers];
    let dispatch = |s: &mut Scheduler, running: &mut Vec<Option<(usize, f64, u64)>>| {
        for w in 0..workers {
            if running[w].is_none()
                && let Some(id) = s.next_for(w)
            {
                let frame = proto::encode_task(&task_for(&plan, s, id, &addrs));
                let len = frame.len() as u64;
                running[w] = Some((id, epoch.elapsed().as_secs_f64(), len));
                task_txs[w].send(frame).expect("the worker thread is alive");
            }
        }
    };
    let start_s = epoch.elapsed().as_secs_f64();
    dispatch(&mut s, &mut running);
    while !s.finished() {
        let (w, done, at) = result_rx.recv().expect("a worker result");
        let (id, dispatched, input_bytes) = running[w].take().expect("the worker had a task");
        let done = done.unwrap_or_else(|e| fail(format!("worker {}: {e}", addrs[w])));
        if !done.error.is_empty() {
            fail(format!(
                "node {id} ({}) on {}: {}",
                nodes[id].kind(),
                addrs[w],
                done.error
            ));
        }
        s.complete(id, w, done.proof_bytes + done.claims_bytes);
        records[id] = Some(Record {
            worker: w,
            dispatch_s: dispatched - start_s,
            done_s: at - start_s,
            input_bytes,
            done,
        });
        dispatch(&mut s, &mut running);
    }
    let makespan = epoch.elapsed().as_secs_f64() - start_s;

    // The block producer receives the root and a validator verifies it.
    let root = s.root();
    let root_worker = s.location(root).expect("the root finished");
    let mut fetch_stream =
        TcpStream::connect(&addrs[root_worker]).unwrap_or_else(|e| fail(e.to_string()));
    let mut w = Writer::default();
    w.u8(proto::FETCH).u64(root as u64);
    write_frame(&mut fetch_stream, &w.buf).unwrap_or_else(|e| fail(e.to_string()));
    let frame = read_frame(&mut fetch_stream).unwrap_or_else(|e| fail(e.to_string()));
    let mut r = Reader::new(&frame);
    let (proof, claims) = match (r.u8(), r.u8()) {
        (Ok(proto::PROOF), Ok(1)) => (r.bytes().unwrap().to_vec(), r.bytes().unwrap().to_vec()),
        _ => fail("the root is missing".into()),
    };
    let claims = get_claims(&mut Reader::new(&claims)).unwrap_or_else(|e| fail(e.to_string()));
    let output_claims = claims.generic.len() + claims.lean_sphincs.len();
    // The block's digest is computed from its dependencies, then the proof is checked against it alone.
    let verify_start = Instant::now();
    let check = api::verify_block(plan.guest, plan.spec.finalize, &claims, &proof);
    let verify_ms = verify_start.elapsed().as_secs_f64() * 1e3;
    if let Err(e) = &check {
        eprintln!("root verification failed: {e}");
    }
    let verified = check.is_ok();

    let recs: Vec<&Record> = records
        .iter()
        .map(|r| r.as_ref().expect("every node ran"))
        .collect();
    let spans: Vec<f64> = recs.iter().map(|r| r.done_s - r.dispatch_s).collect();
    let prove: Vec<f64> = recs.iter().map(|r| r.done.prove_s).collect();
    let work: f64 = prove.iter().sum();
    let mut per_worker = Vec::new();
    for (w, c) in conns.iter().enumerate() {
        let mine: Vec<&&Record> = recs.iter().filter(|r| r.worker == w).collect();
        let mut o = Obj::default();
        o.str("addr", &c.addr)
            .raw("build", &c.info)
            .num("mem_total", c.mem_total);
        o.num("tasks", mine.len())
            .float("busy_s", mine.iter().map(|r| r.done_s - r.dispatch_s).sum());
        o.num(
            "peak_rss",
            mine.iter().map(|r| r.done.peak_rss).max().unwrap_or(0),
        );
        per_worker.push(o.finish());
    }
    let node_json = recs.iter().enumerate().map(|(id, r)| {
        let n = &nodes[id];
        let mut o = Obj::default();
        o.num("id", id)
            .str("kind", n.kind())
            .num("depth", n.depth)
            .num("children", n.children.len());
        o.num(
            "inputs",
            n.inputs
                .iter()
                .map(|i| match i {
                    Input::Sigs { count, .. } => *count,
                    _ => 1,
                })
                .sum::<usize>(),
        );
        o.bool("finalize", n.finalize)
            .num("worker", r.worker)
            .float("dispatch_s", r.dispatch_s)
            .float("done_s", r.done_s);
        o.float("fetch_s", r.done.fetch_s)
            .float("decode_s", r.done.decode_s)
            .float("prove_s", r.done.prove_s);
        o.num("cycles", r.done.cycles)
            .float("log_committed", r.done.log_committed);
        o.num("input_bytes", r.input_bytes)
            .num("fetched_bytes", r.done.fetched_bytes)
            .num("proof_bytes", r.done.proof_bytes);
        o.finish()
    });
    let mut o = Obj::default();
    o.str("label", &plan.label).str("status", "ok").str(
        "guest",
        if plan.guest == GuestKind::Batched {
            "batched"
        } else {
            "base"
        },
    );
    o.num("workers", workers).num("fanin", plan.spec.fanin).num(
        "max_inner_proofs_per_step",
        plan.spec.max_inner_proofs_per_step,
    );
    o.num("sigs_per_node", plan.spec.sigs_per_node);
    o.num(
        "deps_native",
        plan.spec.sigs.iter().map(|s| s.1).sum::<usize>(),
    )
    .num("leaves_generic", plan.spec.generic.len());
    o.num("leaves_batch", plan.spec.batch.len()).num(
        "claims_batch",
        plan.spec.batch.iter().map(|b| b.1).sum::<usize>(),
    );
    o.num("nodes", nodes.len())
        .num("depth", nodes.iter().map(|n| n.depth).max().unwrap_or(0));
    o.float("makespan_s", makespan)
        .float("critical_path_s", sched::critical_path(&nodes, &spans));
    o.float(
        "critical_path_prove_s",
        sched::critical_path(&nodes, &prove),
    );
    o.float("total_work_s", work);
    o.float(
        "total_fetch_s",
        recs.iter().map(|r| r.done.fetch_s + r.done.decode_s).sum(),
    );
    o.num(
        "bytes_inputs",
        recs.iter().map(|r| r.input_bytes).sum::<u64>(),
    );
    o.num(
        "bytes_transfers",
        recs.iter().map(|r| r.done.fetched_bytes).sum::<u64>(),
    );
    o.num("bytes_root", proof.len())
        .num("root_output_claims", output_claims);
    o.bool("root_verified", verified)
        .float("root_verify_ms", verify_ms);
    o.num(
        "peak_rss_max_worker",
        recs.iter().map(|r| r.done.peak_rss).max().unwrap_or(0),
    );
    o.num("coordinator_peak_rss", sys::peak_rss_bytes());
    let mut modelled = Obj::default();
    modelled.float("work_over_workers_s", work / workers as f64);
    modelled.float(
        "list_schedule_no_transfer_s",
        sched::simulate(nodes.clone(), &prove, workers),
    );
    o.raw("modelled", &modelled.finish());
    o.raw("per_worker", &array(per_worker))
        .raw("node_records", &array(node_json))
        .raw("coordinator", &capabilities());
    std::fs::write(&args[2], o.finish()).unwrap_or_else(|e| fail(e.to_string()));
    println!(
        "{}: makespan {makespan:.3} s, work {work:.3} s, {} nodes on {workers} workers, root verified {verified}",
        plan.label,
        nodes.len()
    );
    if !verified {
        std::process::exit(1);
    }
}
