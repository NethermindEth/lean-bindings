//! Host facts the results carry: peak resident memory, physical and available memory, the host name.

/// This process's peak resident set size, in bytes.
pub fn peak_rss_bytes() -> u64 {
    // SAFETY: `getrusage` only writes the zero-initialized struct it is given.
    let usage = unsafe {
        let mut usage: libc::rusage = std::mem::zeroed();
        libc::getrusage(libc::RUSAGE_SELF, &mut usage);
        usage
    };
    let max = usage.ru_maxrss.max(0) as u64;
    // Linux reports kilobytes, macOS bytes.
    if cfg!(target_os = "macos") {
        max
    } else {
        max * 1024
    }
}

/// `(total, available)` physical memory in bytes. Available is `MemAvailable` on Linux and free plus inactive plus
/// purgeable pages on macOS: what a new process can take without swapping others out.
pub fn memory_bytes() -> (u64, u64) {
    #[cfg(target_os = "linux")]
    {
        let info = std::fs::read_to_string("/proc/meminfo").unwrap_or_default();
        let field = |name: &str| {
            info.lines()
                .find(|l| l.starts_with(name))
                .and_then(|l| l.split_whitespace().nth(1))
                .and_then(|v| v.parse::<u64>().ok())
                .unwrap_or(0)
                * 1024
        };
        (field("MemTotal:"), field("MemAvailable:"))
    }
    #[cfg(not(target_os = "linux"))]
    {
        let run = |cmd: &str, args: &[&str]| {
            std::process::Command::new(cmd)
                .args(args)
                .output()
                .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
                .unwrap_or_default()
        };
        let total = run("sysctl", &["-n", "hw.memsize"])
            .trim()
            .parse()
            .unwrap_or(0);
        let vm = run("vm_stat", &[]);
        let page: u64 = vm
            .lines()
            .next()
            .and_then(|l| l.split("page size of ").nth(1))
            .and_then(|s| s.split_whitespace().next())
            .and_then(|s| s.parse().ok())
            .unwrap_or(16384);
        let pages = |name: &str| {
            vm.lines()
                .find(|l| l.starts_with(name))
                .and_then(|l| l.split(':').nth(1))
                .map(|v| v.trim().trim_end_matches('.').parse::<u64>().unwrap_or(0))
                .unwrap_or(0)
        };
        (
            total,
            (pages("Pages free") + pages("Pages inactive") + pages("Pages purgeable")) * page,
        )
    }
}

pub fn hostname() -> String {
    std::process::Command::new("hostname")
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default()
}

/// The prover's worker-thread count: `LEANVM_NUM_THREADS`, else every available core.
pub fn threads() -> usize {
    std::env::var("LEANVM_NUM_THREADS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or_else(|| std::thread::available_parallelism().map_or(1, |n| n.get()))
}
