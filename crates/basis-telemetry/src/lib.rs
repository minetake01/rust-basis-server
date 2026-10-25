//! Rust-native runtime telemetry for the Basis server.
//!
//! The C# server reports its reduction-worker and GC state. This server has neither: it runs a
//! single receive loop with no garbage collector and no worker pools. The record tags (`[CPU]`,
//! `[NET]`, `[BSR]`) stay familiar to operators, but every value here is measured from this
//! process: loop busy/wait time, packet and byte rates, queue depths, reliable resends, bundle
//! totals, process CPU and RSS.

use basis_config::ServerConfig;
use basis_logging::info;
use std::time::{Duration, Instant};
use sysinfo::{Pid, ProcessRefreshKind, ProcessesToUpdate, System};

const REPORT_INTERVAL: Duration = Duration::from_secs(30);

/// A point-in-time view owned by the transport.
pub struct Counters {
    pub online: usize,
    pub peer_limit: usize,
    pub pending_auth: usize,
    pub reliable_queue: usize,
    pub bundle_messages: usize,
    pub bundle_bytes: usize,
    pub rx_packets: u64,
    pub tx_packets: u64,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
}

pub struct Telemetry {
    started: Instant,
    last_report: Instant,
    system: System,
    pid: Pid,
    loops: u64,
    busy_ns: u64,
    wait_ns: u64,
    max_busy_ns: u64,
    resends: u64,
    reliable_drops: u64,
    bundles: u64,
    bundled_messages: u64,
    bundle_raw_bytes: u64,
    bundle_wire_bytes: u64,
    direct_fallbacks: u64,
    send_failures: u64,
    last_rx_packets: u64,
    last_tx_packets: u64,
    last_rx_bytes: u64,
    last_tx_bytes: u64,
}

impl Default for Telemetry {
    fn default() -> Self {
        Self::new()
    }
}

impl Telemetry {
    pub fn new() -> Self {
        let mut system = System::new();
        let pid = Pid::from_u32(std::process::id());
        system.refresh_memory();
        system.refresh_processes_specifics(ProcessesToUpdate::Some(&[pid]), true, refresh_kind());
        Self {
            started: Instant::now(),
            last_report: Instant::now(),
            system,
            pid,
            loops: 0,
            busy_ns: 0,
            wait_ns: 0,
            max_busy_ns: 0,
            resends: 0,
            reliable_drops: 0,
            bundles: 0,
            bundled_messages: 0,
            bundle_raw_bytes: 0,
            bundle_wire_bytes: 0,
            direct_fallbacks: 0,
            send_failures: 0,
            last_rx_packets: 0,
            last_tx_packets: 0,
            last_rx_bytes: 0,
            last_tx_bytes: 0,
        }
    }

    /// Startup facts. These are properties of the build and the host, not windowed counters.
    pub fn log_startup(
        &mut self,
        config: &ServerConfig,
        peer_bytes: usize,
        receive_buffer_bytes: usize,
    ) {
        let cores = std::thread::available_parallelism()
            .map(|count| count.get())
            .unwrap_or(1);
        let profile = if cfg!(debug_assertions) {
            "debug"
        } else {
            "release"
        };
        info!(
            "[CPU] {} {profile} build, {}, {cores} logical cores; single receive loop, no GC",
            std::env::consts::ARCH,
            cpu_features(),
        );

        let (rss, available, total) = self.memory();
        info!(
            "[MEM] RSS {}; {} available of {}; system allocator",
            human_bytes(rss as f64),
            human_bytes(available as f64),
            human_bytes(total as f64),
        );
        info!(
            "[POP] peer limit {}; Peer {} B fixed + heap; receive buffer {} KiB",
            config.peer_limit,
            peer_bytes,
            receive_buffer_bytes.div_ceil(1024),
        );
        info!(
            "[BSR] reduction {} (High <= {:.1} m, Medium <= {:.1} m, Low <= {:.1} m); bundles {} (min {} msg / {} B)",
            on_off(config.avatar_reduction),
            config.high_quality_distance,
            config.medium_quality_distance,
            config.low_quality_distance,
            on_off(config.enable_avatar_bundle_compression),
            config.avatar_bundle_min_messages,
            config.avatar_bundle_min_bytes,
        );
    }

    /// One pass of the transport loop. `busy` covers maintenance and packet handling; `wait` is
    /// the time the loop spent blocked in `recv_from`.
    pub fn record_iteration(&mut self, busy: Duration, wait: Duration) {
        let busy_ns = u64::try_from(busy.as_nanos()).unwrap_or(u64::MAX);
        let wait_ns = u64::try_from(wait.as_nanos()).unwrap_or(u64::MAX);
        self.loops = self.loops.saturating_add(1);
        self.busy_ns = self.busy_ns.saturating_add(busy_ns);
        self.wait_ns = self.wait_ns.saturating_add(wait_ns);
        self.max_busy_ns = self.max_busy_ns.max(busy_ns);
    }

    pub fn record_reliable(&mut self, resends: u64, drops: u64) {
        self.resends = self.resends.saturating_add(resends);
        self.reliable_drops = self.reliable_drops.saturating_add(drops);
    }

    pub fn record_bundles(
        &mut self,
        bundles: u64,
        messages: u64,
        raw_bytes: u64,
        wire_bytes: u64,
        direct_fallbacks: u64,
    ) {
        self.bundles = self.bundles.saturating_add(bundles);
        self.bundled_messages = self.bundled_messages.saturating_add(messages);
        self.bundle_raw_bytes = self.bundle_raw_bytes.saturating_add(raw_bytes);
        self.bundle_wire_bytes = self.bundle_wire_bytes.saturating_add(wire_bytes);
        self.direct_fallbacks = self.direct_fallbacks.saturating_add(direct_fallbacks);
    }

    pub fn record_send_failure(&mut self) {
        self.send_failures = self.send_failures.saturating_add(1);
    }

    pub fn due(&self) -> bool {
        self.last_report.elapsed() >= REPORT_INTERVAL
    }

    /// Emits the measured window and starts a new one.
    pub fn report(&mut self, counters: Counters) {
        let window = self.last_report.elapsed().as_secs_f64().max(0.001);
        let loops = self.loops.max(1) as f64;
        let busy_avg_ms = self.busy_ns as f64 / loops / 1_000_000.0;
        let busy_max_ms = self.max_busy_ns as f64 / 1_000_000.0;
        let total_ns = self.busy_ns.saturating_add(self.wait_ns);
        let duty = if total_ns == 0 {
            0.0
        } else {
            self.busy_ns as f64 / total_ns as f64 * 100.0
        };
        let loop_hz = self.loops as f64 / window;
        let (rss, available, total) = self.memory();
        let cores = std::thread::available_parallelism()
            .map(|count| count.get())
            .unwrap_or(1);
        let cpu = self
            .system
            .process(self.pid)
            .map(|process| process.cpu_usage())
            .unwrap_or(0.0);

        let rx_packets = counters.rx_packets.saturating_sub(self.last_rx_packets) as f64 / window;
        let tx_packets = counters.tx_packets.saturating_sub(self.last_tx_packets) as f64 / window;
        let rx_bytes = counters.rx_bytes.saturating_sub(self.last_rx_bytes) as f64 / window;
        let tx_bytes = counters.tx_bytes.saturating_sub(self.last_tx_bytes) as f64 / window;

        info!(
            "[CPU] {}/{} peers | loop {:.0}/s | busy {:.3} ms avg, {:.3} ms max, {:.1}% duty | CPU {:.1}% of one core ({:.2}% of {}) | RSS {} of {} ({} free) | up {}",
            counters.online,
            counters.peer_limit,
            loop_hz,
            busy_avg_ms,
            busy_max_ms,
            duty,
            cpu,
            cpu / cores as f32,
            cores,
            human_bytes(rss as f64),
            human_bytes(total as f64),
            human_bytes(available as f64),
            format_uptime(self.started.elapsed()),
        );
        info!(
            "[NET] {:.0} pkt/s in, {:.0} pkt/s out | {} in, {} out | bundle q {} msg / {} | reliable q {} | auth q {} | reliable resend {}, drop {}",
            rx_packets,
            tx_packets,
            human_rate(rx_bytes),
            human_rate(tx_bytes),
            counters.bundle_messages,
            human_bytes(counters.bundle_bytes as f64),
            counters.reliable_queue,
            counters.pending_auth,
            self.resends,
            self.reliable_drops,
        );
        let ratio = if self.bundle_wire_bytes == 0 {
            0.0
        } else {
            self.bundle_raw_bytes as f64 / self.bundle_wire_bytes as f64
        };
        if self.bundles + self.direct_fallbacks + self.send_failures > 0 {
            info!(
                "[BSR] last {:.0}s: {} bundles / {} msgs, {} -> {} ({:.2}x); {} direct sends; {} send failures",
                window,
                self.bundles,
                self.bundled_messages,
                human_bytes(self.bundle_raw_bytes as f64),
                human_bytes(self.bundle_wire_bytes as f64),
                ratio,
                self.direct_fallbacks,
                self.send_failures,
            );
        }

        self.last_report = Instant::now();
        self.loops = 0;
        self.busy_ns = 0;
        self.wait_ns = 0;
        self.max_busy_ns = 0;
        self.resends = 0;
        self.reliable_drops = 0;
        self.bundles = 0;
        self.bundled_messages = 0;
        self.bundle_raw_bytes = 0;
        self.bundle_wire_bytes = 0;
        self.direct_fallbacks = 0;
        self.send_failures = 0;
        self.last_rx_packets = counters.rx_packets;
        self.last_tx_packets = counters.tx_packets;
        self.last_rx_bytes = counters.rx_bytes;
        self.last_tx_bytes = counters.tx_bytes;
    }

    fn memory(&mut self) -> (u64, u64, u64) {
        let pid = self.pid;
        self.system.refresh_memory();
        self.system.refresh_processes_specifics(
            ProcessesToUpdate::Some(&[pid]),
            true,
            refresh_kind(),
        );
        let rss = self
            .system
            .process(pid)
            .map(|process| process.memory())
            .unwrap_or(0);
        (
            rss,
            self.system.available_memory(),
            self.system.total_memory(),
        )
    }
}

fn refresh_kind() -> ProcessRefreshKind {
    ProcessRefreshKind::nothing().with_cpu().with_memory()
}

fn cpu_features() -> String {
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    {
        let mut features = Vec::new();
        if std::is_x86_feature_detected!("avx512f") {
            features.push("AVX-512F");
        }
        if std::is_x86_feature_detected!("avx2") {
            features.push("AVX2");
        }
        if std::is_x86_feature_detected!("sse4.2") {
            features.push("SSE4.2");
        }
        if std::is_x86_feature_detected!("bmi2") {
            features.push("BMI2");
        }
        if features.is_empty() {
            "baseline".to_string()
        } else {
            features.join(" ")
        }
    }
    #[cfg(target_arch = "aarch64")]
    {
        "NEON".to_string()
    }
    #[cfg(not(any(target_arch = "x86", target_arch = "x86_64", target_arch = "aarch64")))]
    {
        "baseline".to_string()
    }
}

fn on_off(value: bool) -> &'static str {
    if value {
        "on"
    } else {
        "off"
    }
}

fn human_bytes(bytes: f64) -> String {
    const KIB: f64 = 1024.0;
    const MIB: f64 = KIB * 1024.0;
    const GIB: f64 = MIB * 1024.0;
    if bytes >= GIB {
        format!("{:.1} GiB", bytes / GIB)
    } else if bytes >= MIB {
        format!("{:.1} MiB", bytes / MIB)
    } else if bytes >= KIB {
        format!("{:.1} KiB", bytes / KIB)
    } else {
        format!("{bytes:.0} B")
    }
}

fn human_rate(bytes_per_second: f64) -> String {
    format!("{}/s", human_bytes(bytes_per_second))
}

fn format_uptime(uptime: Duration) -> String {
    let seconds = uptime.as_secs();
    let days = seconds / 86_400;
    let hours = (seconds % 86_400) / 3_600;
    let minutes = (seconds % 3_600) / 60;
    let seconds = seconds % 60;
    if days == 0 {
        format!("{hours:02}:{minutes:02}:{seconds:02}")
    } else {
        format!("{days}d {hours:02}:{minutes:02}:{seconds:02}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn byte_units_scale() {
        assert_eq!(human_bytes(512.0), "512 B");
        assert_eq!(human_bytes(1536.0), "1.5 KiB");
        assert_eq!(human_bytes(5.0 * 1024.0 * 1024.0), "5.0 MiB");
    }

    #[test]
    fn uptime_includes_days_only_when_present() {
        assert_eq!(format_uptime(Duration::from_secs(3_661)), "01:01:01");
        assert_eq!(format_uptime(Duration::from_secs(90_061)), "1d 01:01:01");
    }
}
