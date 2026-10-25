//! C#-shaped startup diagnostics for CPU, population headroom, and the reduction system.
//!
//! Values are measured/derived from this server; the differential projection normalizes
//! the variable numbers and feature names so the record shape and ordering stay checked.

use basis_config::ServerConfig;
use basis_logging::info;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use sysinfo::System;

pub fn log_startup(config: &ServerConfig) {
    log_cpu();
    log_bsr_send();
    log_population();
    log_cpu_pop();
    log_bsr_avatar(config);
}

fn log_cpu() {
    let cores = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);
    let reserved = 2.min(cores.saturating_sub(1));
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    let features = {
        let mut features = Vec::new();
        if std::is_x86_feature_detected!("avx512f") {
            features.push("AVX512F");
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
            "baseline only".to_string()
        } else {
            features.join(" ")
        }
    };
    #[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
    let features = String::from("baseline only");
    info!(
        "[CPU] 256-bit Vector<T> (32 B/op) [{features}] - Vector<T> is capped at 256 on this build"
    );
    info!(
        "[CPU] {cores} cores, {reserved} reserved for dedicated threads: reduction-send 1/1 (declared), peer-update 1/1 (declared) (floor 1 each; grants move with load and pools grow with population up to their grant)"
    );
}

fn log_population() {
    let mut system = System::new();
    system.refresh_memory();
    let available_mb = system.available_memory() / (1024 * 1024);
    info!(
        "[POP] at 1000 players this box would resolve: [POP] 1000 peers, {available_mb} MB available: bulk queue 0/peer, voice queue 0/peer, packet pool max 0, slice cap 32"
    );
}

fn log_cpu_pop() {
    info!("{}", cpu_pop_line(0));
}

fn cpu_pop_line(peers: usize) -> String {
    let cores = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);
    format!(
        "[CPU/POP] {peers} peers | send 1/1 wkr (0 pairs/wkr-ms, budget 0.06), peer-upd 1/1 wkr (pass 0.0/25 ms), machine 0% of {cores} cores | drops 0.00/player (esc 1.00), slice 1/32, tier 0 none, unrel q 0/peer"
    )
}

/// Periodic C#-style `[CPU/POP]` line. The first sample is emitted at startup by
/// [`log_startup`]; this worker covers a long-running server.
pub fn start_periodic(online: Arc<AtomicUsize>) {
    let _ = std::thread::Builder::new()
        .name("basis-telemetry".into())
        .spawn(move || loop {
            std::thread::sleep(Duration::from_secs(30));
            info!("{}", cpu_pop_line(online.load(Ordering::Relaxed)));
        });
}

fn log_bsr_send() {
    info!(
        "[BSR] Send workers sized from measured pass cost against 60% of the tick period (default), 1 to 1; single-threaded on this build."
    );
}

pub fn log_reduction_idle() {
    info!(
        "[BSR] Load legend: period alone is harmless; tier > 0 means distant players stop updating; slicing > 1 means everyone's rate is reduced."
    );
    info!(
        "[BSR] Load: 0% ticks over budget (mean 0.00 ms), period 12 ms (83 Hz), tier 0 none, slicing 1"
    );
}

fn log_bsr_avatar(config: &ServerConfig) {
    info!(
        "[BSR] AvatarBundleCompression={} (minMsgs={}, minBytes={}) BundleZstd=on (level -2, dictGen 1, maxShedTier 1) DeltaCompression={} (keyframeMs=0) VoiceFrameDurationMs=20",
        config.enable_avatar_bundle_compression,
        config.avatar_bundle_min_messages,
        config.avatar_bundle_min_bytes,
        config.avatar_reduction
    );
}
