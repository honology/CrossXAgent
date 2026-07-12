use std::time::Instant;

use sysinfo::{Disks, NetworkData, Networks, System};

/// Kind of an emitted sample; selects the OTLP data-point family.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SampleKind {
    Gauge,
    CumulativeSum,
}

/// One host-metric observation from a single sampler tick.
#[derive(Debug, Clone, PartialEq)]
pub struct MetricSample {
    /// OTel `system.*` semantic-convention metric name.
    pub name: &'static str,
    pub value: f64,
    /// Data-point attributes, e.g. `("direction", "receive")`.
    pub attrs: Vec<(&'static str, String)>,
    pub kind: SampleKind,
}

/// Samples host metrics via sysinfo, retaining OS handles between ticks so
/// CPU usage and network counters are diffed against a live baseline.
pub struct HostSampler {
    system: System,
    networks: Networks,
    disks: Disks,
}

impl HostSampler {
    /// Creates the sampler and completes the CPU warmup: it returns only once
    /// the first `sample()` can measure a real utilization window, so it may
    /// block up to `sysinfo::MINIMUM_CPU_UPDATE_INTERVAL` (~200ms, once).
    pub fn new() -> Self {
        let warmup_started = Instant::now();
        let mut system = System::new();
        // Warmup refresh: CPU usage is a delta against the previous snapshot,
        // so without this the first tick would always report 0.
        system.refresh_cpu_usage();
        system.refresh_memory();
        let sampler = Self {
            system,
            networks: Networks::new_with_refreshed_list(),
            disks: Disks::new_with_refreshed_list(),
        };
        // The warmup alone is not enough: sysinfo skips CPU refreshes that
        // land within MINIMUM_CPU_UPDATE_INTERVAL of the warmup (Linux/macOS)
        // or computes erratic PDH rates over a near-zero window (Windows), so
        // an immediate first sample() would export a bogus utilization (0.0
        // or the since-boot average). Wait out whatever the network/disk
        // enumeration above didn't already cover.
        if let Some(remaining) =
            sysinfo::MINIMUM_CPU_UPDATE_INTERVAL.checked_sub(warmup_started.elapsed())
        {
            std::thread::sleep(remaining);
        }
        sampler
    }

    /// Collects one tick of host metrics (spec §5 metric set v0).
    pub fn sample(&mut self) -> Vec<MetricSample> {
        self.system.refresh_cpu_usage();
        self.system.refresh_memory();
        // Keep interfaces that vanished from the OS list: dropping their
        // counters would make the cumulative network totals go backwards.
        self.networks.refresh(false);
        self.disks.refresh(true);

        let mut samples = Vec::with_capacity(8);

        samples.push(MetricSample {
            name: "system.cpu.utilization",
            value: f64::from(self.system.global_cpu_usage()) / 100.0,
            attrs: Vec::new(),
            kind: SampleKind::Gauge,
        });

        let total_memory = self.system.total_memory();
        let used_memory = self.system.used_memory();
        if total_memory > 0 {
            samples.push(MetricSample {
                name: "system.memory.utilization",
                value: used_memory as f64 / total_memory as f64,
                attrs: Vec::new(),
                kind: SampleKind::Gauge,
            });
        }
        samples.push(MetricSample {
            name: "system.memory.usage",
            value: used_memory as f64,
            attrs: vec![("state", "used".to_owned())],
            kind: SampleKind::Gauge,
        });

        let (received, transmitted) = self.network_totals();
        samples.push(MetricSample {
            name: "system.network.io",
            value: received as f64,
            attrs: vec![("direction", "receive".to_owned())],
            kind: SampleKind::CumulativeSum,
        });
        samples.push(MetricSample {
            name: "system.network.io",
            value: transmitted as f64,
            attrs: vec![("direction", "transmit".to_owned())],
            kind: SampleKind::CumulativeSum,
        });

        if let Some(utilization) = self.largest_disk_utilization() {
            samples.push(MetricSample {
                name: "system.filesystem.utilization",
                value: utilization,
                attrs: Vec::new(),
                kind: SampleKind::Gauge,
            });
        }

        #[cfg(unix)]
        samples.push(MetricSample {
            name: "system.cpu.load_average.1m",
            value: System::load_average().one,
            attrs: Vec::new(),
            kind: SampleKind::Gauge,
        });

        samples
    }

    /// Total bytes received/transmitted across non-loopback interfaces.
    fn network_totals(&self) -> (u64, u64) {
        let mut received: u64 = 0;
        let mut transmitted: u64 = 0;
        for (name, data) in self.networks.list() {
            if is_loopback(name, data) {
                continue;
            }
            received = received.saturating_add(data.total_received());
            transmitted = transmitted.saturating_add(data.total_transmitted());
        }
        (received, transmitted)
    }

    /// `1 - available/total` for the disk with the most capacity.
    fn largest_disk_utilization(&self) -> Option<f64> {
        self.disks
            .list()
            .iter()
            .max_by_key(|disk| disk.total_space())
            .filter(|disk| disk.total_space() > 0)
            .map(|disk| 1.0 - disk.available_space() as f64 / disk.total_space() as f64)
    }
}

impl Default for HostSampler {
    fn default() -> Self {
        Self::new()
    }
}

/// IP-based loopback detection with a name fallback for platforms where
/// sysinfo reports no addresses for an interface.
fn is_loopback(name: &str, data: &NetworkData) -> bool {
    if data.ip_networks().iter().any(|ip| ip.addr.is_loopback()) {
        return true;
    }
    name == "lo" || name.to_ascii_lowercase().contains("loopback")
}

#[cfg(test)]
mod tests {
    use std::thread::sleep;
    use std::time::Duration;

    use super::*;

    fn find<'a>(samples: &'a [MetricSample], name: &str) -> Option<&'a MetricSample> {
        samples.iter().find(|s| s.name == name)
    }

    fn network_total(samples: &[MetricSample], direction: &str) -> f64 {
        samples
            .iter()
            .find(|s| {
                s.name == "system.network.io"
                    && s.attrs
                        .iter()
                        .any(|(k, v)| *k == "direction" && v == direction)
            })
            .map(|s| s.value)
            .unwrap_or_else(|| panic!("missing system.network.io direction={direction}"))
    }

    #[test]
    fn sample_should_emit_expected_metric_names_and_kinds_when_ticked_twice() {
        let mut sampler = HostSampler::new();
        let first = sampler.sample();
        sleep(Duration::from_millis(250));
        let second = sampler.sample();

        for tick in [&first, &second] {
            for gauge_name in [
                "system.cpu.utilization",
                "system.memory.utilization",
                "system.memory.usage",
                "system.filesystem.utilization",
            ] {
                let sample =
                    find(tick, gauge_name).unwrap_or_else(|| panic!("missing {gauge_name}"));
                assert_eq!(sample.kind, SampleKind::Gauge, "{gauge_name} kind");
            }
            let net: Vec<&MetricSample> = tick
                .iter()
                .filter(|s| s.name == "system.network.io")
                .collect();
            assert_eq!(net.len(), 2, "expected receive + transmit network samples");
            assert!(net.iter().all(|s| s.kind == SampleKind::CumulativeSum));
            #[cfg(unix)]
            assert!(find(tick, "system.cpu.load_average.1m").is_some());
        }
    }

    #[test]
    fn sample_should_keep_ratio_gauges_within_unit_interval_when_sampling_live_host() {
        let mut sampler = HostSampler::new();
        sleep(Duration::from_millis(250));
        let samples = sampler.sample();

        for name in [
            "system.cpu.utilization",
            "system.memory.utilization",
            "system.filesystem.utilization",
        ] {
            let sample = find(&samples, name).unwrap_or_else(|| panic!("missing {name}"));
            assert!(
                (0.0..=1.0).contains(&sample.value),
                "{name} out of unit interval: {}",
                sample.value
            );
        }
    }

    #[test]
    fn sample_should_report_memory_usage_bytes_above_zero_when_sampling_live_host() {
        let mut sampler = HostSampler::new();
        let samples = sampler.sample();

        let usage = find(&samples, "system.memory.usage").expect("missing system.memory.usage");
        assert!(usage.value > 0.0, "used memory bytes should be positive");
        assert!(
            usage
                .attrs
                .iter()
                .any(|(k, v)| *k == "state" && v == "used"),
            "system.memory.usage should carry state=used"
        );
    }

    #[test]
    fn sample_should_report_nonzero_cpu_utilization_when_sampled_immediately_after_new_under_load()
    {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, Ordering};

        // Busy-spin one core so real global CPU utilization is provably > 0
        // for the whole measurement window.
        let stop = Arc::new(AtomicBool::new(false));
        let spinner = {
            let stop = Arc::clone(&stop);
            std::thread::spawn(move || {
                let mut x: u64 = 0;
                while !stop.load(Ordering::Relaxed) {
                    x = x.wrapping_add(1);
                }
                std::hint::black_box(x)
            })
        };

        // No sleep between new() and sample(): exactly what `run --once` and
        // the run loop's first tick do.
        let mut sampler = HostSampler::new();
        let samples = sampler.sample();

        stop.store(true, Ordering::Relaxed);
        spinner.join().expect("spinner thread panicked");

        let cpu = find(&samples, "system.cpu.utilization").expect("missing system.cpu.utilization");
        assert!(
            cpu.value > 0.0,
            "first-tick CPU utilization should reflect real load, got {}",
            cpu.value
        );
    }

    #[test]
    fn sample_should_report_monotonic_network_totals_when_ticked_twice() {
        let mut sampler = HostSampler::new();
        let first = sampler.sample();
        sleep(Duration::from_millis(250));
        let second = sampler.sample();

        for direction in ["receive", "transmit"] {
            let before = network_total(&first, direction);
            let after = network_total(&second, direction);
            assert!(
                after >= before,
                "network {direction} total decreased: {before} -> {after}"
            );
        }
    }
}
