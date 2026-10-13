//! The published `/run/nvx/time/state` representation.

use std::io::Write as _;

use super::Phase;
use super::decoders;
#[cfg(test)]
use super::events;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CheckState {
    pub(crate) status: Vec<u8>,
    pub(crate) cpus: u64,
    pub(crate) elapsed_us: i64,
    pub(crate) cpu_us: i64,
    pub(crate) generation: u64,
    pub(crate) failures: i64,
}

impl Default for CheckState {
    fn default() -> Self {
        Self {
            status: Vec::new(),
            cpus: 0,
            elapsed_us: 0,
            cpu_us: 0,
            generation: 0,
            failures: -1,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct TimeState {
    pub(crate) generation: u64,
    pub(crate) checks: [CheckState; 3],
    pub(crate) tsc_hz: u64,
    pub(crate) lapic_hz: u64,
    pub(crate) discontinuities: u64,
    pub(crate) last_discontinuity: Vec<u8>,
    pub(crate) last_step_ns: i64,
    pub(crate) last_step_realtime_ns: i64,
    pub(crate) last_downtime_ns: u64,
    pub(crate) last_downtime_source: Vec<u8>,
    pub(crate) synchronized: u64,
    pub(crate) offset_ns: i64,
    pub(crate) uncertainty_ns: i64,
    pub(crate) frequency_ppb: i64,
    pub(crate) samples: u64,
    pub(crate) rejected_samples: u64,
    pub(crate) last_sample_error: Vec<u8>,
    pub(crate) violations: u64,
}

impl Default for TimeState {
    fn default() -> Self {
        let mut checks = std::array::from_fn(|_| CheckState::default());
        checks[0].status = b"pending".to_vec();
        Self {
            generation: 0,
            checks,
            tsc_hz: 0,
            lapic_hz: 0,
            discontinuities: 0,
            last_discontinuity: b"none".to_vec(),
            last_step_ns: 0,
            last_step_realtime_ns: 0,
            last_downtime_ns: 0,
            last_downtime_source: b"none".to_vec(),
            synchronized: 0,
            offset_ns: 0,
            uncertainty_ns: 0,
            frequency_ppb: 0,
            samples: 0,
            rejected_samples: 0,
            last_sample_error: b"none".to_vec(),
            violations: 0,
        }
    }
}

fn parse_i64(text: &[u8]) -> Option<i64> {
    decoders::parse_i64_exact(text)
}

fn copy_word(value: &[u8], size: usize) -> Vec<u8> {
    value
        .split(|byte| *byte == b'\n' || *byte == 0)
        .next()
        .unwrap_or_default()
        .iter()
        .copied()
        .take(size.saturating_sub(1))
        .collect()
}

impl TimeState {
    /// Parses known `key=value` lines, ignoring unknown keys.
    pub(crate) fn parse(text: &[u8]) -> Option<Self> {
        let mut state = Self::default();
        let text = text.split(|byte| *byte == 0).next().unwrap_or_default();
        for line in text.split(|byte| *byte == b'\n') {
            let Some(equal) = line.iter().position(|byte| *byte == b'=') else {
                continue;
            };
            let key = &line[..equal];
            let value = &line[equal + 1..];
            let number = || parse_i64(value);
            match key {
                b"boot_status" => state.checks[0].status = copy_word(value, 16),
                b"capture_status" => state.checks[1].status = copy_word(value, 16),
                b"restore_status" => state.checks[2].status = copy_word(value, 16),
                b"last_discontinuity" => {
                    state.last_discontinuity = copy_word(value, 16);
                }
                b"last_downtime_source" => {
                    state.last_downtime_source = copy_word(value, 16);
                }
                b"last_sample_error" => state.last_sample_error = copy_word(value, 24),
                b"generation" => state.generation = number()? as u64,
                b"boot_cpus" => state.checks[0].cpus = number()? as u64,
                b"capture_cpus" => state.checks[1].cpus = number()? as u64,
                b"restore_cpus" => state.checks[2].cpus = number()? as u64,
                b"boot_elapsed_us" => state.checks[0].elapsed_us = number()?,
                b"capture_elapsed_us" => state.checks[1].elapsed_us = number()?,
                b"restore_elapsed_us" => state.checks[2].elapsed_us = number()?,
                b"boot_cpu_us" => state.checks[0].cpu_us = number()?,
                b"capture_cpu_us" => state.checks[1].cpu_us = number()?,
                b"restore_cpu_us" => state.checks[2].cpu_us = number()?,
                b"capture_generation" => {
                    state.checks[1].generation = number()? as u64;
                }
                b"restore_generation" => {
                    state.checks[2].generation = number()? as u64;
                }
                b"boot_failures" => state.checks[0].failures = number()?,
                b"capture_failures" => state.checks[1].failures = number()?,
                b"restore_failures" => state.checks[2].failures = number()?,
                b"tsc_hz" => state.tsc_hz = number()? as u64,
                b"lapic_hz" => state.lapic_hz = number()? as u64,
                b"discontinuities" => state.discontinuities = number()? as u64,
                b"last_step_ns" => state.last_step_ns = number()?,
                b"last_step_realtime_ns" => state.last_step_realtime_ns = number()?,
                b"last_downtime_ns" => state.last_downtime_ns = number()? as u64,
                b"synchronized" => state.synchronized = number()? as u64,
                b"offset_ns" => state.offset_ns = number()?,
                b"uncertainty_ns" => state.uncertainty_ns = number()?,
                b"frequency_ppb" => state.frequency_ppb = number()?,
                b"samples" => state.samples = number()? as u64,
                b"rejected_samples" => state.rejected_samples = number()? as u64,
                b"violations" => state.violations = number()? as u64,
                _ => {}
            }
        }
        Some(state)
    }

    /// Formats the state in the order fixed by the ABI.
    pub(crate) fn format(&self) -> Vec<u8> {
        let mut text = Vec::with_capacity(2048);
        let _ = writeln!(text, "version=1");
        let _ = writeln!(text, "generation={}", self.generation);
        for (index, phase) in Phase::CHECKS.iter().copied().enumerate() {
            if !self.checks[index].status.is_empty() {
                push_word_line(
                    &mut text,
                    phase.name(),
                    "status",
                    &self.checks[index].status,
                );
            }
        }
        for (index, phase) in Phase::CHECKS.iter().copied().enumerate() {
            if !self.checks[index].status.is_empty() {
                let _ = writeln!(text, "{}_cpus={}", phase.name(), self.checks[index].cpus);
            }
        }
        for (index, phase) in Phase::CHECKS.iter().copied().enumerate() {
            if !self.checks[index].status.is_empty() {
                let _ = writeln!(
                    text,
                    "{}_elapsed_us={}",
                    phase.name(),
                    self.checks[index].elapsed_us
                );
            }
        }
        for (index, phase) in Phase::CHECKS.iter().copied().enumerate() {
            if !self.checks[index].status.is_empty() {
                let _ = writeln!(
                    text,
                    "{}_cpu_us={}",
                    phase.name(),
                    self.checks[index].cpu_us
                );
            }
        }
        for (index, phase) in Phase::CHECKS.iter().copied().enumerate().skip(1) {
            if !self.checks[index].status.is_empty() {
                let _ = writeln!(
                    text,
                    "{}_generation={}",
                    phase.name(),
                    self.checks[index].generation
                );
            }
        }
        for (index, phase) in Phase::CHECKS.iter().copied().enumerate() {
            if !self.checks[index].status.is_empty() && self.checks[index].failures >= 0 {
                let _ = writeln!(
                    text,
                    "{}_failures={}",
                    phase.name(),
                    self.checks[index].failures
                );
            }
        }
        let _ = writeln!(text, "tsc_hz={}", self.tsc_hz);
        let _ = writeln!(text, "lapic_hz={}", self.lapic_hz);
        let _ = writeln!(text, "discontinuities={}", self.discontinuities);
        push_raw_word_line(&mut text, "last_discontinuity", &self.last_discontinuity);
        let _ = writeln!(text, "last_step_ns={}", self.last_step_ns);
        let _ = writeln!(text, "last_step_realtime_ns={}", self.last_step_realtime_ns);
        let _ = writeln!(text, "last_downtime_ns={}", self.last_downtime_ns);
        push_raw_word_line(
            &mut text,
            "last_downtime_source",
            &self.last_downtime_source,
        );
        let _ = writeln!(text, "synchronized={}", self.synchronized);
        let _ = writeln!(text, "offset_ns={}", self.offset_ns);
        let _ = writeln!(text, "uncertainty_ns={}", self.uncertainty_ns);
        let _ = writeln!(text, "frequency_ppb={}", self.frequency_ppb);
        let _ = writeln!(text, "samples={}", self.samples);
        let _ = writeln!(text, "rejected_samples={}", self.rejected_samples);
        push_raw_word_line(&mut text, "last_sample_error", &self.last_sample_error);
        let _ = writeln!(text, "violations={}", self.violations);
        text
    }

    /// Formats status markers and returns whether every recorded check is `ok`.
    pub(crate) fn format_status(&self, report_only: bool) -> (Vec<u8>, bool) {
        let prefix = if report_only {
            "NVX-TIME-REPORT"
        } else {
            "NVX-TIME-ABI"
        };
        let mut text = Vec::with_capacity(1024);
        let mut ok = true;
        for (index, phase) in Phase::CHECKS.iter().copied().enumerate() {
            let check = &self.checks[index];
            if check.status.is_empty() {
                continue;
            }
            ok &= check.status == b"ok";
            text.extend_from_slice(prefix.as_bytes());
            text.extend_from_slice(b": v=1 phase=");
            text.extend_from_slice(phase.name().as_bytes());
            text.extend_from_slice(b" status=");
            text.extend_from_slice(&check.status);
            let fixed = format!(
                " cpus={} tsc_hz={} lapic_hz={} generation={}",
                check.cpus, self.tsc_hz, self.lapic_hz, check.generation
            );
            text.extend_from_slice(fixed.as_bytes());
            if check.status != b"pending" {
                let times = format!(" elapsed_us={} cpu_us={}", check.elapsed_us, check.cpu_us);
                text.extend_from_slice(times.as_bytes());
            }
            if report_only {
                let suffix = format!(" failures={}", check.failures.max(0));
                text.extend_from_slice(suffix.as_bytes());
            }
            text.push(b'\n');
        }
        let runtime = format!(
            "{prefix}: v=1 phase=runtime status={} generation={} \
             discontinuities={} offset_ns={} uncertainty_ns={} rejected_samples={} ",
            if self.synchronized != 0 {
                "synchronized"
            } else {
                "unsynchronized"
            },
            self.generation,
            self.discontinuities,
            self.offset_ns,
            self.uncertainty_ns,
            self.rejected_samples
        );
        text.extend_from_slice(runtime.as_bytes());
        text.extend_from_slice(b"last_sample_error=");
        text.extend_from_slice(&self.last_sample_error);
        text.push(b'\n');
        (text, ok)
    }
}

fn push_word_line(text: &mut Vec<u8>, phase: &str, suffix: &str, value: &[u8]) {
    let _ = write!(text, "{phase}_{suffix}=");
    text.extend_from_slice(value);
    text.push(b'\n');
}

fn push_raw_word_line(text: &mut Vec<u8>, key: &str, value: &[u8]) {
    let _ = write!(text, "{key}=");
    text.extend_from_slice(value);
    text.push(b'\n');
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fresh_state_has_only_a_pending_boot_check() {
        let state = TimeState::parse(b"version=1\n").unwrap();
        assert!(
            state
                .format()
                .starts_with(b"version=1\ngeneration=0\nboot_status=pending\nboot_cpus=0\n")
        );
        assert!(state.checks[1].status.is_empty());
    }

    #[test]
    fn malformed_known_numbers_fail_but_unknown_keys_do_not() {
        assert!(TimeState::parse(b"unknown=x\nsamples=bad\n").is_none());
        assert!(TimeState::parse(b"unknown=bad\n").is_some());
    }

    #[test]
    fn status_event_lengths_share_the_abi_limit_constant() {
        assert_eq!(events::EVENT_MAX, 512);
    }

    #[test]
    fn state_words_remain_raw_bytes_and_nul_terminates_the_input() {
        let state =
            TimeState::parse(b"last_sample_error=\xff\0\nlast_sample_error=later\n").unwrap();
        assert!(
            state
                .format()
                .split(|byte| *byte == b'\n')
                .any(|line| line == b"last_sample_error=\xff")
        );
        assert_eq!(state.last_sample_error, b"\xff");
    }
}
