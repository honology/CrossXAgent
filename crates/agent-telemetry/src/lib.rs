//! Host telemetry sampling and OTLP export-request construction for
//! crossx-agent. Metric names follow the OTel `system.*` semantic
//! conventions — that naming is the compatibility contract with the
//! pulse-collector and the Monitor widget.

pub mod logs;
pub mod otlp;
pub mod sampler;

pub use otlp::build_export_request;
pub use sampler::{HostSampler, MetricSample, SampleKind};
