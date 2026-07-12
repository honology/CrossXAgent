use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};

use opentelemetry_proto::tonic::collector::metrics::v1::ExportMetricsServiceRequest;
use opentelemetry_proto::tonic::common::v1::{AnyValue, InstrumentationScope, KeyValue, any_value};
use opentelemetry_proto::tonic::metrics::v1::{
    AggregationTemporality, Gauge, Metric, NumberDataPoint, ResourceMetrics, ScopeMetrics, Sum,
    metric, number_data_point,
};
use opentelemetry_proto::tonic::resource::v1::Resource;

use crate::sampler::{MetricSample, SampleKind};

/// Captured on first use as a stand-in for the process start time so
/// cumulative sums report a stable `start_time_unix_nano` across ticks.
static PROCESS_START_NANOS: OnceLock<u64> = OnceLock::new();

fn process_start_unix_nanos() -> u64 {
    *PROCESS_START_NANOS.get_or_init(|| {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |elapsed| u64::try_from(elapsed.as_nanos()).unwrap_or(0))
    })
}

fn string_attr(key: &str, value: &str) -> KeyValue {
    KeyValue {
        key: key.to_owned(),
        value: Some(AnyValue {
            value: Some(any_value::Value::StringValue(value.to_owned())),
        }),
        // Profiling-signal string-table reference; unused for metrics.
        ..Default::default()
    }
}

/// Builds a single-resource OTLP export request from one sampler tick.
///
/// Resource attributes carry the `crossx.node.id` join key (spec §6) and
/// `host.name`; every sample becomes one metric with one data point stamped
/// `ts_ms * 1_000_000` nanoseconds.
pub fn build_export_request(
    node_id: &str,
    host_name: &str,
    ts_ms: i64,
    samples: &[MetricSample],
) -> ExportMetricsServiceRequest {
    // ts_ms is epoch milliseconds by contract; clamp negatives rather than
    // wrap into a far-future unsigned timestamp.
    let time_unix_nano = u64::try_from(ts_ms.max(0)).unwrap_or(0) * 1_000_000;
    let metrics = samples
        .iter()
        .map(|sample| to_metric(sample, time_unix_nano))
        .collect();

    ExportMetricsServiceRequest {
        resource_metrics: vec![ResourceMetrics {
            resource: Some(Resource {
                attributes: vec![
                    string_attr("crossx.node.id", node_id),
                    string_attr("host.name", host_name),
                ],
                ..Default::default()
            }),
            scope_metrics: vec![ScopeMetrics {
                scope: Some(InstrumentationScope {
                    name: "crossx-agent".to_owned(),
                    ..Default::default()
                }),
                metrics,
                ..Default::default()
            }],
            ..Default::default()
        }],
    }
}

fn to_metric(sample: &MetricSample, time_unix_nano: u64) -> Metric {
    let point = NumberDataPoint {
        attributes: sample
            .attrs
            .iter()
            .map(|(key, value)| string_attr(key, value))
            .collect(),
        time_unix_nano,
        value: Some(number_data_point::Value::AsDouble(sample.value)),
        ..Default::default()
    };
    let data = match sample.kind {
        SampleKind::Gauge => metric::Data::Gauge(Gauge {
            data_points: vec![point],
        }),
        SampleKind::CumulativeSum => metric::Data::Sum(Sum {
            data_points: vec![NumberDataPoint {
                start_time_unix_nano: process_start_unix_nanos(),
                ..point
            }],
            aggregation_temporality: AggregationTemporality::Cumulative as i32,
            is_monotonic: true,
        }),
    };
    Metric {
        name: sample.name.to_owned(),
        data: Some(data),
        ..Default::default()
    }
}

#[cfg(test)]
mod tests {
    use opentelemetry_proto::tonic::collector::metrics::v1::ExportMetricsServiceRequest;
    use opentelemetry_proto::tonic::common::v1::any_value;
    use opentelemetry_proto::tonic::metrics::v1::{AggregationTemporality, Metric, metric::Data};

    use super::*;
    use crate::sampler::{MetricSample, SampleKind};

    const TS_MS: i64 = 1_752_300_000_123;

    fn synthetic_samples() -> Vec<MetricSample> {
        vec![
            MetricSample {
                name: "system.cpu.utilization",
                value: 0.25,
                attrs: Vec::new(),
                kind: SampleKind::Gauge,
            },
            MetricSample {
                name: "system.network.io",
                value: 4096.0,
                attrs: vec![("direction", "receive".to_owned())],
                kind: SampleKind::CumulativeSum,
            },
        ]
    }

    fn build() -> ExportMetricsServiceRequest {
        build_export_request("node-test", "host-test", TS_MS, &synthetic_samples())
    }

    fn resource_attr(req: &ExportMetricsServiceRequest, key: &str) -> Option<String> {
        let resource = req.resource_metrics.first()?.resource.as_ref()?;
        let kv = resource.attributes.iter().find(|kv| kv.key == key)?;
        match kv.value.as_ref()?.value.as_ref()? {
            any_value::Value::StringValue(s) => Some(s.clone()),
            _ => None,
        }
    }

    fn metric_by_name(req: &ExportMetricsServiceRequest, name: &str) -> Metric {
        req.resource_metrics
            .iter()
            .flat_map(|rm| rm.scope_metrics.iter())
            .flat_map(|sm| sm.metrics.iter())
            .find(|m| m.name == name)
            .unwrap_or_else(|| panic!("metric {name} not found"))
            .clone()
    }

    #[test]
    fn build_export_request_should_carry_node_and_host_resource_attrs_when_built() {
        let req = build();
        assert_eq!(
            resource_attr(&req, "crossx.node.id").as_deref(),
            Some("node-test")
        );
        assert_eq!(
            resource_attr(&req, "host.name").as_deref(),
            Some("host-test")
        );
    }

    #[test]
    fn build_export_request_should_name_scope_crossx_agent_when_built() {
        let req = build();
        let scope = req.resource_metrics[0].scope_metrics[0]
            .scope
            .as_ref()
            .expect("scope missing");
        assert_eq!(scope.name, "crossx-agent");
    }

    #[test]
    fn build_export_request_should_mark_sums_monotonic_cumulative_when_kind_is_cumulative() {
        let req = build();
        let metric = metric_by_name(&req, "system.network.io");
        let Some(Data::Sum(sum)) = metric.data else {
            panic!("system.network.io should map to a Sum");
        };
        assert!(sum.is_monotonic, "sum must be monotonic");
        assert_eq!(
            sum.aggregation_temporality,
            AggregationTemporality::Cumulative as i32
        );
        let point = sum.data_points.first().expect("sum data point missing");
        assert!(
            point.start_time_unix_nano > 0,
            "cumulative sums need a start timestamp"
        );
    }

    #[test]
    fn build_export_request_should_map_gauge_samples_to_gauge_data_when_kind_is_gauge() {
        let req = build();
        let metric = metric_by_name(&req, "system.cpu.utilization");
        assert!(
            matches!(metric.data, Some(Data::Gauge(_))),
            "system.cpu.utilization should map to a Gauge"
        );
    }

    #[test]
    fn build_export_request_should_convert_millis_to_nanos_when_stamping_data_points() {
        let req = build();
        let expected_nanos = (TS_MS as u64) * 1_000_000;
        for name in ["system.cpu.utilization", "system.network.io"] {
            let metric = metric_by_name(&req, name);
            let points = match metric.data.expect("metric data missing") {
                Data::Gauge(g) => g.data_points,
                Data::Sum(s) => s.data_points,
                other => panic!("unexpected data kind for {name}: {other:?}"),
            };
            assert_eq!(points[0].time_unix_nano, expected_nanos, "{name} timestamp");
        }
    }

    #[test]
    fn build_export_request_should_copy_sample_attrs_onto_data_points_when_present() {
        let req = build();
        let metric = metric_by_name(&req, "system.network.io");
        let Some(Data::Sum(sum)) = metric.data else {
            panic!("system.network.io should map to a Sum");
        };
        let attrs = &sum.data_points[0].attributes;
        let direction = attrs
            .iter()
            .find(|kv| kv.key == "direction")
            .and_then(|kv| kv.value.as_ref())
            .and_then(|v| v.value.as_ref());
        assert!(
            matches!(direction, Some(any_value::Value::StringValue(s)) if s == "receive"),
            "direction attr should be receive"
        );
    }
}
