mod assertions;
mod helpers;
mod metric_assertions;
mod predicates;
mod types;

pub use assertions::{LogAssertion, MetricAssertion, SpanAssertion};
pub use metric_assertions::{ExponentialHistogramAssertion, HistogramAssertion, SummaryAssertion};
pub use types::{TestLogRecord, TestMetric, TestSpan};

use helpers::{format_any_value, format_attributes};
use opentelemetry_proto::tonic::{
    collector::logs::v1::ExportLogsServiceRequest,
    collector::metrics::v1::ExportMetricsServiceRequest,
    collector::trace::v1::ExportTraceServiceRequest,
};
use std::sync::Arc;

/// A mock collector that stores received OTLP logs, traces, and metrics for test assertions.
#[derive(Debug, Clone, Default)]
pub struct MockCollector {
    logs: Vec<TestLogRecord>,
    spans: Vec<TestSpan>,
    metrics: Vec<TestMetric>,
}

impl MockCollector {
    pub fn new() -> Self {
        Self::default()
    }

    fn logs_from_request(req: ExportLogsServiceRequest) -> Vec<TestLogRecord> {
        let mut log_records = vec![];
        for rl in req.resource_logs {
            let resource_attrs = Arc::new(rl.resource.map(|r| r.attributes).unwrap_or_default());

            for sl in rl.scope_logs {
                let scope_attrs = Arc::new(sl.scope.map(|s| s.attributes).unwrap_or_default());

                for lr in sl.log_records {
                    log_records.push(TestLogRecord {
                        log_record: lr,
                        resource_attrs: Arc::clone(&resource_attrs),
                        scope_attrs: Arc::clone(&scope_attrs),
                    });
                }
            }
        }
        log_records
    }

    pub fn add_logs(&mut self, req: ExportLogsServiceRequest) {
        self.logs.extend(Self::logs_from_request(req));
    }

    pub fn logs(&self) -> &[TestLogRecord] {
        &self.logs
    }

    pub fn log_count(&self) -> usize {
        self.logs.len()
    }

    pub fn clear(&mut self) {
        self.logs.clear();
        self.spans.clear();
        self.metrics.clear();
    }

    fn spans_from_request(req: ExportTraceServiceRequest) -> Vec<TestSpan> {
        let mut spans = vec![];
        for rt in req.resource_spans {
            let resource_attrs = Arc::new(rt.resource.map(|r| r.attributes).unwrap_or_default());

            for ss in rt.scope_spans {
                let scope_attrs = Arc::new(ss.scope.map(|s| s.attributes).unwrap_or_default());

                for span in ss.spans {
                    spans.push(TestSpan {
                        span,
                        resource_attrs: Arc::clone(&resource_attrs),
                        scope_attrs: Arc::clone(&scope_attrs),
                    });
                }
            }
        }
        spans
    }

    pub fn add_traces(&mut self, req: ExportTraceServiceRequest) {
        self.spans.extend(Self::spans_from_request(req));
    }

    pub fn spans(&self) -> &[TestSpan] {
        &self.spans
    }

    pub fn span_count(&self) -> usize {
        self.spans.len()
    }

    fn metrics_from_request(req: ExportMetricsServiceRequest) -> Vec<TestMetric> {
        let mut metrics = vec![];
        for rm in req.resource_metrics {
            let resource_attrs = Arc::new(rm.resource.map(|r| r.attributes).unwrap_or_default());

            for sm in rm.scope_metrics {
                let scope_attrs = Arc::new(sm.scope.map(|s| s.attributes).unwrap_or_default());

                for metric in sm.metrics {
                    metrics.push(TestMetric {
                        metric,
                        resource_attrs: Arc::clone(&resource_attrs),
                        scope_attrs: Arc::clone(&scope_attrs),
                    });
                }
            }
        }
        metrics
    }

    pub fn add_metrics(&mut self, req: ExportMetricsServiceRequest) {
        self.metrics.extend(Self::metrics_from_request(req));
    }

    pub fn metrics(&self) -> &[TestMetric] {
        &self.metrics
    }

    pub fn metric_count(&self) -> usize {
        self.metrics.len()
    }

    pub fn dump(&self) -> String {
        let mut output = format!("Mock Collector: {} log(s)\n", self.logs.len());
        for (idx, log) in self.logs.iter().enumerate() {
            output.push_str(&format!("\n[{}] ", idx));
            output.push_str(&format!("body={}", format_any_value(&log.log_record.body)));

            if !log.log_record.attributes.is_empty() {
                output.push_str(&format!(
                    ", attributes={}",
                    format_attributes(&log.log_record.attributes, 5)
                ));
            }

            if !log.resource_attrs.is_empty() {
                output.push_str(&format!(
                    ", resource_attrs={}",
                    format_attributes(&log.resource_attrs, 5)
                ));
            }

            if !log.scope_attrs.is_empty() {
                output.push_str(&format!(
                    ", scope_attrs={}",
                    format_attributes(&log.scope_attrs, 3)
                ));
            }
        }
        output
    }

    pub fn expect_log_with_body<S: Into<String>>(&self, body: S) -> LogAssertion<'_> {
        LogAssertion::new(&self.logs, Some(body.into()))
    }

    /// Starts building an assertion for logs without specifying a body.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use mock_collector::MockCollector;
    /// # let collector = MockCollector::new();
    /// collector
    ///     .expect_log()
    ///     .with_resource_attributes([("service.name", "my-service")])
    ///     .assert_at_least(5);
    /// ```
    pub fn expect_log(&self) -> LogAssertion<'_> {
        LogAssertion::new(&self.logs, None)
    }

    pub fn expect_span_with_name<S: Into<String>>(&self, name: S) -> SpanAssertion<'_> {
        SpanAssertion::new(&self.spans, Some(name.into()))
    }

    /// Starts building an assertion for spans without specifying a name.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use mock_collector::MockCollector;
    /// # let collector = MockCollector::new();
    /// collector
    ///     .expect_span()
    ///     .with_resource_attributes([("service.name", "my-service")])
    ///     .assert_at_least(10);
    /// ```
    pub fn expect_span(&self) -> SpanAssertion<'_> {
        SpanAssertion::new(&self.spans, None)
    }

    pub fn expect_metric_with_name<S: Into<String>>(&self, name: S) -> MetricAssertion<'_> {
        MetricAssertion::new(&self.metrics, Some(name.into()))
    }

    /// Starts building an assertion for metrics without specifying a name.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use mock_collector::MockCollector;
    /// # let collector = MockCollector::new();
    /// collector
    ///     .expect_metric()
    ///     .with_resource_attributes([("service.name", "my-service")])
    ///     .assert_at_least(5);
    /// ```
    pub fn expect_metric(&self) -> MetricAssertion<'_> {
        MetricAssertion::new(&self.metrics, None)
    }

    /// Starts building an assertion for histogram metrics with the specified name.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use mock_collector::MockCollector;
    /// # let collector = MockCollector::new();
    /// collector
    ///     .expect_histogram("http_request_duration")
    ///     .with_attributes([("method", "GET")])
    ///     .with_count_gte(100)
    ///     .with_sum_gte(5000.0)
    ///     .assert_exists();
    /// ```
    pub fn expect_histogram<S: Into<String>>(&self, name: S) -> HistogramAssertion<'_> {
        HistogramAssertion::new(&self.metrics, Some(name.into()))
    }

    /// Starts building an assertion for exponential histogram metrics with the specified name.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use mock_collector::MockCollector;
    /// # let collector = MockCollector::new();
    /// collector
    ///     .expect_exponential_histogram("latency")
    ///     .with_count_gte(100)
    ///     .with_sum_gte(5000.0)
    ///     .with_zero_count_lte(5)
    ///     .assert_exists();
    /// ```
    pub fn expect_exponential_histogram<S: Into<String>>(
        &self,
        name: S,
    ) -> ExponentialHistogramAssertion<'_> {
        ExponentialHistogramAssertion::new(&self.metrics, Some(name.into()))
    }

    /// Starts building an assertion for summary metrics with the specified name.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use mock_collector::MockCollector;
    /// # let collector = MockCollector::new();
    /// collector
    ///     .expect_summary("response_time")
    ///     .with_count_gte(100)
    ///     .with_sum_gte(5000.0)
    ///     .with_quantile_lte(0.5, 100.0)   // median <= 100ms
    ///     .with_quantile_lte(0.99, 500.0)  // p99 <= 500ms
    ///     .assert_exists();
    /// ```
    pub fn expect_summary<S: Into<String>>(&self, name: S) -> SummaryAssertion<'_> {
        SummaryAssertion::new(&self.metrics, Some(name.into()))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use opentelemetry_proto::tonic::common::v1::{
        AnyValue, ArrayValue, KeyValue, KeyValueList, any_value,
    };
    use predicates::{MetricValue, MetricValuePredicate};

    fn make_any_value(inner: any_value::Value) -> Option<AnyValue> {
        Some(AnyValue { value: Some(inner) })
    }

    #[test]
    fn test_format_any_value_string() {
        let value = make_any_value(any_value::Value::StringValue("hello".to_string()));
        assert_eq!(format_any_value(&value), "\"hello\"");
    }

    #[test]
    fn test_format_any_value_int() {
        let value = make_any_value(any_value::Value::IntValue(42));
        assert_eq!(format_any_value(&value), "42");
    }

    #[test]
    fn test_format_any_value_double() {
        let value = make_any_value(any_value::Value::DoubleValue(1.23456));
        assert_eq!(format_any_value(&value), "1.234560");
    }

    #[test]
    fn test_format_any_value_bool_true() {
        let value = make_any_value(any_value::Value::BoolValue(true));
        assert_eq!(format_any_value(&value), "true");
    }

    #[test]
    fn test_format_any_value_bool_false() {
        let value = make_any_value(any_value::Value::BoolValue(false));
        assert_eq!(format_any_value(&value), "false");
    }

    #[test]
    fn test_format_any_value_array() {
        let value = make_any_value(any_value::Value::ArrayValue(ArrayValue {
            values: vec![
                AnyValue {
                    value: Some(any_value::Value::StringValue("a".to_string())),
                },
                AnyValue {
                    value: Some(any_value::Value::IntValue(1)),
                },
            ],
        }));
        assert_eq!(format_any_value(&value), "[\"a\", 1]");
    }

    #[test]
    fn test_format_any_value_kvlist() {
        let value = make_any_value(any_value::Value::KvlistValue(KeyValueList {
            values: vec![KeyValue {
                key: "nested".to_string(),
                value: Some(AnyValue {
                    value: Some(any_value::Value::StringValue("value".to_string())),
                }),
            }],
        }));
        assert_eq!(format_any_value(&value), "{nested=\"value\"}");
    }

    #[test]
    fn test_format_any_value_bytes() {
        let value = make_any_value(any_value::Value::BytesValue(vec![1, 2, 3, 4, 5]));
        assert_eq!(format_any_value(&value), "<bytes: 5 bytes>");
    }

    #[test]
    fn test_format_any_value_none() {
        assert_eq!(format_any_value(&None), "<none>");
    }

    #[test]
    fn test_format_any_value_empty_inner() {
        let value = Some(AnyValue { value: None });
        assert_eq!(format_any_value(&value), "<empty>");
    }

    #[test]
    fn test_format_attributes_single() {
        let attrs = vec![KeyValue {
            key: "service.name".to_string(),
            value: make_any_value(any_value::Value::StringValue("my-service".to_string())),
        }];
        assert_eq!(
            format_attributes(&attrs, 5),
            "{service.name=\"my-service\"}"
        );
    }

    #[test]
    fn test_format_attributes_multiple() {
        let attrs = vec![
            KeyValue {
                key: "key1".to_string(),
                value: make_any_value(any_value::Value::StringValue("val1".to_string())),
            },
            KeyValue {
                key: "key2".to_string(),
                value: make_any_value(any_value::Value::IntValue(42)),
            },
        ];
        assert_eq!(format_attributes(&attrs, 5), "{key1=\"val1\", key2=42}");
    }

    #[test]
    fn test_format_attributes_truncated() {
        let attrs = vec![
            KeyValue {
                key: "a".to_string(),
                value: make_any_value(any_value::Value::IntValue(1)),
            },
            KeyValue {
                key: "b".to_string(),
                value: make_any_value(any_value::Value::IntValue(2)),
            },
            KeyValue {
                key: "c".to_string(),
                value: make_any_value(any_value::Value::IntValue(3)),
            },
            KeyValue {
                key: "d".to_string(),
                value: make_any_value(any_value::Value::IntValue(4)),
            },
        ];
        assert_eq!(format_attributes(&attrs, 2), "{a=1, b=2, ... +2}");
    }

    #[test]
    fn test_format_attributes_empty() {
        let attrs: Vec<KeyValue> = vec![];
        assert_eq!(format_attributes(&attrs, 5), "{}");
    }

    #[test]
    #[should_panic(expected = "No logs matched the assertion")]
    fn test_errors_if_no_logs_match() {
        let mc = MockCollector::new();
        mc.expect_log_with_body("hi there")
            .with_attributes([("key", "value")])
            .with_resource_attributes([("key", "value")])
            .assert_exists();
    }

    #[test]
    fn test_log_count() {
        let mc = MockCollector::new();
        assert_eq!(mc.log_count(), 0);
    }

    #[test]
    fn test_default() {
        let mc = MockCollector::default();
        assert_eq!(mc.log_count(), 0);
    }

    #[test]
    fn test_with_attribute_accepts_string() {
        let mc = MockCollector::new();
        let _assertion = mc
            .expect_log_with_body("test")
            .with_attribute("key", "value");
    }

    #[test]
    fn test_with_attribute_accepts_int() {
        let mc = MockCollector::new();
        let _assertion = mc.expect_log_with_body("test").with_attribute("count", 42);
    }

    #[test]
    fn test_with_attribute_accepts_bool() {
        let mc = MockCollector::new();
        let _assertion = mc
            .expect_log_with_body("test")
            .with_attribute("enabled", true);
    }

    #[test]
    fn test_with_attribute_accepts_float() {
        let mc = MockCollector::new();
        let _assertion = mc.expect_log_with_body("test").with_attribute("ratio", 0.5);
    }

    #[test]
    fn test_with_attribute_chaining_mixed_types() {
        let mc = MockCollector::new();
        let _assertion = mc
            .expect_log_with_body("test")
            .with_attribute("http.method", "GET")
            .with_attribute("http.status_code", 200)
            .with_attribute("success", true)
            .with_attribute("duration_ms", 1.5);
    }

    #[test]
    fn test_with_resource_attribute_mixed_types() {
        let mc = MockCollector::new();
        let _assertion = mc
            .expect_log_with_body("test")
            .with_resource_attribute("service.name", "my-service")
            .with_resource_attribute("service.version", 1)
            .with_resource_attribute("service.active", true);
    }

    #[test]
    fn test_with_scope_attribute_mixed_types() {
        let mc = MockCollector::new();
        let _assertion = mc
            .expect_log_with_body("test")
            .with_scope_attribute("scope.name", "test-scope")
            .with_scope_attribute("scope.version", 2);
    }

    #[test]
    fn test_span_with_attribute_mixed_types() {
        let mc = MockCollector::new();
        let _assertion = mc
            .expect_span_with_name("test-span")
            .with_attribute("http.method", "POST")
            .with_attribute("http.status_code", 201)
            .with_attribute("retry", false);
    }

    #[test]
    fn test_metric_with_attribute_mixed_types() {
        let mc = MockCollector::new();
        let _assertion = mc
            .expect_metric_with_name("request_count")
            .with_attribute("endpoint", "/api/v1")
            .with_attribute("status", 200)
            .with_attribute("cached", true);
    }

    mod metric_value_tests {
        use super::*;
        use opentelemetry_proto::tonic::metrics::v1::{
            Gauge, Metric, NumberDataPoint, Sum, metric::Data, number_data_point,
        };

        fn make_gauge_metric(name: &str, values: &[number_data_point::Value]) -> TestMetric {
            let data_points: Vec<NumberDataPoint> = values
                .iter()
                .map(|v| NumberDataPoint {
                    value: Some(*v),
                    ..Default::default()
                })
                .collect();

            TestMetric {
                resource_attrs: Arc::new(vec![]),
                scope_attrs: Arc::new(vec![]),
                metric: Metric {
                    name: name.to_string(),
                    data: Some(Data::Gauge(Gauge { data_points })),
                    ..Default::default()
                },
            }
        }

        fn make_sum_metric(name: &str, values: &[number_data_point::Value]) -> TestMetric {
            let data_points: Vec<NumberDataPoint> = values
                .iter()
                .map(|v| NumberDataPoint {
                    value: Some(*v),
                    ..Default::default()
                })
                .collect();

            TestMetric {
                resource_attrs: Arc::new(vec![]),
                scope_attrs: Arc::new(vec![]),
                metric: Metric {
                    name: name.to_string(),
                    data: Some(Data::Sum(Sum {
                        data_points,
                        ..Default::default()
                    })),
                    ..Default::default()
                },
            }
        }

        #[test]
        fn test_metric_value_from_i64() {
            let v: MetricValue = 42i64.into();
            assert!(matches!(v, MetricValue::Int(42)));
        }

        #[test]
        fn test_metric_value_from_i32() {
            let v: MetricValue = 42i32.into();
            assert!(matches!(v, MetricValue::Int(42)));
        }

        #[test]
        fn test_metric_value_from_f64() {
            let v: MetricValue = 1.234f64.into();
            assert!(matches!(v, MetricValue::Double(d) if (d - 1.234).abs() < f64::EPSILON));
        }

        #[test]
        fn test_metric_value_from_f32() {
            let v: MetricValue = 1.234f32.into();
            assert!(matches!(v, MetricValue::Double(_)));
        }

        #[test]
        fn test_metric_value_approx_eq_int() {
            let a = MetricValue::Int(42);
            let b = MetricValue::Int(42);
            assert!(a.approx_eq(&b));

            let c = MetricValue::Int(43);
            assert!(!a.approx_eq(&c));
        }

        #[test]
        fn test_metric_value_approx_eq_double() {
            let a = MetricValue::Double(1.234);
            let b = MetricValue::Double(1.234);
            assert!(a.approx_eq(&b));

            let c = MetricValue::Double(1.235);
            assert!(!a.approx_eq(&c));
        }

        #[test]
        fn test_metric_value_approx_eq_mixed() {
            let a = MetricValue::Int(42);
            let b = MetricValue::Double(42.0);
            assert!(a.approx_eq(&b));
        }

        #[test]
        fn test_metric_value_predicate_eq() {
            let pred = MetricValuePredicate::Eq(MetricValue::Int(42));
            assert!(pred.matches(&MetricValue::Int(42)));
            assert!(!pred.matches(&MetricValue::Int(43)));
        }

        #[test]
        fn test_metric_value_predicate_gt() {
            let pred = MetricValuePredicate::Gt(MetricValue::Int(42));
            assert!(pred.matches(&MetricValue::Int(43)));
            assert!(!pred.matches(&MetricValue::Int(42)));
            assert!(!pred.matches(&MetricValue::Int(41)));
        }

        #[test]
        fn test_metric_value_predicate_gte() {
            let pred = MetricValuePredicate::Gte(MetricValue::Int(42));
            assert!(pred.matches(&MetricValue::Int(43)));
            assert!(pred.matches(&MetricValue::Int(42)));
            assert!(!pred.matches(&MetricValue::Int(41)));
        }

        #[test]
        fn test_metric_value_predicate_lt() {
            let pred = MetricValuePredicate::Lt(MetricValue::Int(42));
            assert!(pred.matches(&MetricValue::Int(41)));
            assert!(!pred.matches(&MetricValue::Int(42)));
            assert!(!pred.matches(&MetricValue::Int(43)));
        }

        #[test]
        fn test_metric_value_predicate_lte() {
            let pred = MetricValuePredicate::Lte(MetricValue::Int(42));
            assert!(pred.matches(&MetricValue::Int(41)));
            assert!(pred.matches(&MetricValue::Int(42)));
            assert!(!pred.matches(&MetricValue::Int(43)));
        }

        #[test]
        fn test_metric_assertion_with_value_eq_int() {
            let mut mc = MockCollector::new();
            mc.metrics.push(make_gauge_metric(
                "test_metric",
                &[number_data_point::Value::AsInt(42)],
            ));

            mc.expect_metric_with_name("test_metric")
                .with_value_eq(42)
                .assert_exists();
        }

        #[test]
        fn test_metric_assertion_with_value_eq_double() {
            let mut mc = MockCollector::new();
            mc.metrics.push(make_gauge_metric(
                "test_metric",
                &[number_data_point::Value::AsDouble(1.234)],
            ));

            mc.expect_metric_with_name("test_metric")
                .with_value_eq(1.234)
                .assert_exists();
        }

        #[test]
        fn test_metric_assertion_with_value_gt() {
            let mut mc = MockCollector::new();
            mc.metrics.push(make_sum_metric(
                "request_count",
                &[number_data_point::Value::AsInt(100)],
            ));

            mc.expect_metric_with_name("request_count")
                .with_value_gt(50)
                .assert_exists();
        }

        #[test]
        fn test_metric_assertion_with_value_gte() {
            let mut mc = MockCollector::new();
            mc.metrics.push(make_gauge_metric(
                "temperature",
                &[number_data_point::Value::AsDouble(25.0)],
            ));

            mc.expect_metric_with_name("temperature")
                .with_value_gte(25.0)
                .assert_exists();

            mc.expect_metric_with_name("temperature")
                .with_value_gte(24.0)
                .assert_exists();
        }

        #[test]
        fn test_metric_assertion_with_value_lt() {
            let mut mc = MockCollector::new();
            mc.metrics.push(make_gauge_metric(
                "error_rate",
                &[number_data_point::Value::AsDouble(0.01)],
            ));

            mc.expect_metric_with_name("error_rate")
                .with_value_lt(0.05)
                .assert_exists();
        }

        #[test]
        fn test_metric_assertion_with_value_lte() {
            let mut mc = MockCollector::new();
            mc.metrics.push(make_sum_metric(
                "latency_ms",
                &[number_data_point::Value::AsInt(100)],
            ));

            mc.expect_metric_with_name("latency_ms")
                .with_value_lte(100)
                .assert_exists();

            mc.expect_metric_with_name("latency_ms")
                .with_value_lte(200)
                .assert_exists();
        }

        #[test]
        fn test_metric_assertion_chained_value_predicates() {
            let mut mc = MockCollector::new();
            mc.metrics.push(make_gauge_metric(
                "response_time",
                &[number_data_point::Value::AsDouble(150.0)],
            ));

            mc.expect_metric_with_name("response_time")
                .with_value_gte(100.0)
                .with_value_lte(200.0)
                .assert_exists();
        }

        #[test]
        #[should_panic(expected = "No metrics matched the assertion")]
        fn test_metric_assertion_value_not_found() {
            let mut mc = MockCollector::new();
            mc.metrics.push(make_gauge_metric(
                "counter",
                &[number_data_point::Value::AsInt(10)],
            ));

            mc.expect_metric_with_name("counter")
                .with_value_eq(42)
                .assert_exists();
        }

        #[test]
        #[should_panic(expected = "No metrics matched the assertion")]
        fn test_metric_assertion_chained_predicates_no_match() {
            let mut mc = MockCollector::new();
            mc.metrics.push(make_gauge_metric(
                "value",
                &[number_data_point::Value::AsInt(50)],
            ));

            mc.expect_metric_with_name("value")
                .with_value_gte(100)
                .with_value_lte(200)
                .assert_exists();
        }

        #[test]
        fn test_metric_assertion_multiple_data_points() {
            let mut mc = MockCollector::new();
            mc.metrics.push(make_gauge_metric(
                "multi_point",
                &[
                    number_data_point::Value::AsInt(10),
                    number_data_point::Value::AsInt(50),
                    number_data_point::Value::AsInt(100),
                ],
            ));

            mc.expect_metric_with_name("multi_point")
                .with_value_eq(50)
                .assert_exists();

            mc.expect_metric_with_name("multi_point")
                .with_value_gte(100)
                .assert_exists();

            mc.expect_metric_with_name("multi_point")
                .with_value_lt(20)
                .assert_exists();
        }

        #[test]
        fn test_metric_value_display() {
            assert_eq!(format!("{}", MetricValue::Int(42)), "42");
            assert_eq!(format!("{}", MetricValue::Double(1.234)), "1.234");
        }

        #[test]
        fn test_metric_value_predicate_format() {
            assert_eq!(
                MetricValuePredicate::Eq(MetricValue::Int(42)).format(),
                "== 42"
            );
            assert_eq!(
                MetricValuePredicate::Gt(MetricValue::Int(42)).format(),
                "> 42"
            );
            assert_eq!(
                MetricValuePredicate::Gte(MetricValue::Double(1.234)).format(),
                ">= 1.234"
            );
            assert_eq!(
                MetricValuePredicate::Lt(MetricValue::Int(100)).format(),
                "< 100"
            );
            assert_eq!(
                MetricValuePredicate::Lte(MetricValue::Double(99.9)).format(),
                "<= 99.9"
            );
        }

        #[test]
        fn test_format_criteria_includes_value_predicates() {
            let mc = MockCollector::new();
            let assertion = mc
                .expect_metric_with_name("test")
                .with_value_gte(100)
                .with_value_lt(200);

            let criteria = assertion.format_criteria();
            assert!(criteria.contains("value(>= 100 AND < 200)"));
        }
    }
}
