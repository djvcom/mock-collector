use opentelemetry_proto::tonic::{
    collector::logs::v1::ExportLogsServiceRequest,
    collector::metrics::v1::ExportMetricsServiceRequest,
    collector::trace::v1::ExportTraceServiceRequest,
    common::v1::{AnyValue, KeyValue},
    logs::v1::LogRecord,
    metrics::v1::Metric,
    trace::v1::Span,
};
use serde_json::Value;
use std::sync::Arc;

fn format_any_value(value: &Option<AnyValue>) -> String {
    use opentelemetry_proto::tonic::common::v1::any_value::Value as AnyValueInner;

    match value {
        Some(av) => match &av.value {
            Some(AnyValueInner::StringValue(s)) => format!("\"{}\"", s),
            Some(AnyValueInner::IntValue(i)) => i.to_string(),
            Some(AnyValueInner::DoubleValue(d)) => format!("{:.6}", d),
            Some(AnyValueInner::BoolValue(b)) => b.to_string(),
            Some(AnyValueInner::ArrayValue(arr)) => {
                let items: Vec<String> = arr
                    .values
                    .iter()
                    .map(|v| format_any_value(&Some(v.clone())))
                    .collect();
                format!("[{}]", items.join(", "))
            }
            Some(AnyValueInner::KvlistValue(kv)) => {
                let items: Vec<String> = kv
                    .values
                    .iter()
                    .map(|kv| format!("{}={}", kv.key, format_any_value(&kv.value)))
                    .collect();
                format!("{{{}}}", items.join(", "))
            }
            Some(AnyValueInner::BytesValue(b)) => format!("<bytes: {} bytes>", b.len()),
            None => "<empty>".to_string(),
        },
        None => "<none>".to_string(),
    }
}

fn format_attributes(attrs: &[KeyValue], max_items: usize) -> String {
    let mut output = String::from("{");
    for (i, attr) in attrs.iter().take(max_items).enumerate() {
        if i > 0 {
            output.push_str(", ");
        }
        output.push_str(&attr.key);
        output.push('=');
        output.push_str(&format_any_value(&attr.value));
    }
    if attrs.len() > max_items {
        output.push_str(&format!(", ... +{}", attrs.len() - max_items));
    }
    output.push('}');
    output
}

/// A flattened log record with resource and scope attributes copied for easy test assertions.
///
/// We flatten the OTLP structure such that a copy of the resource attrs and scope attrs
/// are available on each test log record to make it easy to assert against.
#[derive(Debug, Clone)]
pub struct TestLogRecord {
    resource_attrs: Arc<Vec<KeyValue>>,
    scope_attrs: Arc<Vec<KeyValue>>,
    log_record: LogRecord,
}

impl TestLogRecord {
    /// Returns a reference to the resource attributes.
    pub fn resource_attrs(&self) -> &[KeyValue] {
        &self.resource_attrs
    }

    /// Returns a reference to the scope attributes.
    pub fn scope_attrs(&self) -> &[KeyValue] {
        &self.scope_attrs
    }

    /// Returns a reference to the underlying log record.
    pub fn log_record(&self) -> &LogRecord {
        &self.log_record
    }
}

/// A flattened span with resource and scope attributes copied for easy test assertions.
///
/// We flatten the OTLP structure such that a copy of the resource attrs and scope attrs
/// are available on each test span to make it easy to assert against.
#[derive(Debug, Clone)]
pub struct TestSpan {
    resource_attrs: Arc<Vec<KeyValue>>,
    scope_attrs: Arc<Vec<KeyValue>>,
    span: Span,
}

impl TestSpan {
    /// Returns a reference to the resource attributes.
    pub fn resource_attrs(&self) -> &[KeyValue] {
        &self.resource_attrs
    }

    /// Returns a reference to the scope attributes.
    pub fn scope_attrs(&self) -> &[KeyValue] {
        &self.scope_attrs
    }

    /// Returns a reference to the underlying span.
    pub fn span(&self) -> &Span {
        &self.span
    }
}

/// A flattened metric with resource and scope attributes copied for easy test assertions.
///
/// We flatten the OTLP structure such that a copy of the resource attrs and scope attrs
/// are available on each test metric to make it easy to assert against.
#[derive(Debug, Clone)]
pub struct TestMetric {
    resource_attrs: Arc<Vec<KeyValue>>,
    scope_attrs: Arc<Vec<KeyValue>>,
    metric: Metric,
}

impl TestMetric {
    /// Returns a reference to the resource attributes.
    pub fn resource_attrs(&self) -> &[KeyValue] {
        &self.resource_attrs
    }

    /// Returns a reference to the scope attributes.
    pub fn scope_attrs(&self) -> &[KeyValue] {
        &self.scope_attrs
    }

    /// Returns a reference to the underlying metric.
    pub fn metric(&self) -> &Metric {
        &self.metric
    }
}

/// A mock collector that stores received OTLP logs, traces, and metrics for test assertions.
#[derive(Debug, Clone, Default)]
pub struct MockCollector {
    logs: Vec<TestLogRecord>,
    spans: Vec<TestSpan>,
    metrics: Vec<TestMetric>,
}

impl MockCollector {
    /// Creates a new empty mock collector.
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

    /// Adds logs from an OTLP export request to the collector.
    pub fn add_logs(&mut self, req: ExportLogsServiceRequest) {
        self.logs.extend(Self::logs_from_request(req));
    }

    /// Returns a reference to all collected logs.
    pub fn logs(&self) -> &[TestLogRecord] {
        &self.logs
    }

    /// Returns the total number of collected logs.
    pub fn log_count(&self) -> usize {
        self.logs.len()
    }

    /// Clears all collected logs, spans, and metrics.
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

    /// Adds traces from an OTLP export request to the collector.
    pub fn add_traces(&mut self, req: ExportTraceServiceRequest) {
        self.spans.extend(Self::spans_from_request(req));
    }

    /// Returns a reference to all collected spans.
    pub fn spans(&self) -> &[TestSpan] {
        &self.spans
    }

    /// Returns the total number of collected spans.
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

    /// Adds metrics from an OTLP export request to the collector.
    pub fn add_metrics(&mut self, req: ExportMetricsServiceRequest) {
        self.metrics.extend(Self::metrics_from_request(req));
    }

    /// Returns a reference to all collected metrics.
    pub fn metrics(&self) -> &[TestMetric] {
        &self.metrics
    }

    /// Returns the total number of collected metrics.
    pub fn metric_count(&self) -> usize {
        self.metrics.len()
    }

    /// Returns a formatted string representation of all logs for debugging.
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

    /// Starts building an assertion for logs with the specified body.
    pub fn expect_log_with_body<S: Into<String>>(&self, body: S) -> LogAssertion<'_> {
        LogAssertion {
            logs: &self.logs,
            body: Some(body.into()),
            attributes: None,
            resource_attributes: None,
            scope_attributes: None,
            severity_number: None,
            severity_text: None,
        }
    }

    /// Starts building an assertion for logs without specifying a body.
    ///
    /// This is useful when you want to assert on logs based only on their attributes,
    /// resource attributes, or scope attributes, without filtering by body content.
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
        LogAssertion {
            logs: &self.logs,
            body: None,
            attributes: None,
            resource_attributes: None,
            scope_attributes: None,
            severity_number: None,
            severity_text: None,
        }
    }

    /// Starts building an assertion for spans with the specified name.
    pub fn expect_span_with_name<S: Into<String>>(&self, name: S) -> SpanAssertion<'_> {
        SpanAssertion {
            spans: &self.spans,
            name: Some(name.into()),
            attributes: None,
            resource_attributes: None,
            scope_attributes: None,
            event_names: None,
            event_with_attributes: None,
        }
    }

    /// Starts building an assertion for spans without specifying a name.
    ///
    /// This is useful when you want to assert on spans based only on their attributes,
    /// resource attributes, or scope attributes, without filtering by name.
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
        SpanAssertion {
            spans: &self.spans,
            name: None,
            attributes: None,
            resource_attributes: None,
            scope_attributes: None,
            event_names: None,
            event_with_attributes: None,
        }
    }

    /// Starts building an assertion for metrics with the specified name.
    pub fn expect_metric_with_name<S: Into<String>>(&self, name: S) -> MetricAssertion<'_> {
        MetricAssertion {
            metrics: &self.metrics,
            name: Some(name.into()),
            attributes: None,
            resource_attributes: None,
            scope_attributes: None,
            value_predicates: Vec::new(),
        }
    }

    /// Starts building an assertion for metrics without specifying a name.
    ///
    /// This is useful when you want to assert on metrics based only on their attributes,
    /// resource attributes, or scope attributes, without filtering by name.
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
        MetricAssertion {
            metrics: &self.metrics,
            name: None,
            attributes: None,
            resource_attributes: None,
            scope_attributes: None,
            value_predicates: Vec::new(),
        }
    }
}

/// A builder for constructing log assertions.
#[derive(Debug)]
pub struct LogAssertion<'a> {
    logs: &'a [TestLogRecord],
    body: Option<String>,
    attributes: Option<Vec<(String, Value)>>,
    resource_attributes: Option<Vec<(String, Value)>>,
    scope_attributes: Option<Vec<(String, Value)>>,
    severity_number: Option<i32>,
    severity_text: Option<String>,
}

impl<'a> LogAssertion<'a> {
    /// Asserts that at least one log matches all specified criteria.
    ///
    /// # Panics
    ///
    /// Panics with a descriptive message if no matching log is found.
    #[track_caller]
    pub fn assert_exists(&self) {
        if !self.matches_any() {
            panic!("{}", self.build_error_message());
        }
    }

    /// Asserts that no logs match the specified criteria.
    ///
    /// # Panics
    ///
    /// Panics if any logs match the criteria.
    #[track_caller]
    pub fn assert_not_exists(&self) {
        if self.matches_any() {
            panic!(
                "Expected no logs to match, but found {} matching log(s).\nCriteria: {}",
                self.count(),
                self.format_criteria()
            );
        }
    }

    /// Asserts that exactly the specified number of logs match the criteria.
    ///
    /// # Panics
    ///
    /// Panics if the count doesn't match.
    #[track_caller]
    pub fn assert_count(&self, expected: usize) {
        let actual = self.count();
        if actual != expected {
            panic!(
                "Expected {} matching log(s), but found {}.\nCriteria: {}\n\n{}",
                expected,
                actual,
                self.format_criteria(),
                self.format_matching_logs()
            );
        }
    }

    /// Asserts that at least the specified number of logs match the criteria.
    ///
    /// # Panics
    ///
    /// Panics if fewer logs match.
    #[track_caller]
    pub fn assert_at_least(&self, min: usize) {
        let actual = self.count();
        if actual < min {
            panic!(
                "Expected at least {} matching log(s), but found {}.\nCriteria: {}",
                min,
                actual,
                self.format_criteria()
            );
        }
    }

    /// Asserts that no more than the specified number of logs match the criteria.
    ///
    /// # Panics
    ///
    /// Panics if more logs match.
    #[track_caller]
    pub fn assert_at_most(&self, max: usize) {
        let actual = self.count();
        if actual > max {
            panic!(
                "Expected at most {} matching log(s), but found {}.\nCriteria: {}",
                max,
                actual,
                self.format_criteria()
            );
        }
    }

    /// Returns the number of logs that match the criteria.
    #[must_use = "the count should be used"]
    pub fn count(&self) -> usize {
        self.logs.iter().filter(|log| self.matches(log)).count()
    }

    /// Returns all logs that match the criteria.
    #[must_use = "the matching items should be used"]
    pub fn get_all(&self) -> Vec<&TestLogRecord> {
        self.logs.iter().filter(|log| self.matches(log)).collect()
    }

    /// Adds log attribute criteria to the assertion.
    ///
    /// All attributes must have the same value type. For mixed types, use
    /// [`with_attribute`](Self::with_attribute) instead.
    #[must_use]
    pub fn with_attributes<I, K, V>(mut self, attributes: I) -> Self
    where
        I: IntoIterator<Item = (K, V)>,
        K: Into<String>,
        V: Into<Value>,
    {
        self.attributes = Some(
            attributes
                .into_iter()
                .map(|(k, v)| (k.into(), v.into()))
                .collect(),
        );
        self
    }

    /// Adds a single log attribute criterion to the assertion.
    ///
    /// This method can be chained to add multiple attributes of different types:
    ///
    /// ```ignore
    /// collector
    ///     .expect_log_with_body("request processed")
    ///     .with_attribute("http.status_code", 200)
    ///     .with_attribute("http.method", "GET")
    ///     .with_attribute("success", true)
    ///     .assert_exists();
    /// ```
    #[must_use]
    pub fn with_attribute<K, V>(mut self, key: K, value: V) -> Self
    where
        K: Into<String>,
        V: Into<Value>,
    {
        self.attributes
            .get_or_insert_with(Vec::new)
            .push((key.into(), value.into()));
        self
    }

    /// Adds resource attribute criteria to the assertion.
    ///
    /// All attributes must have the same value type. For mixed types, use
    /// [`with_resource_attribute`](Self::with_resource_attribute) instead.
    #[must_use]
    pub fn with_resource_attributes<I, K, V>(mut self, resource_attributes: I) -> Self
    where
        I: IntoIterator<Item = (K, V)>,
        K: Into<String>,
        V: Into<Value>,
    {
        self.resource_attributes = Some(
            resource_attributes
                .into_iter()
                .map(|(k, v)| (k.into(), v.into()))
                .collect(),
        );
        self
    }

    /// Adds a single resource attribute criterion to the assertion.
    #[must_use]
    pub fn with_resource_attribute<K, V>(mut self, key: K, value: V) -> Self
    where
        K: Into<String>,
        V: Into<Value>,
    {
        self.resource_attributes
            .get_or_insert_with(Vec::new)
            .push((key.into(), value.into()));
        self
    }

    /// Adds scope attribute criteria to the assertion.
    ///
    /// All attributes must have the same value type. For mixed types, use
    /// [`with_scope_attribute`](Self::with_scope_attribute) instead.
    #[must_use]
    pub fn with_scope_attributes<I, K, V>(mut self, scope_attributes: I) -> Self
    where
        I: IntoIterator<Item = (K, V)>,
        K: Into<String>,
        V: Into<Value>,
    {
        self.scope_attributes = Some(
            scope_attributes
                .into_iter()
                .map(|(k, v)| (k.into(), v.into()))
                .collect(),
        );
        self
    }

    /// Adds a single scope attribute criterion to the assertion.
    #[must_use]
    pub fn with_scope_attribute<K, V>(mut self, key: K, value: V) -> Self
    where
        K: Into<String>,
        V: Into<Value>,
    {
        self.scope_attributes
            .get_or_insert_with(Vec::new)
            .push((key.into(), value.into()));
        self
    }

    /// Adds severity number criteria to the assertion.
    ///
    /// Use the `SeverityNumber` enum from `opentelemetry_proto::tonic::logs::v1`.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use mock_collector::MockCollector;
    /// use opentelemetry_proto::tonic::logs::v1::SeverityNumber;
    ///
    /// # let collector = MockCollector::new();
    /// // Assert at least one ERROR level log exists
    /// collector
    ///     .expect_log()
    ///     .with_severity(SeverityNumber::Error)
    ///     .assert_exists();
    ///
    /// // Assert at least 3 DEBUG logs from a service
    /// collector
    ///     .expect_log()
    ///     .with_severity(SeverityNumber::Debug)
    ///     .with_resource_attributes([("service.name", "my-service")])
    ///     .assert_at_least(3);
    /// ```
    #[must_use]
    pub fn with_severity(
        mut self,
        severity: opentelemetry_proto::tonic::logs::v1::SeverityNumber,
    ) -> Self {
        self.severity_number = Some(severity as i32);
        self
    }

    /// Adds severity text criteria to the assertion.
    ///
    /// This matches the `severity_text` field, which is the string representation
    /// of the log level (e.g., "INFO", "ERROR", "DEBUG").
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use mock_collector::MockCollector;
    /// # let collector = MockCollector::new();
    /// collector
    ///     .expect_log()
    ///     .with_severity_text("ERROR")
    ///     .assert_exists();
    /// ```
    #[must_use]
    pub fn with_severity_text<S: Into<String>>(mut self, severity_text: S) -> Self {
        self.severity_text = Some(severity_text.into());
        self
    }

    fn matches_any(&self) -> bool {
        self.logs.iter().any(|log| self.matches(log))
    }

    fn matches(&self, test_log: &TestLogRecord) -> bool {
        // Check body if specified
        if let Some(expected_body) = &self.body {
            if let Some(body) = &test_log.log_record.body {
                if let Some(string_value) = &body.value {
                    use opentelemetry_proto::tonic::common::v1::any_value::Value as AnyValue;
                    match string_value {
                        AnyValue::StringValue(s) if s == expected_body => {}
                        _ => return false,
                    }
                } else {
                    return false;
                }
            } else {
                return false;
            }
        }

        // Check attributes if specified
        if let Some(expected_attrs) = &self.attributes
            && !Self::check_attributes(&test_log.log_record.attributes, expected_attrs)
        {
            return false;
        }

        // Check resource attributes if specified
        if let Some(expected_res_attrs) = &self.resource_attributes
            && !Self::check_attributes(&test_log.resource_attrs, expected_res_attrs)
        {
            return false;
        }

        // Check scope attributes if specified
        if let Some(expected_scope_attrs) = &self.scope_attributes
            && !Self::check_attributes(&test_log.scope_attrs, expected_scope_attrs)
        {
            return false;
        }

        // Check severity number if specified
        if let Some(expected_severity) = self.severity_number
            && test_log.log_record.severity_number != expected_severity
        {
            return false;
        }

        // Check severity text if specified
        if let Some(ref expected_text) = self.severity_text
            && &test_log.log_record.severity_text != expected_text
        {
            return false;
        }

        true
    }

    fn check_attributes(attrs: &[KeyValue], expected: &[(String, Value)]) -> bool {
        expected.iter().all(|(key, value)| {
            attrs.iter().any(|kv| {
                if kv.key != *key {
                    return false;
                }
                if let Some(any_value) = &kv.value {
                    if let Some(v) = &any_value.value {
                        Self::any_value_matches(v, value)
                    } else {
                        false
                    }
                } else {
                    false
                }
            })
        })
    }

    fn any_value_matches(
        any_value: &opentelemetry_proto::tonic::common::v1::any_value::Value,
        expected: &Value,
    ) -> bool {
        use opentelemetry_proto::tonic::common::v1::any_value::Value as AnyValue;
        match (any_value, expected) {
            (AnyValue::StringValue(s), Value::String(exp)) => s == exp,
            (AnyValue::BoolValue(b), Value::Bool(exp)) => b == exp,
            (AnyValue::IntValue(i), Value::Number(exp)) => {
                exp.as_i64().map(|n| *i == n).unwrap_or(false)
            }
            (AnyValue::DoubleValue(d), Value::Number(exp)) => exp
                .as_f64()
                .map(|n| (*d - n).abs() < f64::EPSILON)
                .unwrap_or(false),
            _ => false,
        }
    }

    fn format_criteria(&self) -> String {
        let mut criteria = Vec::new();
        if let Some(body) = &self.body {
            criteria.push(format!("body={:?}", body));
        }
        if let Some(severity_num) = self.severity_number {
            criteria.push(format!("severity_number={}", severity_num));
        }
        if let Some(ref severity_txt) = self.severity_text {
            criteria.push(format!("severity_text={:?}", severity_txt));
        }
        if let Some(attrs) = &self.attributes {
            criteria.push(format!("attributes={:?}", attrs));
        }
        if let Some(res_attrs) = &self.resource_attributes {
            criteria.push(format!("resource_attributes={:?}", res_attrs));
        }
        if let Some(scope_attrs) = &self.scope_attributes {
            criteria.push(format!("scope_attributes={:?}", scope_attrs));
        }
        criteria.join(", ")
    }

    fn format_matching_logs(&self) -> String {
        let matching: Vec<_> = self.get_all();
        if matching.is_empty() {
            return String::new();
        }

        let mut output = String::from("Matching logs:\n");
        for (idx, log) in matching.iter().enumerate() {
            output.push_str(&format!("  [{}] ", idx));
            if let Some(body) = &log.log_record.body {
                use opentelemetry_proto::tonic::common::v1::any_value::Value as AnyValue;
                if let Some(AnyValue::StringValue(s)) = &body.value {
                    output.push_str(&format!("body=\"{}\"", s));
                }
            }
            output.push('\n');
        }
        output
    }

    fn build_error_message(&self) -> String {
        let mut msg = String::from("No logs matched the assertion.\n\n");
        msg.push_str(&format!("Expected:\n  {}\n\n", self.format_criteria()));
        msg.push_str(&format!("Found {} log(s) in collector", self.logs.len()));

        if !self.logs.is_empty() {
            msg.push_str(":\n");
            for (idx, log) in self.logs.iter().enumerate().take(10) {
                msg.push_str(&format!("  [{}] ", idx));
                msg.push_str(&format!("body={}", format_any_value(&log.log_record.body)));

                if !log.log_record.attributes.is_empty() {
                    msg.push_str(&format!(
                        ", attributes={}",
                        format_attributes(&log.log_record.attributes, 3)
                    ));
                }

                if !log.resource_attrs.is_empty() {
                    msg.push_str(&format!(
                        ", resource_attrs={}",
                        format_attributes(&log.resource_attrs, 3)
                    ));
                }

                if !log.scope_attrs.is_empty() {
                    msg.push_str(&format!(
                        ", scope_attrs={}",
                        format_attributes(&log.scope_attrs, 3)
                    ));
                }

                msg.push('\n');
            }

            if self.logs.len() > 10 {
                msg.push_str(&format!("  ... and {} more\n", self.logs.len() - 10));
            }
        }

        msg
    }
}

/// Type alias for event specifications with attributes: (event_name, attributes).
type EventWithAttributes = Vec<(String, Vec<(String, Value)>)>;

/// A builder for constructing span assertions.
#[derive(Debug)]
pub struct SpanAssertion<'a> {
    spans: &'a [TestSpan],
    name: Option<String>,
    attributes: Option<Vec<(String, Value)>>,
    resource_attributes: Option<Vec<(String, Value)>>,
    scope_attributes: Option<Vec<(String, Value)>>,
    event_names: Option<Vec<String>>,
    event_with_attributes: Option<EventWithAttributes>,
}

impl<'a> SpanAssertion<'a> {
    /// Asserts that at least one span matches all specified criteria.
    ///
    /// # Panics
    ///
    /// Panics with a descriptive message if no matching span is found.
    #[track_caller]
    pub fn assert_exists(&self) {
        if !self.matches_any() {
            panic!("{}", self.build_error_message());
        }
    }

    /// Asserts that no spans match the specified criteria.
    ///
    /// # Panics
    ///
    /// Panics if any spans match the criteria.
    #[track_caller]
    pub fn assert_not_exists(&self) {
        if self.matches_any() {
            panic!(
                "Expected no spans to match, but found {} matching span(s).\nCriteria: {}",
                self.count(),
                self.format_criteria()
            );
        }
    }

    /// Asserts that exactly the specified number of spans match the criteria.
    ///
    /// # Panics
    ///
    /// Panics if the count doesn't match exactly.
    #[track_caller]
    pub fn assert_count(&self, expected: usize) {
        let actual = self.count();
        if actual != expected {
            panic!(
                "Expected {} matching span(s), but found {}.\nCriteria: {}\n\n{}",
                expected,
                actual,
                self.format_criteria(),
                self.format_matching_spans()
            );
        }
    }

    /// Asserts that at least the specified number of spans match the criteria.
    ///
    /// # Panics
    ///
    /// Panics if fewer spans match than expected.
    #[track_caller]
    pub fn assert_at_least(&self, min: usize) {
        let actual = self.count();
        if actual < min {
            panic!(
                "Expected at least {} matching span(s), but found {}.\nCriteria: {}",
                min,
                actual,
                self.format_criteria()
            );
        }
    }

    /// Asserts that at most the specified number of spans match the criteria.
    ///
    /// # Panics
    ///
    /// Panics if more spans match than expected.
    #[track_caller]
    pub fn assert_at_most(&self, max: usize) {
        let actual = self.count();
        if actual > max {
            panic!(
                "Expected at most {} matching span(s), but found {}.\nCriteria: {}",
                max,
                actual,
                self.format_criteria()
            );
        }
    }

    /// Returns all spans that match the specified criteria.
    #[must_use = "the matching items should be used"]
    pub fn get_all(&self) -> Vec<&TestSpan> {
        self.spans.iter().filter(|s| self.matches(s)).collect()
    }

    /// Returns the count of spans matching the criteria.
    #[must_use = "the count should be used"]
    pub fn count(&self) -> usize {
        self.spans.iter().filter(|s| self.matches(s)).count()
    }

    /// Adds span attribute assertions to the criteria.
    ///
    /// All attributes must have the same value type. For mixed types, use
    /// [`with_attribute`](Self::with_attribute) instead.
    #[must_use]
    pub fn with_attributes<I, K, V>(mut self, attributes: I) -> Self
    where
        I: IntoIterator<Item = (K, V)>,
        K: Into<String>,
        V: Into<Value>,
    {
        let attrs: Vec<(String, Value)> = attributes
            .into_iter()
            .map(|(k, v)| (k.into(), v.into()))
            .collect();
        self.attributes = Some(attrs);
        self
    }

    /// Adds a single span attribute criterion to the assertion.
    ///
    /// This method can be chained to add multiple attributes of different types.
    #[must_use]
    pub fn with_attribute<K, V>(mut self, key: K, value: V) -> Self
    where
        K: Into<String>,
        V: Into<Value>,
    {
        self.attributes
            .get_or_insert_with(Vec::new)
            .push((key.into(), value.into()));
        self
    }

    /// Adds resource attribute assertions to the criteria.
    ///
    /// All attributes must have the same value type. For mixed types, use
    /// [`with_resource_attribute`](Self::with_resource_attribute) instead.
    #[must_use]
    pub fn with_resource_attributes<I, K, V>(mut self, attributes: I) -> Self
    where
        I: IntoIterator<Item = (K, V)>,
        K: Into<String>,
        V: Into<Value>,
    {
        let attrs: Vec<(String, Value)> = attributes
            .into_iter()
            .map(|(k, v)| (k.into(), v.into()))
            .collect();
        self.resource_attributes = Some(attrs);
        self
    }

    /// Adds a single resource attribute criterion to the assertion.
    #[must_use]
    pub fn with_resource_attribute<K, V>(mut self, key: K, value: V) -> Self
    where
        K: Into<String>,
        V: Into<Value>,
    {
        self.resource_attributes
            .get_or_insert_with(Vec::new)
            .push((key.into(), value.into()));
        self
    }

    /// Adds scope attribute assertions to the criteria.
    ///
    /// All attributes must have the same value type. For mixed types, use
    /// [`with_scope_attribute`](Self::with_scope_attribute) instead.
    #[must_use]
    pub fn with_scope_attributes<I, K, V>(mut self, attributes: I) -> Self
    where
        I: IntoIterator<Item = (K, V)>,
        K: Into<String>,
        V: Into<Value>,
    {
        let attrs: Vec<(String, Value)> = attributes
            .into_iter()
            .map(|(k, v)| (k.into(), v.into()))
            .collect();
        self.scope_attributes = Some(attrs);
        self
    }

    /// Adds a single scope attribute criterion to the assertion.
    #[must_use]
    pub fn with_scope_attribute<K, V>(mut self, key: K, value: V) -> Self
    where
        K: Into<String>,
        V: Into<Value>,
    {
        self.scope_attributes
            .get_or_insert_with(Vec::new)
            .push((key.into(), value.into()));
        self
    }

    /// Adds an event name filter to the assertion.
    ///
    /// The span must contain at least one event with this exact name.
    /// Can be called multiple times to require multiple events (all must be present).
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use mock_collector::MockCollector;
    /// # let collector = MockCollector::new();
    /// collector
    ///     .expect_span_with_name("ProcessOrder")
    ///     .with_event("payment.initiated")
    ///     .with_event("payment.completed")
    ///     .assert_exists();
    /// ```
    #[must_use]
    pub fn with_event<S: Into<String>>(mut self, event_name: S) -> Self {
        let event_name = event_name.into();
        if let Some(ref mut events) = self.event_names {
            events.push(event_name);
        } else {
            self.event_names = Some(vec![event_name]);
        }
        self
    }

    /// Adds an event with specific attributes to the assertion criteria.
    ///
    /// The span must contain at least one event with the specified name and all the specified attributes.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use mock_collector::MockCollector;
    /// # let collector = MockCollector::new();
    /// collector
    ///     .expect_span_with_name("ProcessOrder")
    ///     .with_event_attributes("exception", [
    ///         ("exception.type", "TimeoutError"),
    ///         ("exception.message", "Request timed out"),
    ///     ])
    ///     .assert_exists();
    /// ```
    #[must_use]
    pub fn with_event_attributes<S, I, K, V>(mut self, event_name: S, attributes: I) -> Self
    where
        S: Into<String>,
        I: IntoIterator<Item = (K, V)>,
        K: Into<String>,
        V: Into<Value>,
    {
        let event_name = event_name.into();
        let attrs: Vec<(String, Value)> = attributes
            .into_iter()
            .map(|(k, v)| (k.into(), v.into()))
            .collect();

        if let Some(ref mut events) = self.event_with_attributes {
            events.push((event_name, attrs));
        } else {
            self.event_with_attributes = Some(vec![(event_name, attrs)]);
        }
        self
    }

    fn matches_any(&self) -> bool {
        self.spans.iter().any(|s| self.matches(s))
    }

    fn matches(&self, span: &TestSpan) -> bool {
        // Check name
        if let Some(ref expected_name) = self.name
            && &span.span.name != expected_name
        {
            return false;
        }

        // Check attributes
        if let Some(ref expected_attrs) = self.attributes {
            for (key, value) in expected_attrs {
                if !span
                    .span
                    .attributes
                    .iter()
                    .any(|attr| &attr.key == key && Self::any_value_matches(&attr.value, value))
                {
                    return false;
                }
            }
        }

        // Check resource attributes
        if let Some(ref expected_attrs) = self.resource_attributes {
            for (key, value) in expected_attrs {
                if !span
                    .resource_attrs
                    .iter()
                    .any(|attr| &attr.key == key && Self::any_value_matches(&attr.value, value))
                {
                    return false;
                }
            }
        }

        // Check scope attributes
        if let Some(ref expected_attrs) = self.scope_attributes {
            for (key, value) in expected_attrs {
                if !span
                    .scope_attrs
                    .iter()
                    .any(|attr| &attr.key == key && Self::any_value_matches(&attr.value, value))
                {
                    return false;
                }
            }
        }

        // Check event names
        if let Some(ref expected_event_names) = self.event_names {
            for expected_name in expected_event_names {
                if !span
                    .span
                    .events
                    .iter()
                    .any(|event| &event.name == expected_name)
                {
                    return false;
                }
            }
        }

        // Check events with attributes
        if let Some(ref expected_events) = self.event_with_attributes {
            for (event_name, expected_attrs) in expected_events {
                // Find an event with matching name and all expected attributes
                let found = span.span.events.iter().any(|event| {
                    // First check if event name matches
                    if &event.name != event_name {
                        return false;
                    }

                    // Then check if all expected attributes are present
                    expected_attrs.iter().all(|(key, value)| {
                        event.attributes.iter().any(|attr| {
                            &attr.key == key && Self::any_value_matches(&attr.value, value)
                        })
                    })
                });

                if !found {
                    return false;
                }
            }
        }

        true
    }

    fn any_value_matches(
        attr_value: &Option<opentelemetry_proto::tonic::common::v1::AnyValue>,
        expected: &Value,
    ) -> bool {
        use opentelemetry_proto::tonic::common::v1::any_value::Value as AnyValue;

        match attr_value {
            Some(av) => match &av.value {
                Some(AnyValue::StringValue(s)) => {
                    expected.as_str().map(|exp| s == exp).unwrap_or(false)
                }
                Some(AnyValue::IntValue(i)) => {
                    expected.as_i64().map(|exp| *i == exp).unwrap_or(false)
                }
                Some(AnyValue::DoubleValue(d)) => expected
                    .as_f64()
                    .map(|n| (*d - n).abs() < f64::EPSILON)
                    .unwrap_or(false),
                Some(AnyValue::BoolValue(b)) => {
                    expected.as_bool().map(|exp| *b == exp).unwrap_or(false)
                }
                _ => false,
            },
            None => false,
        }
    }

    fn format_criteria(&self) -> String {
        let mut criteria = Vec::new();
        if let Some(name) = &self.name {
            criteria.push(format!("name={:?}", name));
        }
        if let Some(attrs) = &self.attributes {
            criteria.push(format!("attributes={:?}", attrs));
        }
        if let Some(res_attrs) = &self.resource_attributes {
            criteria.push(format!("resource_attributes={:?}", res_attrs));
        }
        if let Some(scope_attrs) = &self.scope_attributes {
            criteria.push(format!("scope_attributes={:?}", scope_attrs));
        }
        if let Some(ref event_names) = self.event_names {
            criteria.push(format!("event_names={:?}", event_names));
        }
        if let Some(ref event_attrs) = self.event_with_attributes {
            criteria.push(format!("event_with_attributes={:?}", event_attrs));
        }
        criteria.join(", ")
    }

    fn format_matching_spans(&self) -> String {
        let matching: Vec<_> = self.get_all();
        if matching.is_empty() {
            return String::new();
        }

        let mut output = String::from("Matching spans:\n");
        for (idx, span) in matching.iter().enumerate() {
            output.push_str(&format!("  [{}] name=\"{}\"\n", idx, span.span.name));
        }
        output
    }

    fn build_error_message(&self) -> String {
        let mut msg = String::from("No spans matched the assertion.\n\nExpected:\n");

        if let Some(ref name) = self.name {
            msg.push_str(&format!("  name: \"{}\"\n", name));
        }

        if let Some(ref attrs) = self.attributes {
            msg.push_str("  attributes:\n");
            for (k, v) in attrs {
                msg.push_str(&format!("    {}={:?}\n", k, v));
            }
        }

        if let Some(ref attrs) = self.resource_attributes {
            msg.push_str("  resource_attributes:\n");
            for (k, v) in attrs {
                msg.push_str(&format!("    {}={:?}\n", k, v));
            }
        }

        if let Some(ref attrs) = self.scope_attributes {
            msg.push_str("  scope_attributes:\n");
            for (k, v) in attrs {
                msg.push_str(&format!("    {}={:?}\n", k, v));
            }
        }

        if let Some(ref event_names) = self.event_names {
            msg.push_str("  event_names:\n");
            for name in event_names {
                msg.push_str(&format!("    \"{}\"\n", name));
            }
        }

        if let Some(ref event_attrs) = self.event_with_attributes {
            msg.push_str("  event_with_attributes:\n");
            for (event_name, attrs) in event_attrs {
                msg.push_str(&format!("    \"{}\":\n", event_name));
                for (k, v) in attrs {
                    msg.push_str(&format!("      {}={:?}\n", k, v));
                }
            }
        }

        msg.push_str(&format!(
            "\nFound {} span(s) in collector:\n",
            self.spans.len()
        ));

        if !self.spans.is_empty() {
            for (idx, span) in self.spans.iter().take(10).enumerate() {
                msg.push_str(&format!("  [{}] name=\"{}\"", idx, span.span.name));

                if !span.span.attributes.is_empty() {
                    msg.push_str(&format!(
                        ", attributes={}",
                        format_attributes(&span.span.attributes, 3)
                    ));
                }

                if !span.resource_attrs.is_empty() {
                    msg.push_str(&format!(
                        ", resource_attrs={}",
                        format_attributes(&span.resource_attrs, 3)
                    ));
                }

                if !span.scope_attrs.is_empty() {
                    msg.push_str(&format!(
                        ", scope_attrs={}",
                        format_attributes(&span.scope_attrs, 3)
                    ));
                }

                msg.push('\n');
            }

            if self.spans.len() > 10 {
                msg.push_str(&format!("  ... and {} more\n", self.spans.len() - 10));
            }
        }

        msg
    }
}

/// Represents a numeric metric value for assertions.
///
/// Metric data points can contain either integer or floating-point values.
/// This enum provides a unified representation for both types, enabling
/// value-based assertions on Gauge and Sum metrics.
#[derive(Debug, Clone, Copy)]
pub enum MetricValue {
    /// An integer value (i64).
    Int(i64),
    /// A floating-point value (f64).
    Double(f64),
}

impl MetricValue {
    /// Compares two metric values for approximate equality.
    ///
    /// For integer comparisons, uses exact equality.
    /// For floating-point comparisons, uses epsilon-based comparison.
    /// Mixed comparisons convert to f64.
    fn approx_eq(&self, other: &MetricValue) -> bool {
        match (self, other) {
            (MetricValue::Int(a), MetricValue::Int(b)) => a == b,
            (MetricValue::Double(a), MetricValue::Double(b)) => (a - b).abs() < f64::EPSILON,
            (MetricValue::Int(a), MetricValue::Double(b))
            | (MetricValue::Double(b), MetricValue::Int(a)) => {
                ((*a as f64) - b).abs() < f64::EPSILON
            }
        }
    }

    /// Converts the metric value to f64 for comparison.
    fn as_f64(&self) -> f64 {
        match self {
            MetricValue::Int(i) => *i as f64,
            MetricValue::Double(d) => *d,
        }
    }
}

impl std::fmt::Display for MetricValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MetricValue::Int(i) => write!(f, "{}", i),
            MetricValue::Double(d) => write!(f, "{}", d),
        }
    }
}

impl From<i64> for MetricValue {
    fn from(v: i64) -> Self {
        MetricValue::Int(v)
    }
}

impl From<i32> for MetricValue {
    fn from(v: i32) -> Self {
        MetricValue::Int(v.into())
    }
}

impl From<i16> for MetricValue {
    fn from(v: i16) -> Self {
        MetricValue::Int(v.into())
    }
}

impl From<i8> for MetricValue {
    fn from(v: i8) -> Self {
        MetricValue::Int(v.into())
    }
}

impl From<u32> for MetricValue {
    fn from(v: u32) -> Self {
        MetricValue::Int(v.into())
    }
}

impl From<u16> for MetricValue {
    fn from(v: u16) -> Self {
        MetricValue::Int(v.into())
    }
}

impl From<u8> for MetricValue {
    fn from(v: u8) -> Self {
        MetricValue::Int(v.into())
    }
}

impl From<f64> for MetricValue {
    fn from(v: f64) -> Self {
        MetricValue::Double(v)
    }
}

impl From<f32> for MetricValue {
    fn from(v: f32) -> Self {
        MetricValue::Double(v.into())
    }
}

/// Internal enum for metric value comparison predicates.
#[derive(Debug, Clone)]
enum MetricValuePredicate {
    Eq(MetricValue),
    Gt(MetricValue),
    Gte(MetricValue),
    Lt(MetricValue),
    Lte(MetricValue),
}

impl MetricValuePredicate {
    fn matches(&self, actual: &MetricValue) -> bool {
        match self {
            MetricValuePredicate::Eq(expected) => actual.approx_eq(expected),
            MetricValuePredicate::Gt(expected) => actual.as_f64() > expected.as_f64(),
            MetricValuePredicate::Gte(expected) => {
                actual.as_f64() >= expected.as_f64() || actual.approx_eq(expected)
            }
            MetricValuePredicate::Lt(expected) => actual.as_f64() < expected.as_f64(),
            MetricValuePredicate::Lte(expected) => {
                actual.as_f64() <= expected.as_f64() || actual.approx_eq(expected)
            }
        }
    }

    fn format(&self) -> String {
        match self {
            MetricValuePredicate::Eq(v) => format!("== {}", v),
            MetricValuePredicate::Gt(v) => format!("> {}", v),
            MetricValuePredicate::Gte(v) => format!(">= {}", v),
            MetricValuePredicate::Lt(v) => format!("< {}", v),
            MetricValuePredicate::Lte(v) => format!("<= {}", v),
        }
    }
}

/// A builder for constructing metric assertions.
#[derive(Debug)]
pub struct MetricAssertion<'a> {
    metrics: &'a [TestMetric],
    name: Option<String>,
    attributes: Option<Vec<(String, Value)>>,
    resource_attributes: Option<Vec<(String, Value)>>,
    scope_attributes: Option<Vec<(String, Value)>>,
    value_predicates: Vec<MetricValuePredicate>,
}

impl<'a> MetricAssertion<'a> {
    /// Asserts that at least one metric matches all specified criteria.
    ///
    /// # Panics
    ///
    /// Panics with a descriptive message if no matching metric is found.
    #[track_caller]
    pub fn assert_exists(&self) {
        if !self.matches_any() {
            panic!("{}", self.build_error_message());
        }
    }

    /// Asserts that no metrics match the specified criteria.
    ///
    /// # Panics
    ///
    /// Panics if any metrics match the criteria.
    #[track_caller]
    pub fn assert_not_exists(&self) {
        if self.matches_any() {
            panic!(
                "Expected no metrics to match, but found {} matching metric(s).\nCriteria: {}",
                self.count(),
                self.format_criteria()
            );
        }
    }

    /// Asserts that exactly the specified number of metrics match the criteria.
    ///
    /// # Panics
    ///
    /// Panics if the count doesn't match exactly.
    #[track_caller]
    pub fn assert_count(&self, expected: usize) {
        let actual = self.count();
        if actual != expected {
            panic!(
                "Expected {} matching metric(s), but found {}.\nCriteria: {}\n\n{}",
                expected,
                actual,
                self.format_criteria(),
                self.format_matching_metrics()
            );
        }
    }

    /// Asserts that at least the specified number of metrics match the criteria.
    ///
    /// # Panics
    ///
    /// Panics if fewer metrics match than expected.
    #[track_caller]
    pub fn assert_at_least(&self, min: usize) {
        let actual = self.count();
        if actual < min {
            panic!(
                "Expected at least {} matching metric(s), but found {}.\nCriteria: {}",
                min,
                actual,
                self.format_criteria()
            );
        }
    }

    /// Asserts that at most the specified number of metrics match the criteria.
    ///
    /// # Panics
    ///
    /// Panics if more metrics match than expected.
    #[track_caller]
    pub fn assert_at_most(&self, max: usize) {
        let actual = self.count();
        if actual > max {
            panic!(
                "Expected at most {} matching metric(s), but found {}.\nCriteria: {}",
                max,
                actual,
                self.format_criteria()
            );
        }
    }

    /// Returns all metrics that match the specified criteria.
    #[must_use = "the matching items should be used"]
    pub fn get_all(&self) -> Vec<&TestMetric> {
        self.metrics.iter().filter(|m| self.matches(m)).collect()
    }

    /// Returns the count of metrics matching the criteria.
    #[must_use = "the count should be used"]
    pub fn count(&self) -> usize {
        self.metrics.iter().filter(|m| self.matches(m)).count()
    }

    /// Adds metric attribute assertions to the criteria.
    ///
    /// All attributes must have the same value type. For mixed types, use
    /// [`with_attribute`](Self::with_attribute) instead.
    #[must_use]
    pub fn with_attributes<I, K, V>(mut self, attributes: I) -> Self
    where
        I: IntoIterator<Item = (K, V)>,
        K: Into<String>,
        V: Into<Value>,
    {
        let attrs: Vec<(String, Value)> = attributes
            .into_iter()
            .map(|(k, v)| (k.into(), v.into()))
            .collect();
        self.attributes = Some(attrs);
        self
    }

    /// Adds a single metric attribute criterion to the assertion.
    ///
    /// This method can be chained to add multiple attributes of different types.
    #[must_use]
    pub fn with_attribute<K, V>(mut self, key: K, value: V) -> Self
    where
        K: Into<String>,
        V: Into<Value>,
    {
        self.attributes
            .get_or_insert_with(Vec::new)
            .push((key.into(), value.into()));
        self
    }

    /// Adds resource attribute assertions to the criteria.
    ///
    /// All attributes must have the same value type. For mixed types, use
    /// [`with_resource_attribute`](Self::with_resource_attribute) instead.
    #[must_use]
    pub fn with_resource_attributes<I, K, V>(mut self, resource_attributes: I) -> Self
    where
        I: IntoIterator<Item = (K, V)>,
        K: Into<String>,
        V: Into<Value>,
    {
        let attrs: Vec<(String, Value)> = resource_attributes
            .into_iter()
            .map(|(k, v)| (k.into(), v.into()))
            .collect();
        self.resource_attributes = Some(attrs);
        self
    }

    /// Adds a single resource attribute criterion to the assertion.
    #[must_use]
    pub fn with_resource_attribute<K, V>(mut self, key: K, value: V) -> Self
    where
        K: Into<String>,
        V: Into<Value>,
    {
        self.resource_attributes
            .get_or_insert_with(Vec::new)
            .push((key.into(), value.into()));
        self
    }

    /// Adds scope attribute assertions to the criteria.
    ///
    /// All attributes must have the same value type. For mixed types, use
    /// [`with_scope_attribute`](Self::with_scope_attribute) instead.
    #[must_use]
    pub fn with_scope_attributes<I, K, V>(mut self, scope_attributes: I) -> Self
    where
        I: IntoIterator<Item = (K, V)>,
        K: Into<String>,
        V: Into<Value>,
    {
        let attrs: Vec<(String, Value)> = scope_attributes
            .into_iter()
            .map(|(k, v)| (k.into(), v.into()))
            .collect();
        self.scope_attributes = Some(attrs);
        self
    }

    /// Adds a single scope attribute criterion to the assertion.
    #[must_use]
    pub fn with_scope_attribute<K, V>(mut self, key: K, value: V) -> Self
    where
        K: Into<String>,
        V: Into<Value>,
    {
        self.scope_attributes
            .get_or_insert_with(Vec::new)
            .push((key.into(), value.into()));
        self
    }

    /// Adds a value equality assertion for Gauge or Sum metrics.
    ///
    /// The metric must have at least one data point with a value equal to the
    /// specified value. For floating-point comparisons, uses epsilon-based equality.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use mock_collector::MockCollector;
    /// # let collector = MockCollector::new();
    /// collector
    ///     .expect_metric_with_name("http_requests_total")
    ///     .with_value_eq(42)
    ///     .assert_exists();
    /// ```
    #[must_use]
    pub fn with_value_eq<V: Into<MetricValue>>(mut self, value: V) -> Self {
        self.value_predicates
            .push(MetricValuePredicate::Eq(value.into()));
        self
    }

    /// Adds a value greater-than assertion for Gauge or Sum metrics.
    ///
    /// The metric must have at least one data point with a value strictly
    /// greater than the specified value.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use mock_collector::MockCollector;
    /// # let collector = MockCollector::new();
    /// collector
    ///     .expect_metric_with_name("queue_depth")
    ///     .with_value_gt(0)
    ///     .assert_exists();
    /// ```
    #[must_use]
    pub fn with_value_gt<V: Into<MetricValue>>(mut self, value: V) -> Self {
        self.value_predicates
            .push(MetricValuePredicate::Gt(value.into()));
        self
    }

    /// Adds a value greater-than-or-equal assertion for Gauge or Sum metrics.
    ///
    /// The metric must have at least one data point with a value greater than
    /// or equal to the specified value.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use mock_collector::MockCollector;
    /// # let collector = MockCollector::new();
    /// collector
    ///     .expect_metric_with_name("response_time_ms")
    ///     .with_value_gte(100.0)
    ///     .assert_exists();
    /// ```
    #[must_use]
    pub fn with_value_gte<V: Into<MetricValue>>(mut self, value: V) -> Self {
        self.value_predicates
            .push(MetricValuePredicate::Gte(value.into()));
        self
    }

    /// Adds a value less-than assertion for Gauge or Sum metrics.
    ///
    /// The metric must have at least one data point with a value strictly
    /// less than the specified value.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use mock_collector::MockCollector;
    /// # let collector = MockCollector::new();
    /// collector
    ///     .expect_metric_with_name("error_rate")
    ///     .with_value_lt(0.01)
    ///     .assert_exists();
    /// ```
    #[must_use]
    pub fn with_value_lt<V: Into<MetricValue>>(mut self, value: V) -> Self {
        self.value_predicates
            .push(MetricValuePredicate::Lt(value.into()));
        self
    }

    /// Adds a value less-than-or-equal assertion for Gauge or Sum metrics.
    ///
    /// The metric must have at least one data point with a value less than
    /// or equal to the specified value.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use mock_collector::MockCollector;
    /// # let collector = MockCollector::new();
    /// collector
    ///     .expect_metric_with_name("response_time_ms")
    ///     .with_value_lte(500.0)
    ///     .assert_exists();
    /// ```
    #[must_use]
    pub fn with_value_lte<V: Into<MetricValue>>(mut self, value: V) -> Self {
        self.value_predicates
            .push(MetricValuePredicate::Lte(value.into()));
        self
    }

    fn matches_any(&self) -> bool {
        self.metrics.iter().any(|m| self.matches(m))
    }

    fn matches(&self, metric: &TestMetric) -> bool {
        // Check name
        if let Some(ref expected_name) = self.name
            && &metric.metric.name != expected_name
        {
            return false;
        }

        // Check metric attributes (data point attributes)
        if let Some(ref expected_attrs) = self.attributes {
            // Metrics have data points with attributes
            // We check if any data point has the expected attributes
            let has_matching_data_point =
                Self::check_metric_data_points(&metric.metric, expected_attrs);
            if !has_matching_data_point {
                return false;
            }
        }

        // Check resource attributes
        if let Some(ref expected_attrs) = self.resource_attributes
            && !Self::check_attributes(&metric.resource_attrs, expected_attrs)
        {
            return false;
        }

        // Check scope attributes
        if let Some(ref expected_attrs) = self.scope_attributes
            && !Self::check_attributes(&metric.scope_attrs, expected_attrs)
        {
            return false;
        }

        // Check value predicates
        if !self.value_predicates.is_empty() {
            let values = Self::get_data_point_values(&metric.metric);
            if values.is_empty() {
                return false;
            }
            // Check if ANY data point value satisfies ALL predicates
            let has_matching_value = values.iter().any(|actual| {
                self.value_predicates
                    .iter()
                    .all(|pred| pred.matches(actual))
            });
            if !has_matching_value {
                return false;
            }
        }

        true
    }

    fn get_data_point_values(metric: &Metric) -> Vec<MetricValue> {
        use opentelemetry_proto::tonic::metrics::v1::metric::Data;
        use opentelemetry_proto::tonic::metrics::v1::number_data_point::Value as NumberValue;

        let mut values = Vec::new();

        if let Some(ref data) = metric.data {
            match data {
                Data::Gauge(gauge) => {
                    for dp in &gauge.data_points {
                        if let Some(ref v) = dp.value {
                            match v {
                                NumberValue::AsInt(i) => values.push(MetricValue::Int(*i)),
                                NumberValue::AsDouble(d) => values.push(MetricValue::Double(*d)),
                            }
                        }
                    }
                }
                Data::Sum(sum) => {
                    for dp in &sum.data_points {
                        if let Some(ref v) = dp.value {
                            match v {
                                NumberValue::AsInt(i) => values.push(MetricValue::Int(*i)),
                                NumberValue::AsDouble(d) => values.push(MetricValue::Double(*d)),
                            }
                        }
                    }
                }
                // Histogram, ExponentialHistogram, and Summary do not have simple scalar values
                Data::Histogram(_) | Data::ExponentialHistogram(_) | Data::Summary(_) => {}
            }
        }

        values
    }

    fn check_metric_data_points(metric: &Metric, expected: &[(String, Value)]) -> bool {
        use opentelemetry_proto::tonic::metrics::v1::metric::Data;

        // Check data points based on metric type
        if let Some(ref data) = metric.data {
            match data {
                Data::Gauge(gauge) => gauge
                    .data_points
                    .iter()
                    .any(|dp| Self::check_attributes(&dp.attributes, expected)),
                Data::Sum(sum) => sum
                    .data_points
                    .iter()
                    .any(|dp| Self::check_attributes(&dp.attributes, expected)),
                Data::Histogram(histogram) => histogram
                    .data_points
                    .iter()
                    .any(|dp| Self::check_attributes(&dp.attributes, expected)),
                Data::ExponentialHistogram(hist) => hist
                    .data_points
                    .iter()
                    .any(|dp| Self::check_attributes(&dp.attributes, expected)),
                Data::Summary(summary) => summary
                    .data_points
                    .iter()
                    .any(|dp| Self::check_attributes(&dp.attributes, expected)),
            }
        } else {
            false
        }
    }

    fn check_attributes(attrs: &[KeyValue], expected: &[(String, Value)]) -> bool {
        expected.iter().all(|(key, value)| {
            attrs
                .iter()
                .any(|kv| &kv.key == key && Self::any_value_matches(&kv.value, value))
        })
    }

    fn any_value_matches(
        attr_value: &Option<opentelemetry_proto::tonic::common::v1::AnyValue>,
        expected: &Value,
    ) -> bool {
        use opentelemetry_proto::tonic::common::v1::any_value::Value as AnyValue;

        match attr_value {
            Some(av) => match &av.value {
                Some(AnyValue::StringValue(s)) => {
                    expected.as_str().map(|exp| s == exp).unwrap_or(false)
                }
                Some(AnyValue::IntValue(i)) => {
                    expected.as_i64().map(|exp| *i == exp).unwrap_or(false)
                }
                Some(AnyValue::DoubleValue(d)) => expected
                    .as_f64()
                    .map(|n| (*d - n).abs() < f64::EPSILON)
                    .unwrap_or(false),
                Some(AnyValue::BoolValue(b)) => {
                    expected.as_bool().map(|exp| *b == exp).unwrap_or(false)
                }
                _ => false,
            },
            None => false,
        }
    }

    fn format_criteria(&self) -> String {
        let mut criteria = Vec::new();
        if let Some(name) = &self.name {
            criteria.push(format!("name={:?}", name));
        }
        if let Some(attrs) = &self.attributes {
            criteria.push(format!("attributes={:?}", attrs));
        }
        if let Some(res_attrs) = &self.resource_attributes {
            criteria.push(format!("resource_attributes={:?}", res_attrs));
        }
        if let Some(scope_attrs) = &self.scope_attributes {
            criteria.push(format!("scope_attributes={:?}", scope_attrs));
        }
        if !self.value_predicates.is_empty() {
            let preds: Vec<String> = self.value_predicates.iter().map(|p| p.format()).collect();
            criteria.push(format!("value({})", preds.join(" AND ")));
        }
        criteria.join(", ")
    }

    fn format_matching_metrics(&self) -> String {
        let matching: Vec<_> = self.get_all();
        if matching.is_empty() {
            return String::new();
        }

        let mut output = String::from("Matching metrics:\n");
        for (idx, metric) in matching.iter().enumerate() {
            output.push_str(&format!("  [{}] name=\"{}\"\n", idx, metric.metric.name));
        }
        output
    }

    fn build_error_message(&self) -> String {
        let mut msg = String::from("No metrics matched the assertion.\n\nExpected:\n");

        if let Some(ref name) = self.name {
            msg.push_str(&format!("  name: \"{}\"\n", name));
        }

        if let Some(ref attrs) = self.attributes {
            msg.push_str("  attributes:\n");
            for (k, v) in attrs {
                msg.push_str(&format!("    {}={:?}\n", k, v));
            }
        }

        if let Some(ref attrs) = self.resource_attributes {
            msg.push_str("  resource_attributes:\n");
            for (k, v) in attrs {
                msg.push_str(&format!("    {}={:?}\n", k, v));
            }
        }

        if let Some(ref attrs) = self.scope_attributes {
            msg.push_str("  scope_attributes:\n");
            for (k, v) in attrs {
                msg.push_str(&format!("    {}={:?}\n", k, v));
            }
        }

        if !self.value_predicates.is_empty() {
            msg.push_str("  value:\n");
            for pred in &self.value_predicates {
                msg.push_str(&format!("    {}\n", pred.format()));
            }
        }

        msg.push_str(&format!(
            "\nFound {} metric(s) in collector:\n",
            self.metrics.len()
        ));

        if !self.metrics.is_empty() {
            for (idx, metric) in self.metrics.iter().take(10).enumerate() {
                msg.push_str(&format!("  [{}] name=\"{}\"", idx, metric.metric.name));

                // Show data point values and attributes if available
                let values = Self::get_data_point_values(&metric.metric);
                if !values.is_empty() {
                    let value_strs: Vec<String> = values.iter().map(|v| v.to_string()).collect();
                    msg.push_str(&format!(", values=[{}]", value_strs.join(", ")));
                }

                if let Some(ref data) = metric.metric.data {
                    use opentelemetry_proto::tonic::metrics::v1::metric::Data;
                    let sample_attrs = match data {
                        Data::Gauge(g) => g.data_points.first().map(|dp| &dp.attributes),
                        Data::Sum(s) => s.data_points.first().map(|dp| &dp.attributes),
                        Data::Histogram(h) => h.data_points.first().map(|dp| &dp.attributes),
                        Data::ExponentialHistogram(e) => {
                            e.data_points.first().map(|dp| &dp.attributes)
                        }
                        Data::Summary(s) => s.data_points.first().map(|dp| &dp.attributes),
                    };

                    if let Some(attrs) = sample_attrs
                        && !attrs.is_empty()
                    {
                        msg.push_str(&format!(", attributes={}", format_attributes(attrs, 3)));
                    }
                }

                if !metric.resource_attrs.is_empty() {
                    msg.push_str(&format!(
                        ", resource_attrs={}",
                        format_attributes(&metric.resource_attrs, 3)
                    ));
                }

                if !metric.scope_attrs.is_empty() {
                    msg.push_str(&format!(
                        ", scope_attrs={}",
                        format_attributes(&metric.scope_attrs, 3)
                    ));
                }

                msg.push('\n');
            }

            if self.metrics.len() > 10 {
                msg.push_str(&format!("  ... and {} more\n", self.metrics.len() - 10));
            }
        }

        msg
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use opentelemetry_proto::tonic::common::v1::{ArrayValue, KeyValueList, any_value};

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
