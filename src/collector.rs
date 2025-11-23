use opentelemetry_proto::tonic::{
    collector::logs::v1::ExportLogsServiceRequest,
    collector::metrics::v1::ExportMetricsServiceRequest,
    collector::trace::v1::ExportTraceServiceRequest, common::v1::KeyValue, logs::v1::LogRecord,
    metrics::v1::Metric, trace::v1::Span,
};
use serde_json::Value;
use std::sync::Arc;

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
        use opentelemetry_proto::tonic::common::v1::any_value::Value as AnyValue;

        let mut output = format!("Mock Collector: {} log(s)\n", self.logs.len());
        for (idx, log) in self.logs.iter().enumerate() {
            output.push_str(&format!("\n[{}] ", idx));

            if let Some(body) = &log.log_record.body
                && let Some(AnyValue::StringValue(s)) = &body.value
            {
                output.push_str(&format!("body=\"{}\"", s));
            }

            if !log.log_record.attributes.is_empty() {
                output.push_str(", attributes={");
                for (i, attr) in log.log_record.attributes.iter().enumerate() {
                    if i > 0 {
                        output.push_str(", ");
                    }
                    output.push_str(&format!("{}=", attr.key));
                    if let Some(val) = &attr.value
                        && let Some(AnyValue::StringValue(s)) = &val.value
                    {
                        output.push_str(&format!("\"{}\"", s));
                    }
                }
                output.push('}');
            }

            if !log.resource_attrs.is_empty() {
                output.push_str(", resource_attrs={");
                for (i, attr) in log.resource_attrs.iter().enumerate() {
                    if i > 0 {
                        output.push_str(", ");
                    }
                    output.push_str(&format!("{}=", attr.key));
                    if let Some(val) = &attr.value
                        && let Some(AnyValue::StringValue(s)) = &val.value
                    {
                        output.push_str(&format!("\"{}\"", s));
                    }
                }
                output.push('}');
            }
        }
        output
    }

    /// Starts building an assertion for logs with the specified body.
    pub fn has_log_with_body<S: Into<String>>(&self, body: S) -> LogAssertion<'_> {
        LogAssertion {
            logs: &self.logs,
            body: Some(body.into()),
            attributes: None,
            resource_attributes: None,
            scope_attributes: None,
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
    ///     .has_logs()
    ///     .with_resource_attributes([("service.name", "my-service")])
    ///     .assert_at_least(5);
    /// ```
    pub fn has_logs(&self) -> LogAssertion<'_> {
        LogAssertion {
            logs: &self.logs,
            body: None,
            attributes: None,
            resource_attributes: None,
            scope_attributes: None,
        }
    }

    /// Starts building an assertion for spans with the specified name.
    pub fn has_span_with_name<S: Into<String>>(&self, name: S) -> SpanAssertion<'_> {
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
    ///     .has_spans()
    ///     .with_resource_attributes([("service.name", "my-service")])
    ///     .assert_at_least(10);
    /// ```
    pub fn has_spans(&self) -> SpanAssertion<'_> {
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
    pub fn has_metric_with_name<S: Into<String>>(&self, name: S) -> MetricAssertion<'_> {
        MetricAssertion {
            metrics: &self.metrics,
            name: Some(name.into()),
            attributes: None,
            resource_attributes: None,
            scope_attributes: None,
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
    ///     .has_metrics()
    ///     .with_resource_attributes([("service.name", "my-service")])
    ///     .assert_at_least(5);
    /// ```
    pub fn has_metrics(&self) -> MetricAssertion<'_> {
        MetricAssertion {
            metrics: &self.metrics,
            name: None,
            attributes: None,
            resource_attributes: None,
            scope_attributes: None,
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
}

impl<'a> LogAssertion<'a> {
    /// Asserts that at least one log matches all specified criteria.
    ///
    /// # Panics
    ///
    /// Panics with a descriptive message if no matching log is found.
    #[track_caller]
    pub fn assert(&self) {
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
    pub fn count(&self) -> usize {
        self.logs.iter().filter(|log| self.matches(log)).count()
    }

    /// Returns all logs that match the criteria.
    pub fn get_all(&self) -> Vec<&TestLogRecord> {
        self.logs.iter().filter(|log| self.matches(log)).collect()
    }

    /// Adds log attribute criteria to the assertion.
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

    /// Adds resource attribute criteria to the assertion.
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

    /// Adds scope attribute criteria to the assertion.
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
        use opentelemetry_proto::tonic::common::v1::any_value::Value as AnyValue;

        let mut msg = String::from("No logs matched the assertion.\n\n");
        msg.push_str(&format!("Expected:\n  {}\n\n", self.format_criteria()));
        msg.push_str(&format!("Found {} log(s) in collector", self.logs.len()));

        if !self.logs.is_empty() {
            msg.push_str(":\n");
            for (idx, log) in self.logs.iter().enumerate().take(10) {
                msg.push_str(&format!("  [{}] ", idx));

                if let Some(body) = &log.log_record.body
                    && let Some(AnyValue::StringValue(s)) = &body.value
                {
                    msg.push_str(&format!("body=\"{}\"", s));
                }

                if !log.log_record.attributes.is_empty() {
                    msg.push_str(", attributes={");
                    for (i, attr) in log.log_record.attributes.iter().take(3).enumerate() {
                        if i > 0 {
                            msg.push_str(", ");
                        }
                        msg.push_str(&attr.key);
                        msg.push('=');
                        if let Some(val) = &attr.value
                            && let Some(AnyValue::StringValue(s)) = &val.value
                        {
                            msg.push_str(&format!("\"{}\"", s));
                        }
                    }
                    msg.push('}');
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
    pub fn assert(&self) {
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
            panic!("Expected no spans to match the criteria, but found at least one");
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
            panic!("Expected exactly {} span(s) but found {}", expected, actual);
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
            panic!("Expected at least {} span(s) but found {}", min, actual);
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
            panic!("Expected at most {} span(s) but found {}", max, actual);
        }
    }

    /// Returns all spans that match the specified criteria.
    pub fn get_all(&self) -> Vec<&TestSpan> {
        self.spans.iter().filter(|s| self.matches(s)).collect()
    }

    /// Returns the count of spans matching the criteria.
    pub fn count(&self) -> usize {
        self.spans.iter().filter(|s| self.matches(s)).count()
    }

    /// Adds span attribute assertions to the criteria.
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

    /// Adds resource attribute assertions to the criteria.
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

    /// Adds scope attribute assertions to the criteria.
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
    ///     .has_span_with_name("ProcessOrder")
    ///     .with_event("payment.initiated")
    ///     .with_event("payment.completed")
    ///     .assert();
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
    ///     .has_span_with_name("ProcessOrder")
    ///     .with_event_attributes("exception", [
    ///         ("exception.type", "TimeoutError"),
    ///         ("exception.message", "Request timed out"),
    ///     ])
    ///     .assert();
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

    fn build_error_message(&self) -> String {
        use opentelemetry_proto::tonic::common::v1::any_value::Value as AnyValue;

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

        msg.push_str(&format!(
            "\nFound {} span(s) in collector:\n",
            self.spans.len()
        ));

        if !self.spans.is_empty() {
            for (idx, span) in self.spans.iter().take(10).enumerate() {
                msg.push_str(&format!("  [{}] name=\"{}\"", idx, span.span.name));

                if !span.span.attributes.is_empty() {
                    msg.push_str(", attributes={");
                    for (i, attr) in span.span.attributes.iter().take(3).enumerate() {
                        if i > 0 {
                            msg.push_str(", ");
                        }
                        msg.push_str(&attr.key);
                        msg.push('=');
                        if let Some(val) = &attr.value
                            && let Some(AnyValue::StringValue(s)) = &val.value
                        {
                            msg.push_str(&format!("\"{}\"", s));
                        }
                    }
                    msg.push('}');
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

/// A builder for constructing metric assertions.
#[derive(Debug)]
pub struct MetricAssertion<'a> {
    metrics: &'a [TestMetric],
    name: Option<String>,
    attributes: Option<Vec<(String, Value)>>,
    resource_attributes: Option<Vec<(String, Value)>>,
    scope_attributes: Option<Vec<(String, Value)>>,
}

impl<'a> MetricAssertion<'a> {
    /// Asserts that at least one metric matches all specified criteria.
    ///
    /// # Panics
    ///
    /// Panics with a descriptive message if no matching metric is found.
    #[track_caller]
    pub fn assert(&self) {
        if !self.matches_any() {
            panic!("No metrics matched the assertion criteria");
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
            panic!("Expected no metrics to match the criteria, but found at least one");
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
                "Expected exactly {} metric(s) but found {}",
                expected, actual
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
            panic!("Expected at least {} metric(s) but found {}", min, actual);
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
            panic!("Expected at most {} metric(s) but found {}", max, actual);
        }
    }

    /// Returns all metrics that match the specified criteria.
    pub fn get_all(&self) -> Vec<&TestMetric> {
        self.metrics.iter().filter(|m| self.matches(m)).collect()
    }

    /// Returns the count of metrics matching the criteria.
    pub fn count(&self) -> usize {
        self.metrics.iter().filter(|m| self.matches(m)).count()
    }

    /// Adds metric attribute assertions to the criteria.
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

    /// Adds resource attribute assertions to the criteria.
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

    /// Adds scope attribute assertions to the criteria.
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

        true
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[should_panic(expected = "No logs matched the assertion")]
    fn test_errors_if_no_logs_match() {
        let mc = MockCollector::new();
        mc.has_log_with_body("hi there")
            .with_attributes([("key", "value")])
            .with_resource_attributes([("key", "value")])
            .assert();
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
}
