use opentelemetry_proto::tonic::{
    collector::logs::v1::ExportLogsServiceRequest, common::v1::KeyValue, logs::v1::LogRecord,
};
use serde_json::Value;
use std::sync::Arc;

/// A flattened log record with resource and scope attributes copied for easy test assertions.
///
/// We flatten the OTLP structure such that a copy of the resource attrs and scope attrs
/// are available on each test log record to make it easy to assert against.
#[derive(Debug, Clone)]
pub struct TestLogRecord {
    pub resource_attrs: Arc<Vec<KeyValue>>,
    pub scope_attrs: Arc<Vec<KeyValue>>,
    pub log_record: LogRecord,
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

/// A mock collector that stores received OTLP logs for test assertions.
#[derive(Debug, Clone, Default)]
pub struct MockCollector {
    logs: Vec<TestLogRecord>,
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

    /// Clears all collected logs.
    pub fn clear(&mut self) {
        self.logs.clear();
    }

    /// Returns a formatted string representation of all logs for debugging.
    pub fn dump(&self) -> String {
        use opentelemetry_proto::tonic::common::v1::any_value::Value as AnyValue;

        let mut output = format!("Mock Collector: {} log(s)\n", self.logs.len());
        for (idx, log) in self.logs.iter().enumerate() {
            output.push_str(&format!("\n[{}] ", idx));

            if let Some(body) = &log.log_record.body {
                if let Some(AnyValue::StringValue(s)) = &body.value {
                    output.push_str(&format!("body=\"{}\"", s));
                }
            }

            if !log.log_record.attributes.is_empty() {
                output.push_str(", attributes={");
                for (i, attr) in log.log_record.attributes.iter().enumerate() {
                    if i > 0 {
                        output.push_str(", ");
                    }
                    output.push_str(&format!("{}=", attr.key));
                    if let Some(val) = &attr.value {
                        if let Some(AnyValue::StringValue(s)) = &val.value {
                            output.push_str(&format!("\"{}\"", s));
                        }
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
                    if let Some(val) = &attr.value {
                        if let Some(AnyValue::StringValue(s)) = &val.value {
                            output.push_str(&format!("\"{}\"", s));
                        }
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
        if let Some(expected_attrs) = &self.attributes {
            if !Self::check_attributes(&test_log.log_record.attributes, expected_attrs) {
                return false;
            }
        }

        // Check resource attributes if specified
        if let Some(expected_res_attrs) = &self.resource_attributes {
            if !Self::check_attributes(&test_log.resource_attrs, expected_res_attrs) {
                return false;
            }
        }

        // Check scope attributes if specified
        if let Some(expected_scope_attrs) = &self.scope_attributes {
            if !Self::check_attributes(&test_log.scope_attrs, expected_scope_attrs) {
                return false;
            }
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

                if let Some(body) = &log.log_record.body {
                    if let Some(AnyValue::StringValue(s)) = &body.value {
                        msg.push_str(&format!("body=\"{}\"", s));
                    }
                }

                if !log.log_record.attributes.is_empty() {
                    msg.push_str(", attributes={");
                    for (i, attr) in log.log_record.attributes.iter().take(3).enumerate() {
                        if i > 0 {
                            msg.push_str(", ");
                        }
                        msg.push_str(&attr.key);
                        msg.push('=');
                        if let Some(val) = &attr.value {
                            if let Some(AnyValue::StringValue(s)) = &val.value {
                                msg.push_str(&format!("\"{}\"", s));
                            }
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
