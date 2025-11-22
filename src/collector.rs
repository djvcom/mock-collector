use opentelemetry_proto::tonic::{
    collector::logs::v1::ExportLogsServiceRequest, common::v1::KeyValue, logs::v1::LogRecord,
};
use serde_json::Value;

/// We flatten the structure such that a copy of the resource attrs and scope attrs
/// are available on a test log record to make it easy to assert against.
pub struct TestLogRecord {
    resource_attrs: Vec<KeyValue>,
    scope_attrs: Vec<KeyValue>,
    log_record: LogRecord,
}

pub struct MockCollector {
    logs: Vec<TestLogRecord>,
}

impl MockCollector {
    pub fn new() -> Self {
        Self { logs: vec![] }
    }

    fn logs_from_request(req: ExportLogsServiceRequest) -> Vec<TestLogRecord> {
        let mut log_records = vec![];
        for rl in req.resource_logs {
            let mut resource_attrs = Vec::new();
            if let Some(resource) = rl.resource {
                resource_attrs.extend(resource.attributes);
            }
            for sl in rl.scope_logs {
                let mut scope_attrs = Vec::new();
                if let Some(scope) = sl.scope {
                    scope_attrs.extend(scope.attributes)
                }
                for lr in sl.log_records {
                    log_records.push(TestLogRecord {
                        log_record: lr,
                        resource_attrs: resource_attrs.clone(),
                        scope_attrs: scope_attrs.clone(),
                    });
                }
            }
        }
        log_records
    }

    pub fn add_logs(&mut self, req: ExportLogsServiceRequest) {
        self.logs.extend(Self::logs_from_request(req));
    }
}

pub struct LogAssertion<'a> {
    logs: &'a [TestLogRecord],
    body: Option<String>,
    attributes: Option<Vec<(String, Value)>>,
    resource_attributes: Option<Vec<(String, Value)>>,
}

impl<'a> LogAssertion<'a> {
    /// Checks whether the Mock Collector has any log which matches all the specified
    /// criteria. Panics with a descriptive message if no matching log is found.
    pub fn exists(&self) {
        let matched = self.logs.iter().any(|test_log| {
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

            true
        });

        if !matched {
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

            panic!(
                "No logs matched the assertion.\nExpected: {}\nFound {} log(s) in collector",
                criteria.join(", "),
                self.logs.len()
            );
        }
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

    pub fn with_attributes<K, V>(mut self, attributes: &[(K, V)]) -> Self
    where
        K: Into<String> + Clone,
        V: Into<Value> + Clone,
    {
        self.attributes = Some(
            attributes
                .iter()
                .map(|(k, v)| (k.clone().into(), v.clone().into()))
                .collect(),
        );
        self
    }

    pub fn with_resource_attributes<K, V>(mut self, resource_attributes: &[(K, V)]) -> Self
    where
        K: Into<String> + Clone,
        V: Into<Value> + Clone,
    {
        self.resource_attributes = Some(
            resource_attributes
                .iter()
                .map(|(k, v)| (k.clone().into(), v.clone().into()))
                .collect(),
        );
        self
    }
}

impl MockCollector {
    pub fn has_log_with_body<S: Into<String>>(&self, body: S) -> LogAssertion<'_> {
        LogAssertion {
            logs: &self.logs,
            body: Some(body.into()),
            attributes: None,
            resource_attributes: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::collector::MockCollector;

    #[test]
    #[should_panic(expected = "No logs matched the assertion")]
    fn test_errors_if_no_logs_match() {
        let mc = MockCollector::new();
        mc.has_log_with_body("hi there")
            .with_attributes(&[("key", "value")])
            .with_resource_attributes(&[("key", "value")])
            .exists();
    }
}
