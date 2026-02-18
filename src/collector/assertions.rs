use serde_json::Value;

use super::helpers::{check_attributes, format_any_value, format_attributes};
use super::predicates::{
    MetricValue, MetricValuePredicate, impl_assertion_methods, impl_attribute_methods,
};
use super::types::{TestLogRecord, TestMetric, TestSpan};

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
    pub(crate) fn new(logs: &'a [TestLogRecord], body: Option<String>) -> Self {
        Self {
            logs,
            body,
            attributes: None,
            resource_attributes: None,
            scope_attributes: None,
            severity_number: None,
            severity_text: None,
        }
    }

    impl_assertion_methods!(logs, TestLogRecord, "logs", format_matching_logs);
    impl_attribute_methods!();

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
    /// collector
    ///     .expect_log()
    ///     .with_severity(SeverityNumber::Error)
    ///     .assert_exists();
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
    /// Matches the `severity_text` field (e.g., "INFO", "ERROR", "DEBUG").
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

    fn matches(&self, test_log: &TestLogRecord) -> bool {
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

        if let Some(expected_attrs) = &self.attributes
            && !check_attributes(&test_log.log_record.attributes, expected_attrs)
        {
            return false;
        }

        if let Some(expected_res_attrs) = &self.resource_attributes
            && !check_attributes(&test_log.resource_attrs, expected_res_attrs)
        {
            return false;
        }

        if let Some(expected_scope_attrs) = &self.scope_attributes
            && !check_attributes(&test_log.scope_attrs, expected_scope_attrs)
        {
            return false;
        }

        if let Some(expected_severity) = self.severity_number
            && test_log.log_record.severity_number != expected_severity
        {
            return false;
        }

        if let Some(ref expected_text) = self.severity_text
            && &test_log.log_record.severity_text != expected_text
        {
            return false;
        }

        true
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
    pub(crate) fn new(spans: &'a [TestSpan], name: Option<String>) -> Self {
        Self {
            spans,
            name,
            attributes: None,
            resource_attributes: None,
            scope_attributes: None,
            event_names: None,
            event_with_attributes: None,
        }
    }

    impl_assertion_methods!(spans, TestSpan, "spans", format_matching_spans);
    impl_attribute_methods!();

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

    fn matches(&self, span: &TestSpan) -> bool {
        if let Some(ref expected_name) = self.name
            && &span.span.name != expected_name
        {
            return false;
        }

        if let Some(ref expected_attrs) = self.attributes
            && !check_attributes(&span.span.attributes, expected_attrs)
        {
            return false;
        }

        if let Some(ref expected_attrs) = self.resource_attributes
            && !check_attributes(&span.resource_attrs, expected_attrs)
        {
            return false;
        }

        if let Some(ref expected_attrs) = self.scope_attributes
            && !check_attributes(&span.scope_attrs, expected_attrs)
        {
            return false;
        }

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

        if let Some(ref expected_events) = self.event_with_attributes {
            for (event_name, expected_attrs) in expected_events {
                let found = span.span.events.iter().any(|event| {
                    if &event.name != event_name {
                        return false;
                    }
                    check_attributes(&event.attributes, expected_attrs)
                });

                if !found {
                    return false;
                }
            }
        }

        true
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
    pub(crate) fn new(metrics: &'a [TestMetric], name: Option<String>) -> Self {
        Self {
            metrics,
            name,
            attributes: None,
            resource_attributes: None,
            scope_attributes: None,
            value_predicates: Vec::new(),
        }
    }

    impl_assertion_methods!(metrics, TestMetric, "metrics", format_matching_metrics);
    impl_attribute_methods!();

    /// Adds a value equality assertion for Gauge or Sum metrics.
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
    #[must_use]
    pub fn with_value_gt<V: Into<MetricValue>>(mut self, value: V) -> Self {
        self.value_predicates
            .push(MetricValuePredicate::Gt(value.into()));
        self
    }

    /// Adds a value greater-than-or-equal assertion for Gauge or Sum metrics.
    #[must_use]
    pub fn with_value_gte<V: Into<MetricValue>>(mut self, value: V) -> Self {
        self.value_predicates
            .push(MetricValuePredicate::Gte(value.into()));
        self
    }

    /// Adds a value less-than assertion for Gauge or Sum metrics.
    #[must_use]
    pub fn with_value_lt<V: Into<MetricValue>>(mut self, value: V) -> Self {
        self.value_predicates
            .push(MetricValuePredicate::Lt(value.into()));
        self
    }

    /// Adds a value less-than-or-equal assertion for Gauge or Sum metrics.
    #[must_use]
    pub fn with_value_lte<V: Into<MetricValue>>(mut self, value: V) -> Self {
        self.value_predicates
            .push(MetricValuePredicate::Lte(value.into()));
        self
    }

    fn matches(&self, metric: &TestMetric) -> bool {
        if let Some(ref expected_name) = self.name
            && &metric.metric.name != expected_name
        {
            return false;
        }

        if let Some(ref expected_attrs) = self.attributes {
            let has_matching_data_point =
                Self::check_metric_data_points(&metric.metric, expected_attrs);
            if !has_matching_data_point {
                return false;
            }
        }

        if let Some(ref expected_attrs) = self.resource_attributes
            && !check_attributes(&metric.resource_attrs, expected_attrs)
        {
            return false;
        }

        if let Some(ref expected_attrs) = self.scope_attributes
            && !check_attributes(&metric.scope_attrs, expected_attrs)
        {
            return false;
        }

        if !self.value_predicates.is_empty() {
            let values = Self::get_data_point_values(&metric.metric);
            if values.is_empty() {
                return false;
            }
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

    fn get_data_point_values(
        metric: &opentelemetry_proto::tonic::metrics::v1::Metric,
    ) -> Vec<MetricValue> {
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
                Data::Histogram(_) | Data::ExponentialHistogram(_) | Data::Summary(_) => {}
            }
        }

        values
    }

    fn check_metric_data_points(
        metric: &opentelemetry_proto::tonic::metrics::v1::Metric,
        expected: &[(String, Value)],
    ) -> bool {
        use opentelemetry_proto::tonic::metrics::v1::metric::Data;

        if let Some(ref data) = metric.data {
            match data {
                Data::Gauge(gauge) => gauge
                    .data_points
                    .iter()
                    .any(|dp| check_attributes(&dp.attributes, expected)),
                Data::Sum(sum) => sum
                    .data_points
                    .iter()
                    .any(|dp| check_attributes(&dp.attributes, expected)),
                Data::Histogram(histogram) => histogram
                    .data_points
                    .iter()
                    .any(|dp| check_attributes(&dp.attributes, expected)),
                Data::ExponentialHistogram(hist) => hist
                    .data_points
                    .iter()
                    .any(|dp| check_attributes(&dp.attributes, expected)),
                Data::Summary(summary) => summary
                    .data_points
                    .iter()
                    .any(|dp| check_attributes(&dp.attributes, expected)),
            }
        } else {
            false
        }
    }

    pub(crate) fn format_criteria(&self) -> String {
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
