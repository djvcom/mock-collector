use opentelemetry_proto::tonic::{
    common::v1::KeyValue, logs::v1::LogRecord, metrics::v1::Metric, trace::v1::Span,
};
use std::sync::Arc;

/// A flattened log record with resource and scope attributes copied for easy test assertions.
///
/// The OTLP structure is flattened so each log record carries its own copy of resource
/// and scope attributes via `Arc`, enabling direct assertions without navigating the
/// nested OTLP hierarchy.
#[derive(Debug, Clone)]
pub struct TestLogRecord {
    pub(crate) resource_attrs: Arc<Vec<KeyValue>>,
    pub(crate) scope_attrs: Arc<Vec<KeyValue>>,
    pub(crate) log_record: LogRecord,
}

impl TestLogRecord {
    pub fn resource_attrs(&self) -> &[KeyValue] {
        &self.resource_attrs
    }

    pub fn scope_attrs(&self) -> &[KeyValue] {
        &self.scope_attrs
    }

    pub fn log_record(&self) -> &LogRecord {
        &self.log_record
    }
}

/// A flattened span with resource and scope attributes copied for easy test assertions.
///
/// The OTLP structure is flattened so each span carries its own copy of resource
/// and scope attributes via `Arc`, enabling direct assertions without navigating the
/// nested OTLP hierarchy.
#[derive(Debug, Clone)]
pub struct TestSpan {
    pub(crate) resource_attrs: Arc<Vec<KeyValue>>,
    pub(crate) scope_attrs: Arc<Vec<KeyValue>>,
    pub(crate) span: Span,
}

impl TestSpan {
    pub fn resource_attrs(&self) -> &[KeyValue] {
        &self.resource_attrs
    }

    pub fn scope_attrs(&self) -> &[KeyValue] {
        &self.scope_attrs
    }

    pub fn span(&self) -> &Span {
        &self.span
    }
}

/// A flattened metric with resource and scope attributes copied for easy test assertions.
///
/// The OTLP structure is flattened so each metric carries its own copy of resource
/// and scope attributes via `Arc`, enabling direct assertions without navigating the
/// nested OTLP hierarchy.
#[derive(Debug, Clone)]
pub struct TestMetric {
    pub(crate) resource_attrs: Arc<Vec<KeyValue>>,
    pub(crate) scope_attrs: Arc<Vec<KeyValue>>,
    pub(crate) metric: Metric,
}

impl TestMetric {
    pub fn resource_attrs(&self) -> &[KeyValue] {
        &self.resource_attrs
    }

    pub fn scope_attrs(&self) -> &[KeyValue] {
        &self.scope_attrs
    }

    pub fn metric(&self) -> &Metric {
        &self.metric
    }
}
