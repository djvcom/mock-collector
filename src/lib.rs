//! A mock OpenTelemetry OTLP collector server for testing.
//!
//! This library provides a mock collector that can receive OTLP logs, traces, and metrics over gRPC, HTTP/JSON, or HTTP/Protobuf,
//! and provides a fluent assertion API for verifying the received telemetry data in tests.
//!
//! # Features
//!
//! - **Multiple Signal Support**: Logs, Traces, and Metrics
//! - **Single Collector**: One collector handles all signals - test logs, traces, and metrics together
//! - **Multiple Protocol Support**: gRPC, HTTP/Protobuf, and HTTP/JSON
//! - **Fluent Assertion API**: Easy-to-use builder pattern for test assertions
//! - **Async Waiting**: Wait for telemetry to arrive with timeout support
//! - **Severity Level Assertions**: Assert on log severity levels (Debug, Info, Warn, Error, Fatal)
//! - **Count-Based Assertions**: Assert exact counts, minimums, or maximums
//! - **Negative Assertions**: Verify logs/spans/metrics don't exist
//! - **Async-Ready**: Built with Tokio for async/await compatibility
//! - **Graceful Shutdown**: Proper resource cleanup
//!
//! # Quick Start
//!
//! ```no_run
//! use mock_collector::{MockServer, Protocol};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Start a server (supports logs, traces, and metrics)
//!     let server = MockServer::builder().start().await?;
//!
//!     // Your application exports logs, traces, and metrics here...
//!
//!     // Assert on collected data
//!     server.with_collector(|collector| {
//!         // Logs
//!         collector
//!             .expect_log_with_body("Application started")
//!             .with_resource_attributes([("service.name", "my-service")])
//!             .assert_exists();
//!
//!         // Logs with severity
//!         use mock_collector::SeverityNumber;
//!         collector
//!             .expect_log()
//!             .with_severity(SeverityNumber::Error)
//!             .assert_not_exists();
//!
//!         // Traces
//!         collector
//!             .expect_span_with_name("Initialize")
//!             .with_resource_attributes([("service.name", "my-service")])
//!             .assert_exists();
//!
//!         // Metrics
//!         collector
//!             .expect_metric_with_name("requests_total")
//!             .with_resource_attributes([("service.name", "my-service")])
//!             .assert_exists();
//!     }).await;
//!
//!     // Graceful shutdown
//!     server.shutdown().await?;
//!     Ok(())
//! }
//! ```
//!
//! # Async Waiting
//!
//! When testing async telemetry pipelines, signals often arrive asynchronously after the
//! operation that generates them completes. The library provides waiting methods to handle
//! this pattern:
//!
//! ```no_run
//! use mock_collector::MockServer;
//! use std::time::Duration;
//!
//! # #[tokio::main]
//! # async fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let server = MockServer::builder().start().await?;
//!
//! // Trigger async telemetry export...
//!
//! // Wait for telemetry to arrive before asserting
//! server.wait_for_spans(1, Duration::from_secs(5)).await?;
//! server.wait_for_logs(2, Duration::from_secs(5)).await?;
//! server.wait_for_metrics(3, Duration::from_secs(5)).await?;
//!
//! // Or use a custom predicate for complex conditions
//! server.wait_until(
//!     |c| c.expect_span_with_name("http.request")
//!         .with_attributes([("http.status_code", 200)])
//!         .count() >= 1,
//!     Duration::from_secs(5),
//! ).await?;
//!
//! // Now safe to run assertions
//! server.with_collector(|collector| {
//!     collector.expect_span_with_name("http.request").assert_exists();
//! }).await;
//! # Ok(())
//! # }
//! ```
//!
//! # Assertion API
//!
//! The library provides assertion methods for logs, traces, and metrics:
//!
//! ## Log Assertions
//!
//! - [`LogAssertion::assert_exists`]: Assert at least one log matches
//! - [`LogAssertion::assert_not_exists`]: Assert no logs match
//! - [`LogAssertion::assert_count`]: Assert exact number of matches
//! - [`LogAssertion::assert_at_least`]: Assert minimum matches
//! - [`LogAssertion::assert_at_most`]: Assert maximum matches
//!
//! ## Trace Assertions
//!
//! - [`SpanAssertion::assert_exists`]: Assert at least one span matches
//! - [`SpanAssertion::assert_not_exists`]: Assert no spans match
//! - [`SpanAssertion::assert_count`]: Assert exact number of matches
//! - [`SpanAssertion::assert_at_least`]: Assert minimum matches
//! - [`SpanAssertion::assert_at_most`]: Assert maximum matches
//!
//! ## Metric Assertions
//!
//! - [`MetricAssertion::assert_exists`]: Assert at least one metric matches
//! - [`MetricAssertion::assert_not_exists`]: Assert no metrics match
//! - [`MetricAssertion::assert_count`]: Assert exact number of matches
//! - [`MetricAssertion::assert_at_least`]: Assert minimum matches
//! - [`MetricAssertion::assert_at_most`]: Assert maximum matches
//!
//! ## Waiting Methods
//!
//! - [`ServerHandle::wait_until`]: Wait for a custom predicate to return true
//! - [`ServerHandle::wait_for_spans`]: Wait for at least N spans to arrive
//! - [`ServerHandle::wait_for_logs`]: Wait for at least N logs to arrive
//! - [`ServerHandle::wait_for_metrics`]: Wait for at least N metrics to arrive
//!
//! # Examples
//!
//! See the [examples directory](https://github.com/djvcom/mock-collector/tree/main/examples)
//! for complete working examples.

mod collector;
mod error;
mod server;

pub use collector::{
    ExponentialHistogramAssertion, HistogramAssertion, LogAssertion, MetricAssertion,
    MockCollector, SpanAssertion, SummaryAssertion, TestLogRecord, TestMetric, TestSpan,
};
pub use error::MockServerError;
pub use opentelemetry_otlp::Protocol;
pub use opentelemetry_proto::tonic::logs::v1::SeverityNumber;
pub use server::{MockServer, MockServerBuilder, ServerHandle};
