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
//! All signal types ([`LogAssertion`], [`SpanAssertion`], [`MetricAssertion`]) share the
//! same fluent API: `assert_exists`, `assert_not_exists`, `assert_count`, `assert_at_least`,
//! `assert_at_most`, `count`, and `get_all`. Each supports filtering by `with_attributes`,
//! `with_resource_attributes`, and `with_scope_attributes`.
//!
//! For type-specific metric assertions, use the dedicated builders:
//!
//! - [`HistogramAssertion`]: count, sum, min, max, and bucket counts
//! - [`ExponentialHistogramAssertion`]: count, sum, min, max, zero_count, and scale
//! - [`SummaryAssertion`]: count, sum, and quantile values
//!
//! ```no_run
//! # use mock_collector::MockCollector;
//! # let collector = MockCollector::new();
//! collector
//!     .expect_histogram("http_request_duration")
//!     .with_count_gte(100)
//!     .with_sum_gte(5000.0)
//!     .assert_exists();
//!
//! collector
//!     .expect_summary("response_time")
//!     .with_quantile_lte(0.99, 500.0)  // p99 <= 500ms
//!     .assert_exists();
//! ```
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
