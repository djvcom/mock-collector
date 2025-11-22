//! A mock OpenTelemetry OTLP collector server for testing.
//!
//! This library provides a mock collector that can receive OTLP logs and traces over gRPC, HTTP/JSON, or HTTP/Protobuf,
//! and provides a fluent assertion API for verifying the received telemetry data in tests.
//!
//! # Features
//!
//! - **Multiple Signal Support**: Logs and Traces (Metrics coming soon)
//! - **Single Collector**: One collector handles all signals - test logs and traces together
//! - **Multiple Protocol Support**: gRPC, HTTP/Protobuf, and HTTP/JSON
//! - **Fluent Assertion API**: Easy-to-use builder pattern for test assertions
//! - **Count-Based Assertions**: Assert exact counts, minimums, or maximums
//! - **Negative Assertions**: Verify logs/spans don't exist
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
//!     // Start a server (supports logs and traces)
//!     let server = MockServer::builder().start().await?;
//!
//!     // Your application exports logs and traces here...
//!
//!     // Assert on collected data
//!     server.with_collector(|collector| {
//!         // Logs
//!         collector
//!             .has_log_with_body("Application started")
//!             .with_resource_attributes([("service.name", "my-service")])
//!             .assert();
//!
//!         // Traces
//!         collector
//!             .has_span_with_name("Initialize")
//!             .with_resource_attributes([("service.name", "my-service")])
//!             .assert();
//!     }).await;
//!
//!     // Graceful shutdown
//!     server.shutdown().await?;
//!     Ok(())
//! }
//! ```
//!
//! # Assertion API
//!
//! The library provides assertion methods for both logs and traces:
//!
//! ## Log Assertions
//!
//! - [`LogAssertion::assert`]: Assert at least one log matches
//! - [`LogAssertion::assert_not_exists`]: Assert no logs match
//! - [`LogAssertion::assert_count`]: Assert exact number of matches
//! - [`LogAssertion::assert_at_least`]: Assert minimum matches
//! - [`LogAssertion::assert_at_most`]: Assert maximum matches
//!
//! ## Trace Assertions
//!
//! - [`SpanAssertion::assert`]: Assert at least one span matches
//! - [`SpanAssertion::assert_not_exists`]: Assert no spans match
//! - [`SpanAssertion::assert_count`]: Assert exact number of matches
//! - [`SpanAssertion::assert_at_least`]: Assert minimum matches
//! - [`SpanAssertion::assert_at_most`]: Assert maximum matches
//!
//! # Examples
//!
//! See the [examples directory](https://github.com/youruser/mock-collector/tree/main/examples)
//! for complete working examples.

mod collector;
mod error;
mod server;

pub use collector::{LogAssertion, MockCollector, SpanAssertion, TestLogRecord, TestSpan};
pub use error::MockServerError;
pub use opentelemetry_otlp::Protocol;
pub use server::{MockServer, MockServerBuilder, ServerHandle};
