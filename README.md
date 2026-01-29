# Mock Collector

[![Crates.io](https://img.shields.io/crates/v/mock-collector.svg)](https://crates.io/crates/mock-collector)
[![Documentation](https://docs.rs/mock-collector/badge.svg)](https://docs.rs/mock-collector)
[![CI](https://github.com/djvcom/mock-collector/workflows/CI/badge.svg)](https://github.com/djvcom/mock-collector/actions)
[![License](https://img.shields.io/crates/l/mock-collector.svg)](LICENSE)

A mock OpenTelemetry OTLP collector server for testing applications that export telemetry data.

## Features

- **Multiple Signal Support**: Logs, Traces, and Metrics
- **Multiple Protocol Support**: gRPC, HTTP/Protobuf, and HTTP/JSON
- **Single Collector**: One collector handles all signals - test logs, traces, and metrics together
- **Fluent Assertion API**: Easy-to-use builder pattern for test assertions
- **Flexible Matching**: Match by body/name, attributes, resource attributes, and scope attributes
- **Severity Level Assertions**: Assert on log severity levels (Debug, Info, Warn, Error, Fatal)
- **Count-Based Assertions**: Assert exact counts, minimum, or maximum number of matches
- **Async-Ready**: Built with Tokio for async/await compatibility
- **Graceful Shutdown**: Proper resource cleanup with shutdown signals

## Installation

Add to your `Cargo.toml` (check the badge above for the latest version):

```toml
[dev-dependencies]
mock-collector = "0.2"
tokio = { version = "1", features = ["macros", "rt-multi-thread"] }
```

## Quick Start

### gRPC Server

```rust
use mock_collector::{MockServer, Protocol};

#[tokio::test]
async fn test_grpc_logging() {
    // Start a gRPC server on port 4317
    let server = MockServer::new(Protocol::Grpc, 4317)
        .start()
        .await
        .unwrap();

    // Your application exports logs here...

    // Assert logs were received
    server.with_collector(|collector| {
        collector
            .expect_log_with_body("Application started")
            .with_resource_attributes([("service.name", "my-service")])
            .assert_exists();
    }).await;

    // Graceful shutdown
    server.shutdown().await.unwrap();
}
```

### HTTP/JSON Server

```rust
use mock_collector::{MockServer, Protocol};

#[tokio::test]
async fn test_http_json_logging() {
    let server = MockServer::new(Protocol::HttpJson, 4318)
        .start()
        .await
        .unwrap();

    // Your application exports logs to http://localhost:4318/v1/logs

    server.with_collector(|collector| {
        collector
            .expect_log_with_body("Request processed")
            .with_attributes([("http.status_code", "200")])
            .assert_exists();
    }).await;
}
```

### HTTP/Protobuf Server

```rust
use mock_collector::{MockServer, Protocol};

#[tokio::test]
async fn test_http_binary_logging() {
    let server = MockServer::new(Protocol::HttpBinary, 4318)
        .start()
        .await
        .unwrap();

    // Your application exports logs to http://localhost:4318/v1/logs
    // with Content-Type: application/x-protobuf

    server.with_collector(|collector| {
        assert_eq!(collector.log_count(), 5);
    }).await;
}
```

### Testing Traces

The same server automatically supports traces! Simply use the trace assertion API:

```rust
use mock_collector::{MockServer, Protocol};

#[tokio::test]
async fn test_traces() {
    // Start server with default settings (gRPC on OS-assigned port)
    let server = MockServer::builder().start().await.unwrap();

    // Your application exports traces to the server...
    // For gRPC: server.addr()
    // For HTTP: http://{server.addr()}/v1/traces

    server.with_collector(|collector| {
        // Assert on spans
        collector
            .expect_span_with_name("GET /api/users")
            .with_attributes([("http.method", "GET")])
            .with_resource_attributes([("service.name", "api-gateway")])
            .assert_exists();

        // Count assertions work too
        collector
            .expect_span_with_name("database.query")
            .assert_at_least(3);
    }).await;
}
```

### Testing Metrics

The same server automatically supports metrics! Simply use the metric assertion API:

```rust
use mock_collector::{MockServer, Protocol};

#[tokio::test]
async fn test_metrics() {
    let server = MockServer::builder().start().await.unwrap();

    // Your application exports metrics to the server...
    // For gRPC: server.addr()
    // For HTTP: http://{server.addr()}/v1/metrics

    server.with_collector(|collector| {
        // Assert on metrics
        collector
            .expect_metric_with_name("http_requests_total")
            .with_attributes([("method", "GET")])
            .with_resource_attributes([("service.name", "api-gateway")])
            .assert_exists();

        // Count assertions work too
        collector
            .expect_metric_with_name("db_query_duration")
            .assert_at_least(1);
    }).await;
}
```

### Testing All Signals Together

One collector handles all three signals simultaneously:

```rust
#[tokio::test]
async fn test_all_signals() {
    let server = MockServer::builder().start().await.unwrap();

    // Your app exports logs, traces, and metrics...

    server.with_collector(|collector| {
        // Verify all signals were collected
        assert_eq!(collector.log_count(), 10);
        assert_eq!(collector.span_count(), 15);
        assert_eq!(collector.metric_count(), 5);

        // Assert on logs
        collector
            .expect_log_with_body("Request received")
            .assert_exists();

        // Assert on traces
        collector
            .expect_span_with_name("handle_request")
            .assert_exists();

        // Assert on metrics
        collector
            .expect_metric_with_name("requests_total")
            .assert_exists();
    }).await;
}
```

## Assertion API

### Log Assertions

```rust
// Assert at least one log matches
collector.expect_log_with_body("error occurred").assert_exists();

// Assert no logs match (negative assertion)
collector.expect_log_with_body("password=secret").assert_not_exists();

// Assert exact count
collector.expect_log_with_body("retry attempt").assert_count(3);

// Assert minimum
collector.expect_log_with_body("cache hit").assert_at_least(10);

// Assert maximum
collector.expect_log_with_body("WARNING").assert_at_most(5);

// Assert on severity levels
use mock_collector::SeverityNumber;

collector
    .expect_log()
    .with_severity(SeverityNumber::Error)
    .assert_count(2);

collector
    .expect_log()
    .with_severity(SeverityNumber::Debug)
    .assert_exists();

// Combine severity with other criteria
collector
    .expect_log_with_body("Connection failed")
    .with_severity(SeverityNumber::Error)
    .with_resource_attributes([("service.name", "api")])
    .assert_exists();
```

### Trace Assertions

Span assertions use the same fluent API:

```rust
// Assert at least one span matches
collector.expect_span_with_name("ProcessOrder").assert_exists();

// Assert no spans match (negative assertion)
collector.expect_span_with_name("deprecated.operation").assert_not_exists();

// Assert exact count
collector.expect_span_with_name("database.query").assert_count(5);

// Assert minimum
collector.expect_span_with_name("cache.lookup").assert_at_least(10);

// Assert maximum
collector.expect_span_with_name("external.api.call").assert_at_most(3);
```

### Metric Assertions

Metric assertions use the same fluent API:

```rust
// Assert at least one metric matches
collector.expect_metric_with_name("http_requests_total").assert_exists();

// Assert no metrics match (negative assertion)
collector.expect_metric_with_name("deprecated_metric").assert_not_exists();

// Assert exact count
collector.expect_metric_with_name("db_connections").assert_count(1);

// Assert minimum
collector.expect_metric_with_name("cache_hits").assert_at_least(5);

// Assert maximum
collector.expect_metric_with_name("errors_total").assert_at_most(2);
```

### Histogram and Summary Assertions

For histogram and summary metrics, use type-specific assertion builders:

```rust
// Histogram assertions
collector
    .expect_histogram("http_request_duration")
    .with_attributes([("method", "GET")])
    .with_count_gte(100)
    .with_sum_gte(5000.0)
    .with_bucket_count_gte(2, 50)  // bucket index 2 has >= 50 observations
    .assert_exists();

// Summary assertions with quantile checks
collector
    .expect_summary("response_time")
    .with_count_gte(100)
    .with_quantile_lte(0.5, 100.0)   // median <= 100ms
    .with_quantile_lte(0.99, 500.0)  // p99 <= 500ms
    .assert_exists();

// Exponential histogram assertions
collector
    .expect_exponential_histogram("latency")
    .with_count_gte(100)
    .with_zero_count_lte(5)
    .with_scale_eq(3)
    .assert_exists();
```

### Matching Criteria

All three signals (logs, spans, and metrics) support matching on attributes, resource attributes, and scope attributes:

```rust
// Logs
collector
    .expect_log_with_body("User login")
    .with_attributes([
        ("user.id", "12345"),
        ("auth.method", "oauth2"),
    ])
    .with_resource_attributes([
        ("service.name", "auth-service"),
        ("deployment.environment", "production"),
    ])
    .with_scope_attributes([
        ("scope.name", "user-authentication"),
    ])
    .assert_exists();

// Spans (same API!)
collector
    .expect_span_with_name("AuthenticateUser")
    .with_attributes([
        ("user.id", "12345"),
        ("auth.provider", "google"),
    ])
    .with_resource_attributes([
        ("service.name", "auth-service"),
    ])
    .with_scope_attributes([
        ("library.name", "auth-lib"),
    ])
    .assert_exists();

// Metrics (same API!)
collector
    .expect_metric_with_name("http_requests_total")
    .with_attributes([
        ("method", "POST"),
        ("status", "200"),
    ])
    .with_resource_attributes([
        ("service.name", "api-gateway"),
    ])
    .with_scope_attributes([
        ("meter.name", "http-metrics"),
    ])
    .assert_exists();
```

### Inspection Methods

```rust
// Get counts
let log_count = collector.log_count();
let span_count = collector.span_count();
let metric_count = collector.metric_count();

// Get matching items
let log_assertion = collector.expect_log_with_body("error");
let matching_logs = log_assertion.get_all();
let log_match_count = log_assertion.count();

let span_assertion = collector.expect_span_with_name("database.query");
let matching_spans = span_assertion.get_all();
let span_match_count = span_assertion.count();

let metric_assertion = collector.expect_metric_with_name("requests_total");
let matching_metrics = metric_assertion.get_all();
let metric_match_count = metric_assertion.count();

// Clear all collected data (logs, spans, AND metrics)
collector.clear();

// Debug dump all data
println!("{}", collector.dump());
```

## Sharing a Collector

You can share a collector between multiple servers or inspect logs without starting a server:

```rust
use std::sync::Arc;
use tokio::sync::RwLock;
use mock_collector::{MockCollector, MockServer, Protocol};

let collector = Arc::new(RwLock::new(MockCollector::new()));

// Start multiple servers with the same collector
let grpc_server = MockServer::with_collector(
    Protocol::Grpc,
    4317,
    collector.clone()
).start().await?;

let http_server = MockServer::with_collector(
    Protocol::HttpJson,
    4318,
    collector.clone()
).start().await?;

// Access the collector directly
let log_count = collector.read().await.log_count();
```

## Examples

The `examples/` directory contains complete working examples:

- **[basic_grpc.rs](examples/basic_grpc.rs)** - Getting started with gRPC
  - Starting a server and sending logs
  - Using `wait_for_*` methods for async data
  - Basic assertion patterns and graceful shutdown

- **[http_protocols.rs](examples/http_protocols.rs)** - HTTP/JSON and HTTP/Protobuf
  - Using HTTP endpoints (`/v1/logs`, `/v1/traces`, `/v1/metrics`)
  - Content-Type handling for JSON vs Protobuf

- **[metrics.rs](examples/metrics.rs)** - Metrics collection
  - Sending metrics via gRPC
  - Asserting on metric names and attributes

- **[assertion_patterns.rs](examples/assertion_patterns.rs)** - Comprehensive assertion API
  - Count assertions (`assert_count`, `assert_at_least`, `assert_at_most`)
  - Negative assertions (`assert_not_exists`)
  - Severity level filtering
  - Using `dump()` for debugging
  - Event assertions on spans

Run examples with:
```bash
just example basic_grpc
# or: cargo run --example basic_grpc
```

## Comparison with fake-opentelemetry-collector

This library was inspired by `fake-opentelemetry-collector` but adds:

- **Full Signal Support**: Test logs, traces, and metrics in the same collector
- **HTTP Protocol Support**: Both JSON and Protobuf over HTTP, not just gRPC
- **Fluent Assertion API**: Builder pattern for more readable tests
- **Count Assertions**: `assert_count()`, `assert_at_least()`, `assert_at_most()`
- **Negative Assertions**: `assert_not_exists()` for verifying data doesn't exist
- **Scope Attributes**: Support for asserting on scope-level attributes
- **Better Error Messages**: Detailed panic messages showing what was expected vs what was found
- **Arc-Optimised Storage**: Efficient memory usage for resource/scope attributes
- **Builder Pattern**: Simple defaults with `MockServer::builder().start()` or full control

## Development

A Nix flake provides a development shell with all required tools:

```bash
nix develop
```

Common tasks are available via [just](https://github.com/casey/just):

```bash
just          # List all commands
just check    # Run tests, clippy, and format check
just test     # Run tests
just clippy   # Run clippy
just fmt      # Format code
just doc-open # Build and open documentation
```

## License

Licensed under the [MIT license](LICENSE).

## Contributing

Contributions are welcome! Please feel free to open issues or submit pull requests.
