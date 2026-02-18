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
    let server = MockServer::builder()
        .protocol(Protocol::Grpc)
        .port(4317)
        .start()
        .await
        .unwrap();

    // Your application exports logs here...

    server.with_collector(|collector| {
        collector
            .expect_log_with_body("Application started")
            .with_resource_attributes([("service.name", "my-service")])
            .assert_exists();
    }).await;

    server.shutdown().await.unwrap();
}
```

### HTTP/JSON Server

```rust
use mock_collector::{MockServer, Protocol};

#[tokio::test]
async fn test_http_json_logging() {
    let server = MockServer::builder()
        .protocol(Protocol::HttpJson)
        .port(4318)
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
    let server = MockServer::builder()
        .protocol(Protocol::HttpBinary)
        .port(4318)
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

### Testing All Signals

One server handles logs, traces, and metrics simultaneously:

```rust
use mock_collector::MockServer;

#[tokio::test]
async fn test_all_signals() {
    let server = MockServer::builder().start().await.unwrap();

    // Your app exports logs, traces, and metrics to server.addr()...

    server.with_collector(|collector| {
        collector
            .expect_log_with_body("Request received")
            .assert_exists();

        collector
            .expect_span_with_name("handle_request")
            .with_attributes([("http.method", "GET")])
            .with_resource_attributes([("service.name", "api-gateway")])
            .assert_exists();

        collector
            .expect_metric_with_name("requests_total")
            .assert_exists();
    }).await;
}
```

## Assertion API

All signal types (logs, spans, metrics) share the same fluent assertion API:

```rust
// Existence and count assertions
collector.expect_log_with_body("error occurred").assert_exists();
collector.expect_span_with_name("ProcessOrder").assert_not_exists();
collector.expect_metric_with_name("requests").assert_count(3);
collector.expect_log().assert_at_least(10);
collector.expect_span().assert_at_most(5);

// Attribute matching (same API for all signal types)
collector
    .expect_log_with_body("User login")
    .with_attributes([("user.id", "12345")])
    .with_resource_attributes([("service.name", "auth-service")])
    .with_scope_attributes([("scope.name", "user-auth")])
    .assert_exists();

// Severity assertions (logs only)
use mock_collector::SeverityNumber;
collector
    .expect_log_with_body("Connection failed")
    .with_severity(SeverityNumber::Error)
    .assert_exists();

// Inspection methods
let count = collector.expect_log_with_body("error").count();
let matching = collector.expect_span_with_name("query").get_all();
println!("{}", collector.dump());
```

### Histogram and Summary Assertions

For histogram and summary metrics, use type-specific assertion builders:

```rust
collector
    .expect_histogram("http_request_duration")
    .with_attributes([("method", "GET")])
    .with_count_gte(100)
    .with_sum_gte(5000.0)
    .with_bucket_count_gte(2, 50)
    .assert_exists();

collector
    .expect_summary("response_time")
    .with_count_gte(100)
    .with_quantile_lte(0.5, 100.0)   // median <= 100ms
    .with_quantile_lte(0.99, 500.0)  // p99 <= 500ms
    .assert_exists();

collector
    .expect_exponential_histogram("latency")
    .with_count_gte(100)
    .with_zero_count_lte(5)
    .with_scale_eq(3)
    .assert_exists();
```

## Sharing a Collector

You can share a collector between multiple servers or inspect data without starting a server:

```rust
use std::sync::Arc;
use tokio::sync::RwLock;
use mock_collector::{MockCollector, MockServer, Protocol};

let collector = Arc::new(RwLock::new(MockCollector::new()));

let grpc_server = MockServer::builder()
    .protocol(Protocol::Grpc)
    .port(4317)
    .collector(collector.clone())
    .start()
    .await?;

let http_server = MockServer::builder()
    .protocol(Protocol::HttpJson)
    .port(4318)
    .collector(collector.clone())
    .start()
    .await?;

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
