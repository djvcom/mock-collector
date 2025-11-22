# Mock Collector

A mock OpenTelemetry OTLP collector server for testing applications that export telemetry data.

## Features

- **Multiple Signal Support**: Logs and Traces (Metrics coming soon)
- **Multiple Protocol Support**: gRPC, HTTP/Protobuf, and HTTP/JSON
- **Single Collector**: One collector handles all signals - test logs and traces together
- **Fluent Assertion API**: Easy-to-use builder pattern for test assertions
- **Flexible Matching**: Match by body/name, attributes, resource attributes, and scope attributes
- **Count-Based Assertions**: Assert exact counts, minimum, or maximum number of matches
- **Async-Ready**: Built with Tokio for async/await compatibility
- **Graceful Shutdown**: Proper resource cleanup with shutdown signals

## Installation

Add to your `Cargo.toml`:

```toml
[dev-dependencies]
mock-collector = "0.1"
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
            .has_log_with_body("Application started")
            .with_resource_attributes([("service.name", "my-service")])
            .assert();
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
            .has_log_with_body("Request processed")
            .with_attributes([("http.status_code", "200")])
            .assert();
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
            .has_span_with_name("GET /api/users")
            .with_attributes([("http.method", "GET")])
            .with_resource_attributes([("service.name", "api-gateway")])
            .assert();

        // Count assertions work too
        collector
            .has_span_with_name("database.query")
            .assert_at_least(3);
    }).await;
}
```

### Testing Logs and Traces Together

One collector handles both signals simultaneously:

```rust
#[tokio::test]
async fn test_logs_and_traces() {
    let server = MockServer::builder().start().await.unwrap();

    // Your app exports both logs and traces...

    server.with_collector(|collector| {
        // Verify both signals were collected
        assert_eq!(collector.log_count(), 10);
        assert_eq!(collector.span_count(), 15);

        // Assert on logs
        collector
            .has_log_with_body("Request received")
            .assert();

        // Assert on traces
        collector
            .has_span_with_name("handle_request")
            .assert();
    }).await;
}
```

## Assertion API

### Log Assertions

```rust
// Assert at least one log matches
collector.has_log_with_body("error occurred").assert();

// Assert no logs match (negative assertion)
collector.has_log_with_body("password=secret").assert_not_exists();

// Assert exact count
collector.has_log_with_body("retry attempt").assert_count(3);

// Assert minimum
collector.has_log_with_body("cache hit").assert_at_least(10);

// Assert maximum
collector.has_log_with_body("WARNING").assert_at_most(5);
```

### Trace Assertions

Span assertions use the same fluent API:

```rust
// Assert at least one span matches
collector.has_span_with_name("ProcessOrder").assert();

// Assert no spans match (negative assertion)
collector.has_span_with_name("deprecated.operation").assert_not_exists();

// Assert exact count
collector.has_span_with_name("database.query").assert_count(5);

// Assert minimum
collector.has_span_with_name("cache.lookup").assert_at_least(10);

// Assert maximum
collector.has_span_with_name("external.api.call").assert_at_most(3);
```

### Matching Criteria

Both logs and spans support matching on attributes, resource attributes, and scope attributes:

```rust
// Logs
collector
    .has_log_with_body("User login")
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
    .assert();

// Spans (same API!)
collector
    .has_span_with_name("AuthenticateUser")
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
    .assert();
```

### Inspection Methods

```rust
// Get counts
let log_count = collector.log_count();
let span_count = collector.span_count();

// Get matching items
let log_assertion = collector.has_log_with_body("error");
let matching_logs = log_assertion.get_all();
let log_match_count = log_assertion.count();

let span_assertion = collector.has_span_with_name("database.query");
let matching_spans = span_assertion.get_all();
let span_match_count = span_assertion.count();

// Clear all collected data (logs AND spans)
collector.clear();

// Debug dump all logs
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

## Comparison with fake-opentelemetry-collector

This library was inspired by `fake-opentelemetry-collector` but adds:

- **Trace Support**: Test both logs and traces in the same collector
- **HTTP Protocol Support**: Both JSON and Protobuf over HTTP, not just gRPC
- **Fluent Assertion API**: Builder pattern for more readable tests
- **Count Assertions**: `assert_count()`, `assert_at_least()`, `assert_at_most()`
- **Negative Assertions**: `assert_not_exists()` for verifying data doesn't exist
- **Scope Attributes**: Support for asserting on scope-level attributes
- **Better Error Messages**: Detailed panic messages showing what was expected vs what was found
- **Arc-Optimised Storage**: Efficient memory usage for resource/scope attributes
- **Builder Pattern**: Simple defaults with `MockServer::builder().start()` or full control

## License

Licensed under the [MIT license](LICENSE).

## Contributing

Contributions are welcome! Please feel free to open issues or submit pull requests.
