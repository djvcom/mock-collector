# Mock Collector

[![CI](https://github.com/djvcom/mock-collector/workflows/CI/badge.svg)](https://github.com/djvcom/mock-collector/actions)
[![License](https://img.shields.io/crates/l/mock-collector.svg)](LICENSE)

OpenTelemetry testing and instrumentation tools for Rust.

## Packages

This workspace contains two packages:

### 📦 [mock-collector](crates/mock-collector)

[![Crates.io](https://img.shields.io/crates/v/mock-collector.svg)](https://crates.io/crates/mock-collector)
[![Documentation](https://docs.rs/mock-collector/badge.svg)](https://docs.rs/mock-collector)

A mock OpenTelemetry OTLP collector server for testing applications that export telemetry data.

**Features:**
- Multiple signal support (logs, traces, metrics)
- Multiple protocol support (gRPC, HTTP/Protobuf, HTTP/JSON)
- Fluent assertion API for test validation
- Async-ready with Tokio

[View documentation →](crates/mock-collector/README.md)

### 📦 [otel-lambda-init](crates/otel-lambda-init)

[![Documentation](https://docs.rs/otel-lambda-init/badge.svg)](https://docs.rs/otel-lambda-init) *(coming soon)*

OpenTelemetry SDK initialisation helpers for AWS Lambda functions.

**Features:**
- All three OTLP protocols (gRPC, HTTP/Protobuf, HTTP/JSON)
- Traces, logs, and metrics configured together
- Custom resource attributes and TLS support
- Automatic cleanup via drop handler

[View documentation →](crates/otel-lambda-init)

## Quick Start

### Testing with mock-collector

```toml
[dev-dependencies]
mock-collector = "0.1"
```

```rust
use mock_collector::{MockServer, Protocol};

#[tokio::test]
async fn test_telemetry() {
    let server = MockServer::builder()
        .protocol(Protocol::Grpc)
        .start()
        .await
        .unwrap();

    // ... send telemetry to server.addr() ...

    server.with_collector(|collector| {
        collector.expect_log_with_body("test message")
            .assert_exists();
    }).await;
}
```

### Lambda instrumentation with otel-lambda-init

```toml
[dependencies]
otel-lambda-init = "0.1"  # Not yet published
```

```rust
use otel_lambda_init::OtelConfigBuilder;
use mock_collector::Protocol;

let config = OtelConfigBuilder::new()
    .with_endpoint("http://localhost:4317")
    .with_protocol(Protocol::Grpc)
    .with_resource_attribute("service.name", "my-lambda")
    .build()?;

let _guard = config.init().await?;

// Now use tracing macros
tracing::info!("Lambda initialised");
```

## Examples

Both packages include comprehensive examples:

```bash
# Mock collector examples
cargo run --example basic_grpc
cargo run --example assertion_patterns
cargo run --example metrics

# Lambda init examples
cargo run --example all_signals
cargo run --example grpc_instrumented
cargo run --example logs_with_severity
```

## Development

```bash
# Run all tests
cargo test --workspace

# Run clippy
cargo clippy --all-targets --all-features

# Build documentation
cargo doc --workspace --no-deps --open
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
