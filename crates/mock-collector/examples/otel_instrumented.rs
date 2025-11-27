//! Example demonstrating OpenTelemetry instrumented application
//!
//! This example shows how to use the otel-lambda-init package to initialise
//! OpenTelemetry SDK with tracing integration, then send telemetry to the mock collector.
//!
//! Run with: `cargo run --example otel_instrumented`

use mock_collector::{MockServer, Protocol};
use otel_lambda_init::OtelConfigBuilder;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Starting mock OTLP collector...");

    let server = MockServer::builder()
        .protocol(Protocol::Grpc)
        .start()
        .await?;

    println!("Server started on {}", server.addr());

    println!("Initialising OpenTelemetry SDK with tracing integration...");

    let config = OtelConfigBuilder::new()
        .with_endpoint(format!("http://{}", server.addr()))
        .with_protocol(Protocol::Grpc)
        .with_tls(false)
        .with_resource_attribute("service.name", "otel-example")
        .with_resource_attribute("environment", "development")
        .with_resource_attribute("service.version", "1.0.0")
        .build()?;

    let _guard = config.init().await?;

    println!("OpenTelemetry SDK initialised successfully!\n");

    println!("Emitting traces using the tracing crate...");

    let request_id = "req-12345";

    let span = tracing::info_span!("handle_request", request_id = request_id);
    let _enter = span.enter();

    tracing::info!("Application started successfully");

    process_request(request_id).await;

    tracing::info!("Request completed successfully");

    drop(_enter);
    drop(span);

    println!("Shutting down OpenTelemetry SDK...");
    _guard.shutdown()?;

    tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

    println!("\nPerforming assertions on collected telemetry...");

    server
        .with_collector(|collector| {
            println!("Total spans collected: {}", collector.span_count());

            collector
                .expect_span_with_name("handle_request")
                .with_resource_attributes([("service.name", "otel-example")])
                .assert_exists();

            println!("✓ Found 'handle_request' span with correct service name");

            collector
                .expect_span_with_name("process_request")
                .with_resource_attributes([
                    ("service.name", "otel-example"),
                    ("environment", "development"),
                ])
                .assert_exists();

            println!("✓ Found 'process_request' span with environment attribute");

            let service_spans = collector
                .expect_span()
                .with_resource_attributes([("service.name", "otel-example")])
                .count();

            println!("✓ Found {} spans from otel-example service", service_spans);
        })
        .await;

    println!("\nAll assertions passed!");

    server.shutdown().await?;
    println!("Server shut down successfully");

    Ok(())
}

#[tracing::instrument]
async fn process_request(request_id: &str) {
    tracing::debug!("Starting request processing");

    validate_request(request_id).await;

    execute_business_logic().await;

    tracing::debug!("Request processing completed");
}

#[tracing::instrument]
async fn validate_request(request_id: &str) {
    tracing::debug!(request_id = request_id, "Validating request");
    tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
}

#[tracing::instrument]
async fn execute_business_logic() {
    tracing::debug!("Executing business logic");
    tokio::time::sleep(tokio::time::Duration::from_millis(20)).await;
}
