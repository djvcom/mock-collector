//! Example demonstrating HTTP OTLP exporter with traces and logs
//!
//! This example shows how to configure the OpenTelemetry SDK to export
//! both traces and logs using HTTP/Protobuf protocol.
//!
//! Run with: `cargo run --example http_instrumented`

use mock_collector::{MockServer, Protocol, SeverityNumber};
use otel_lambda_init::OtelConfigBuilder;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Starting mock OTLP collector with HTTP...");

    let server = MockServer::builder()
        .protocol(Protocol::HttpBinary)
        .start()
        .await?;

    println!("Server started on {}\n", server.addr());

    println!("Initialising OpenTelemetry SDK with HTTP/Protobuf exporter...");

    let config = OtelConfigBuilder::new()
        .with_endpoint(format!("http://{}", server.addr()))
        .with_protocol(Protocol::HttpBinary)
        .with_tls(false)
        .with_resource_attribute("service.name", "http-example")
        .with_resource_attribute("deployment.environment.name", "qa")
        .with_resource_attribute("faas.logical_id", "my-test-lambda")
        .build()?;

    let _guard = config.init().await?;

    println!("OpenTelemetry SDK initialised with HTTP/Protobuf!\n");

    println!("Emitting telemetry data...");

    let api_key = "key-xyz-789";
    let endpoint = "/api/v1/users";

    let span = tracing::info_span!(
        "handle_api_request",
        http.method = "POST",
        http.target = endpoint
    );
    let _enter = span.enter();

    tracing::info!("Received API request");

    authenticate(api_key).await;

    execute_handler(endpoint).await;

    tracing::info!("API request completed successfully");

    drop(_enter);
    drop(span);

    println!("Shutting down OpenTelemetry SDK...");
    _guard.shutdown()?;

    // tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

    println!("\nPerforming assertions...");

    server
        .with_collector(|collector| {
            println!("Total spans: {}", collector.span_count());
            println!("Total logs: {}", collector.log_count());

            collector
                .expect_span_with_name("handle_api_request")
                .with_resource_attributes([
                    ("service.name", "http-example"),
                    ("deployment.environment", "staging"),
                    ("host.name", "lambda-instance-1"),
                ])
                .assert_exists();

            println!("✓ Found handle_api_request span with HTTP resource attributes");

            collector
                .expect_span_with_name("authenticate")
                .assert_exists();

            println!("✓ Found authenticate span");

            collector
                .expect_span_with_name("execute_handler")
                .assert_exists();

            println!("✓ Found execute_handler span");

            collector
                .expect_log_with_body("Received API request")
                .with_severity(SeverityNumber::Info)
                .assert_exists();

            println!("✓ Found info log for API request");

            collector
                .expect_log_with_body("API request completed successfully")
                .with_severity(SeverityNumber::Info)
                .assert_exists();

            println!("✓ Found completion log");

            let http_service_count = collector
                .expect_log()
                .with_resource_attributes([("service.name", "http-example")])
                .count();

            println!(
                "✓ Found {} logs from http-example service",
                http_service_count
            );
        })
        .await;

    println!("\nAll assertions passed!");

    server.shutdown().await?;
    println!("Server shut down successfully");

    Ok(())
}

#[tracing::instrument]
async fn authenticate(api_key: &str) {
    tracing::debug!(api_key = api_key, "Authenticating API key");
    tokio::time::sleep(tokio::time::Duration::from_millis(5)).await;
}

#[tracing::instrument]
async fn execute_handler(endpoint: &str) {
    tracing::info!(endpoint = endpoint, "Executing request handler");
    tokio::time::sleep(tokio::time::Duration::from_millis(15)).await;
}
