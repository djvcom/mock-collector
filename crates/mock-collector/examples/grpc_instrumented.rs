//! Example demonstrating gRPC OTLP exporter with traces and logs
//!
//! This example shows how to configure the OpenTelemetry SDK to export
//! both traces and logs using gRPC protocol.
//!
//! Run with: `cargo run --example grpc_instrumented`

use mock_collector::{MockServer, Protocol, SeverityNumber};
use otel_lambda_init::OtelConfigBuilder;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Starting mock OTLP collector with gRPC...");

    let server = MockServer::builder()
        .protocol(Protocol::Grpc)
        .start()
        .await?;

    println!("Server started on {}\n", server.addr());

    println!("Initialising OpenTelemetry SDK with gRPC exporter...");

    let config = OtelConfigBuilder::new()
        .with_endpoint(format!("http://{}", server.addr()))
        .with_protocol(Protocol::Grpc)
        .with_tls(false)
        .with_resource_attribute("service.name", "grpc-example")
        .with_resource_attribute("deployment.environment", "production")
        .with_resource_attribute("service.version", "1.2.3")
        .build()?;

    let _guard = config.init().await?;

    println!("OpenTelemetry SDK initialised with gRPC!\n");

    println!("Emitting telemetry data...");

    let user_id = "user-123";
    let request_id = "req-abc-456";

    let span = tracing::info_span!("process_order", user_id = user_id, request_id = request_id);
    let _enter = span.enter();

    tracing::info!("Starting order processing");

    validate_order(user_id).await;

    tracing::warn!(stock_level = "5", "Stock level is low");

    process_payment(request_id).await;

    tracing::info!("Order processing completed successfully");

    drop(_enter);
    drop(span);

    println!("Shutting down OpenTelemetry SDK...");
    _guard.shutdown()?;

    tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

    println!("\nPerforming assertions...");

    server
        .with_collector(|collector| {
            println!("Total spans: {}", collector.span_count());
            println!("Total logs: {}", collector.log_count());

            collector
                .expect_span_with_name("process_order")
                .with_resource_attributes([
                    ("service.name", "grpc-example"),
                    ("deployment.environment", "production"),
                ])
                .assert_exists();

            println!("✓ Found process_order span with correct resource attributes");

            collector
                .expect_span_with_name("validate_order")
                .assert_exists();

            println!("✓ Found validate_order span");

            collector
                .expect_log_with_body("Starting order processing")
                .with_severity(SeverityNumber::Info)
                .assert_exists();

            println!("✓ Found info log");

            collector
                .expect_log_with_body("Stock level is low")
                .with_severity(SeverityNumber::Warn)
                .with_attributes([("stock_level", "5")])
                .assert_exists();

            println!("✓ Found warning log with stock_level attribute");

            let grpc_service_count = collector
                .expect_span()
                .with_resource_attributes([("service.name", "grpc-example")])
                .count();

            println!(
                "✓ Found {} spans from grpc-example service",
                grpc_service_count
            );
        })
        .await;

    println!("\nAll assertions passed!");

    server.shutdown().await?;
    println!("Server shut down successfully");

    Ok(())
}

#[tracing::instrument]
async fn validate_order(user_id: &str) {
    tracing::debug!(user_id = user_id, "Validating order for user");
    tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
}

#[tracing::instrument]
async fn process_payment(request_id: &str) {
    tracing::info!(request_id = request_id, "Processing payment");
    tokio::time::sleep(tokio::time::Duration::from_millis(20)).await;
}
