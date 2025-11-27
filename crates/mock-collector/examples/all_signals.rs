//! Comprehensive example demonstrating all three OpenTelemetry signals
//!
//! This example shows traces, logs, and metrics working together in a single application.
//! It demonstrates:
//! - Distributed tracing with instrumented functions
//! - Structured logging at multiple severity levels
//! - Multiple metric types (Counter, Histogram, Gauge)
//! - Resource attributes applied to all signals
//!
//! Run with: `cargo run --example all_signals`

use mock_collector::{MockServer, Protocol, SeverityNumber};
use opentelemetry::KeyValue;
use opentelemetry::metrics::MeterProvider;
use otel_lambda_init::OtelConfigBuilder;
use std::time::{Duration, Instant};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== All Signals Example ===\n");
    println!("Demonstrating traces, logs, and metrics together\n");

    let server = MockServer::builder()
        .protocol(Protocol::Grpc)
        .start()
        .await?;

    println!("Server started on {}\n", server.addr());

    let config = OtelConfigBuilder::new()
        .with_endpoint(format!("http://{}", server.addr()))
        .with_protocol(Protocol::Grpc)
        .with_tls(false)
        .with_resource_attribute("service.name", "all-signals-example")
        .with_resource_attribute("service.version", "1.0.0")
        .with_resource_attribute("deployment.environment", "production")
        .build()?;

    let guard = config.init().await?;

    let meter = guard
        .meter_provider()
        .expect("meter provider should be available")
        .meter("all-signals-example");

    let request_counter = meter
        .u64_counter("http.requests")
        .with_description("Number of HTTP requests")
        .build();

    let request_duration = meter
        .f64_histogram("http.request.duration")
        .with_description("HTTP request duration in seconds")
        .with_unit("s")
        .build();

    println!("Simulating application workload...\n");

    for i in 1..=3 {
        let request_id = format!("req-{}", i);
        let method = if i % 2 == 0 { "POST" } else { "GET" };

        let start = Instant::now();

        let span = tracing::info_span!(
            "http_request",
            request_id = %request_id,
            http.method = method,
            http.status_code = tracing::field::Empty
        );
        let _enter = span.enter();

        tracing::info!(
            request_id = %request_id,
            method = method,
            "Received HTTP request"
        );

        request_counter.add(
            1,
            &[
                KeyValue::new("http.method", method),
                KeyValue::new("http.status_code", 200),
            ],
        );

        process_request(&request_id, method).await;

        let duration = start.elapsed().as_secs_f64();
        request_duration.record(
            duration,
            &[
                KeyValue::new("http.method", method),
                KeyValue::new("http.status_code", 200),
            ],
        );

        span.record("http.status_code", 200);

        tracing::info!(
            request_id = %request_id,
            duration_ms = duration * 1000.0,
            "Request completed"
        );
    }

    simulate_error().await;

    println!("\nShutting down...");
    guard.shutdown()?;

    tokio::time::sleep(Duration::from_secs(6)).await;

    println!("\nPerforming assertions...\n");

    server
        .with_collector(|collector| {
            println!("📊 Telemetry Summary:");
            println!("  Spans: {}", collector.span_count());
            println!("  Logs: {}", collector.log_count());
            println!("  Metrics: {}\n", collector.metric_count());

            println!("✓ Traces Assertions:");
            collector
                .expect_span_with_name("http_request")
                .with_resource_attributes([("service.name", "all-signals-example")])
                .assert_at_least(3);
            println!("  - Found multiple http_request spans");

            collector
                .expect_span_with_name("process_request")
                .assert_at_least(3);
            println!("  - Found multiple process_request spans");

            collector
                .expect_span_with_name("error_handler")
                .assert_exists();
            println!("  - Found error_handler span");

            println!("\n✓ Logs Assertions:");
            collector
                .expect_log_with_body("Received HTTP request")
                .with_severity(SeverityNumber::Info)
                .assert_at_least(3);
            println!("  - Found HTTP request logs");

            collector
                .expect_log()
                .with_severity(SeverityNumber::Error)
                .assert_exists();
            println!("  - Found error log");

            println!("\n✓ Metrics Assertions:");
            collector
                .expect_metric_with_name("http.requests")
                .with_resource_attributes([("service.name", "all-signals-example")])
                .assert_exists();
            println!("  - Found http.requests counter metric");

            collector
                .expect_metric_with_name("http.request.duration")
                .with_resource_attributes([("service.name", "all-signals-example")])
                .assert_exists();
            println!("  - Found http.request.duration histogram metric");

            let total_signals =
                collector.span_count() + collector.log_count() + collector.metric_count();
            println!("\n📈 Total signals collected: {}", total_signals);
        })
        .await;

    println!("\n✅ All assertions passed!");

    server.shutdown().await?;
    println!("Server shut down successfully");

    Ok(())
}

#[tracing::instrument]
async fn process_request(request_id: &str, method: &str) {
    tracing::debug!(
        request_id = request_id,
        method = method,
        "Processing request"
    );

    authenticate().await;

    tokio::time::sleep(Duration::from_millis(50)).await;

    tracing::info!("Request processing complete");
}

#[tracing::instrument]
async fn authenticate() {
    tracing::debug!("Authenticating request");
    tokio::time::sleep(Duration::from_millis(10)).await;
}

#[tracing::instrument]
async fn error_handler() {
    tracing::error!(
        error_code = "ERR_500",
        error_type = "InternalServerError",
        "An error occurred during processing"
    );
}

async fn simulate_error() {
    let span = tracing::error_span!("error_scenario");
    let _enter = span.enter();

    tracing::warn!("Entering error scenario");
    error_handler().await;
}
