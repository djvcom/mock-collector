//! Example demonstrating OpenTelemetry logs with different severity levels
//!
//! This example shows how to emit logs at different severity levels (debug, info, warn, error)
//! using the tracing crate, and how to assert against them using the mock collector.
//!
//! Run with: `RUST_LOG=debug cargo run --example logs_with_severity`

use mock_collector::{MockServer, Protocol, SeverityNumber};
use otel_lambda_init::OtelConfigBuilder;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Starting mock OTLP collector...");

    let server = MockServer::builder()
        .protocol(Protocol::Grpc)
        .start()
        .await?;

    println!("Server started on {}\n", server.addr());

    println!("Initialising OpenTelemetry SDK...");

    let config = OtelConfigBuilder::new()
        .with_endpoint(format!("http://{}", server.addr()))
        .with_protocol(Protocol::Grpc)
        .with_tls(false)
        .with_resource_attribute("service.name", "logs-example")
        .with_resource_attribute("environment", "testing")
        .build()?;

    let _guard = config.init().await?;

    println!("OpenTelemetry SDK initialised!\n");

    println!("Emitting logs at different severity levels...");

    tracing::debug!("This is a DEBUG log - detailed information for diagnosing issues");

    tracing::info!("This is an INFO log - general informational message");

    tracing::warn!(
        warning_type = "configuration",
        "This is a WARN log - something might be wrong"
    );

    tracing::error!(
        error_code = "ERR_500",
        component = "database",
        "This is an ERROR log - something went wrong"
    );

    println!("Shutting down OpenTelemetry SDK...");
    _guard.shutdown()?;

    tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

    println!("\nPerforming assertions on collected logs...");

    server
        .with_collector(|collector| {
            println!("Total logs collected: {}", collector.log_count());

            collector
                .expect_log_with_body(
                    "This is a DEBUG log - detailed information for diagnosing issues",
                )
                .with_severity(SeverityNumber::Debug)
                .with_resource_attributes([("service.name", "logs-example")])
                .assert_exists();

            println!("✓ Found DEBUG log with correct severity and service name");

            collector
                .expect_log_with_body("This is an INFO log - general informational message")
                .with_severity(SeverityNumber::Info)
                .assert_exists();

            println!("✓ Found INFO log with correct severity");

            collector
                .expect_log_with_body("This is a WARN log - something might be wrong")
                .with_severity(SeverityNumber::Warn)
                .with_attributes([("warning_type", "configuration")])
                .assert_exists();

            println!("✓ Found WARN log with correct severity and attributes");

            collector
                .expect_log_with_body("This is an ERROR log - something went wrong")
                .with_severity(SeverityNumber::Error)
                .with_attributes([("error_code", "ERR_500"), ("component", "database")])
                .assert_exists();

            println!("✓ Found ERROR log with correct severity and error attributes");

            let debug_count = collector
                .expect_log()
                .with_severity(SeverityNumber::Debug)
                .count();

            println!("✓ Found {} DEBUG logs", debug_count);

            let error_count = collector
                .expect_log()
                .with_severity(SeverityNumber::Error)
                .count();

            println!("✓ Found {} ERROR logs", error_count);

            collector
                .expect_log()
                .with_severity(SeverityNumber::Fatal)
                .assert_not_exists();

            println!("✓ Verified no FATAL logs exist");
        })
        .await;

    println!("\nAll assertions passed!");

    server.shutdown().await?;
    println!("Server shut down successfully");

    Ok(())
}
