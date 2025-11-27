//! Severity Level Assertions Example
//!
//! This example demonstrates how to assert on log severity levels using the
//! SeverityNumber enum from OpenTelemetry.
//!
//! Run with: `cargo run --example severity_assertions`

use mock_collector::{MockServer, Protocol, SeverityNumber};
use opentelemetry_proto::tonic::collector::logs::v1::{
    ExportLogsServiceRequest, logs_service_client::LogsServiceClient,
};
use opentelemetry_proto::tonic::common::v1::{AnyValue, KeyValue, any_value};
use opentelemetry_proto::tonic::logs::v1::{LogRecord, ResourceLogs, ScopeLogs};
use opentelemetry_proto::tonic::resource::v1::Resource;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Starting mock OTLP collector...");

    // Start a gRPC server
    let server = MockServer::builder()
        .protocol(Protocol::Grpc)
        .start()
        .await?;

    println!("Server started on {}", server.addr());

    // Create a gRPC client
    let mut client = LogsServiceClient::connect(format!("http://{}", server.addr())).await?;

    println!("Sending logs with different severity levels...");

    // Send logs with different severity levels
    let request = ExportLogsServiceRequest {
        resource_logs: vec![ResourceLogs {
            resource: Some(Resource {
                attributes: vec![KeyValue {
                    key: "service.name".to_string(),
                    value: Some(AnyValue {
                        value: Some(any_value::Value::StringValue("demo-service".to_string())),
                    }),
                }],
                dropped_attributes_count: 0,
                ..Default::default()
            }),
            scope_logs: vec![ScopeLogs {
                scope: None,
                log_records: vec![
                    LogRecord {
                        body: Some(AnyValue {
                            value: Some(any_value::Value::StringValue(
                                "Application starting".to_string(),
                            )),
                        }),
                        severity_number: SeverityNumber::Info as i32,
                        severity_text: "INFO".to_string(),
                        ..Default::default()
                    },
                    LogRecord {
                        body: Some(AnyValue {
                            value: Some(any_value::Value::StringValue(
                                "Debug: Configuration loaded".to_string(),
                            )),
                        }),
                        severity_number: SeverityNumber::Debug as i32,
                        severity_text: "DEBUG".to_string(),
                        ..Default::default()
                    },
                    LogRecord {
                        body: Some(AnyValue {
                            value: Some(any_value::Value::StringValue(
                                "Warning: High memory usage".to_string(),
                            )),
                        }),
                        severity_number: SeverityNumber::Warn as i32,
                        severity_text: "WARN".to_string(),
                        ..Default::default()
                    },
                    LogRecord {
                        body: Some(AnyValue {
                            value: Some(any_value::Value::StringValue(
                                "Error: Connection failed".to_string(),
                            )),
                        }),
                        severity_number: SeverityNumber::Error as i32,
                        severity_text: "ERROR".to_string(),
                        ..Default::default()
                    },
                    LogRecord {
                        body: Some(AnyValue {
                            value: Some(any_value::Value::StringValue(
                                "Error: Retry failed".to_string(),
                            )),
                        }),
                        severity_number: SeverityNumber::Error as i32,
                        severity_text: "ERROR".to_string(),
                        ..Default::default()
                    },
                ],
                ..Default::default()
            }],
            ..Default::default()
        }],
    };

    client.export(request).await?;

    println!("Logs sent successfully!\n");

    // Perform severity-based assertions
    println!("Performing severity-based assertions...");

    server
        .with_collector(|collector| {
            println!("Total logs collected: {}", collector.log_count());

            // Assert we have exactly 2 ERROR level logs
            let error_count = collector
                .expect_log()
                .with_severity(SeverityNumber::Error)
                .count();
            println!("✓ Found {} ERROR level logs", error_count);
            assert_eq!(error_count, 2);

            // Assert we have at least 1 DEBUG log
            collector
                .expect_log()
                .with_severity(SeverityNumber::Debug)
                .assert_exists();
            println!("✓ Found at least one DEBUG log");

            // Assert we have exactly 1 WARN log
            collector
                .expect_log()
                .with_severity(SeverityNumber::Warn)
                .assert_count(1);
            println!("✓ Found exactly 1 WARN log");

            // Assert we have exactly 1 INFO log
            collector
                .expect_log()
                .with_severity(SeverityNumber::Info)
                .assert_count(1);
            println!("✓ Found exactly 1 INFO log");

            // Assert no FATAL logs exist
            collector
                .expect_log()
                .with_severity(SeverityNumber::Fatal)
                .assert_not_exists();
            println!("✓ Verified no FATAL logs exist");

            // Combine severity with text matching
            collector
                .expect_log_with_body("Error: Connection failed")
                .with_severity(SeverityNumber::Error)
                .assert_exists();
            println!("✓ Found specific error message at ERROR level");

            // Combine severity with resource attributes
            collector
                .expect_log()
                .with_severity(SeverityNumber::Warn)
                .with_resource_attributes([("service.name", "demo-service")])
                .assert_exists();
            println!("✓ Found WARN log from demo-service");

            // Using severity_text instead of severity_number
            collector
                .expect_log()
                .with_severity_text("DEBUG")
                .assert_exists();
            println!("✓ Found log with severity_text=\"DEBUG\"");

            // Count all error-level and above (using at_least)
            let error_and_above = collector
                .expect_log()
                .with_severity(SeverityNumber::Error)
                .count();
            println!("✓ {} logs at ERROR level or above", error_and_above);
        })
        .await;

    println!("\nAll severity assertions passed!");

    // Graceful shutdown
    server.shutdown().await?;
    println!("Server shut down successfully");

    Ok(())
}
