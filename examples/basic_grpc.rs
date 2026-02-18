//! Basic gRPC Example
//!
//! This example demonstrates how to start a mock OTLP collector with gRPC protocol
//! and perform basic assertions on collected telemetry data.
//!
//! Run with: `cargo run --example basic_grpc`

use mock_collector::{MockServer, Protocol};
use opentelemetry_proto::tonic::collector::logs::v1::{
    ExportLogsServiceRequest, logs_service_client::LogsServiceClient,
};
use opentelemetry_proto::tonic::common::v1::{AnyValue, KeyValue, any_value};
use opentelemetry_proto::tonic::logs::v1::{LogRecord, ResourceLogs, ScopeLogs};
use opentelemetry_proto::tonic::resource::v1::Resource;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Starting mock OTLP collector with gRPC protocol...");

    let server = MockServer::builder()
        .protocol(Protocol::Grpc)
        .start()
        .await?;

    println!("Server started on {}", server.addr());

    let mut client = LogsServiceClient::connect(format!("http://{}", server.addr())).await?;

    println!("Sending log records via gRPC...");

    let request = ExportLogsServiceRequest {
        resource_logs: vec![ResourceLogs {
            resource: Some(Resource {
                attributes: vec![KeyValue {
                    key: "service.name".to_string(),
                    value: Some(AnyValue {
                        value: Some(any_value::Value::StringValue("example-service".to_string())),
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
                                "Application started".to_string(),
                            )),
                        }),
                        severity_text: "INFO".to_string(),
                        ..Default::default()
                    },
                    LogRecord {
                        body: Some(AnyValue {
                            value: Some(any_value::Value::StringValue(
                                "Processing request".to_string(),
                            )),
                        }),
                        severity_text: "INFO".to_string(),
                        attributes: vec![KeyValue {
                            key: "request.id".to_string(),
                            value: Some(AnyValue {
                                value: Some(any_value::Value::StringValue("req-12345".to_string())),
                            }),
                        }],
                        ..Default::default()
                    },
                    LogRecord {
                        body: Some(AnyValue {
                            value: Some(any_value::Value::StringValue(
                                "Request completed".to_string(),
                            )),
                        }),
                        severity_text: "INFO".to_string(),
                        ..Default::default()
                    },
                ],
                ..Default::default()
            }],
            ..Default::default()
        }],
    };

    client.export(request).await?;

    println!("Log records sent successfully!\n");

    // In real tests, telemetry often arrives asynchronously (batched, buffered, etc.)
    // Use wait_for_* methods to wait for data before asserting
    use std::time::Duration;
    server.wait_for_logs(3, Duration::from_secs(5)).await?;
    println!("Logs arrived (waited with timeout)");

    println!("Performing assertions...");

    server
        .with_collector(|collector| {
            println!("Total logs collected: {}", collector.log_count());

            assert_eq!(collector.log_count(), 3);

            collector
                .expect_log_with_body("Application started")
                .with_resource_attributes([("service.name", "example-service")])
                .assert_exists();

            println!("✓ Found 'Application started' log with correct service name");

            collector
                .expect_log_with_body("Processing request")
                .with_attributes([("request.id", "req-12345")])
                .assert_exists();

            println!("✓ Found 'Processing request' log with request ID");

            let service_logs = collector
                .expect_log()
                .with_resource_attributes([("service.name", "example-service")])
                .count();

            println!("✓ Found {} logs from example-service", service_logs);

            collector
                .expect_log_with_body("Error occurred")
                .assert_not_exists();

            println!("✓ Verified 'Error occurred' log doesn't exist");
        })
        .await;

    println!("\nAll assertions passed!");

    server.shutdown().await?;
    println!("Server shut down successfully");

    Ok(())
}
