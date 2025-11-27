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

    // Start a gRPC server on an OS-assigned port
    let server = MockServer::builder()
        .protocol(Protocol::Grpc)
        .start()
        .await?;

    println!("Server started on {}", server.addr());

    // Create a gRPC client
    let mut client = LogsServiceClient::connect(format!("http://{}", server.addr())).await?;

    println!("Sending log records via gRPC...");

    // Send some log records
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

    // Perform assertions on collected data
    println!("Performing assertions...");

    server
        .with_collector(|collector| {
            println!("Total logs collected: {}", collector.log_count());

            // Assert we received exactly 3 logs
            assert_eq!(collector.log_count(), 3);

            // Assert on specific log
            collector
                .expect_log_with_body("Application started")
                .with_resource_attributes([("service.name", "example-service")])
                .assert_exists();

            println!("✓ Found 'Application started' log with correct service name");

            // Assert on log with attributes
            collector
                .expect_log_with_body("Processing request")
                .with_attributes([("request.id", "req-12345")])
                .assert_exists();

            println!("✓ Found 'Processing request' log with request ID");

            // Count logs from the service
            let service_logs = collector
                .expect_log()
                .with_resource_attributes([("service.name", "example-service")])
                .count();

            println!("✓ Found {} logs from example-service", service_logs);

            // Verify negative case - this log doesn't exist
            collector
                .expect_log_with_body("Error occurred")
                .assert_not_exists();

            println!("✓ Verified 'Error occurred' log doesn't exist");
        })
        .await;

    println!("\nAll assertions passed!");

    // Graceful shutdown
    server.shutdown().await?;
    println!("Server shut down successfully");

    Ok(())
}
