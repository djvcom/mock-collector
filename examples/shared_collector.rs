//! Shared Collector Example
//!
//! This example demonstrates how to share a single collector between multiple servers,
//! useful for testing applications that export to different endpoints.
//!
//! Run with: `cargo run --example shared_collector`

use mock_collector::{MockCollector, MockServer, Protocol};
use opentelemetry_proto::tonic::collector::logs::v1::{
    ExportLogsServiceRequest, logs_service_client::LogsServiceClient,
};
use opentelemetry_proto::tonic::common::v1::{AnyValue, KeyValue, any_value};
use opentelemetry_proto::tonic::logs::v1::{LogRecord, ResourceLogs, ScopeLogs};
use opentelemetry_proto::tonic::resource::v1::Resource;
use prost::Message;
use std::sync::Arc;
use tokio::sync::RwLock;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Starting multiple servers with shared collector...\n");

    // Create a shared collector
    let collector = Arc::new(RwLock::new(MockCollector::new()));

    // Start gRPC server
    let grpc_server = MockServer::builder()
        .protocol(Protocol::Grpc)
        .collector(collector.clone())
        .start()
        .await?;

    println!("gRPC server: {}", grpc_server.addr());

    // Start HTTP/JSON server
    let json_server = MockServer::builder()
        .protocol(Protocol::HttpJson)
        .collector(collector.clone())
        .start()
        .await?;

    println!("HTTP/JSON server: {}", json_server.addr());

    // Start HTTP/Protobuf server
    let proto_server = MockServer::builder()
        .protocol(Protocol::HttpBinary)
        .collector(collector.clone())
        .start()
        .await?;

    println!("HTTP/Protobuf server: {}\n", proto_server.addr());

    // Send logs to gRPC server
    println!("Sending logs to gRPC server...");
    let mut grpc_client =
        LogsServiceClient::connect(format!("http://{}", grpc_server.addr())).await?;

    grpc_client
        .export(ExportLogsServiceRequest {
            resource_logs: vec![ResourceLogs {
                resource: Some(Resource {
                    attributes: vec![KeyValue {
                        key: "protocol".to_string(),
                        value: Some(AnyValue {
                            value: Some(any_value::Value::StringValue("grpc".to_string())),
                        }),
                    }],
                    dropped_attributes_count: 0,
                    ..Default::default()
                }),
                scope_logs: vec![ScopeLogs {
                    scope: None,
                    log_records: vec![LogRecord {
                        body: Some(AnyValue {
                            value: Some(any_value::Value::StringValue("Log from gRPC".to_string())),
                        }),
                        ..Default::default()
                    }],
                    ..Default::default()
                }],
                ..Default::default()
            }],
        })
        .await?;

    // Send logs to HTTP/JSON server
    println!("Sending logs to HTTP/JSON server...");
    let http_client = reqwest::Client::new();

    let json_request = ExportLogsServiceRequest {
        resource_logs: vec![ResourceLogs {
            resource: Some(Resource {
                attributes: vec![KeyValue {
                    key: "protocol".to_string(),
                    value: Some(AnyValue {
                        value: Some(any_value::Value::StringValue("http-json".to_string())),
                    }),
                }],
                dropped_attributes_count: 0,
                ..Default::default()
            }),
            scope_logs: vec![ScopeLogs {
                scope: None,
                log_records: vec![LogRecord {
                    body: Some(AnyValue {
                        value: Some(any_value::Value::StringValue(
                            "Log from HTTP/JSON".to_string(),
                        )),
                    }),
                    ..Default::default()
                }],
                ..Default::default()
            }],
            ..Default::default()
        }],
    };

    http_client
        .post(format!("http://{}/v1/logs", json_server.addr()))
        .header("Content-Type", "application/json")
        .body(serde_json::to_string(&json_request)?)
        .send()
        .await?;

    // Send logs to HTTP/Protobuf server
    println!("Sending logs to HTTP/Protobuf server...\n");

    let proto_request = ExportLogsServiceRequest {
        resource_logs: vec![ResourceLogs {
            resource: Some(Resource {
                attributes: vec![KeyValue {
                    key: "protocol".to_string(),
                    value: Some(AnyValue {
                        value: Some(any_value::Value::StringValue("http-proto".to_string())),
                    }),
                }],
                dropped_attributes_count: 0,
                ..Default::default()
            }),
            scope_logs: vec![ScopeLogs {
                scope: None,
                log_records: vec![LogRecord {
                    body: Some(AnyValue {
                        value: Some(any_value::Value::StringValue(
                            "Log from HTTP/Protobuf".to_string(),
                        )),
                    }),
                    ..Default::default()
                }],
                ..Default::default()
            }],
            ..Default::default()
        }],
    };

    http_client
        .post(format!("http://{}/v1/logs", proto_server.addr()))
        .header("Content-Type", "application/x-protobuf")
        .body(proto_request.encode_to_vec())
        .send()
        .await?;

    // Access the shared collector directly
    let log_count = collector.read().await.log_count();
    println!("Total logs in shared collector: {}", log_count);
    assert_eq!(log_count, 3);

    // Verify each protocol's logs
    let collector_guard = collector.read().await;

    collector_guard.has_log_with_body("Log from gRPC").assert();
    println!("✓ Found log from gRPC");

    collector_guard
        .has_log_with_body("Log from HTTP/JSON")
        .assert();
    println!("✓ Found log from HTTP/JSON");

    collector_guard
        .has_log_with_body("Log from HTTP/Protobuf")
        .assert();
    println!("✓ Found log from HTTP/Protobuf");

    // Verify by protocol attribute
    collector_guard
        .has_logs()
        .with_resource_attributes([("protocol", "grpc")])
        .assert_count(1);
    println!("✓ Found 1 log with protocol=grpc");

    collector_guard
        .has_logs()
        .with_resource_attributes([("protocol", "http-json")])
        .assert_count(1);
    println!("✓ Found 1 log with protocol=http-json");

    collector_guard
        .has_logs()
        .with_resource_attributes([("protocol", "http-proto")])
        .assert_count(1);
    println!("✓ Found 1 log with protocol=http-proto");

    drop(collector_guard);

    // Cleanup
    grpc_server.shutdown().await?;
    json_server.shutdown().await?;
    proto_server.shutdown().await?;

    println!("\nAll servers shut down successfully!");

    Ok(())
}
