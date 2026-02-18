//! HTTP Protocols Example
//!
//! This example demonstrates the different HTTP protocols supported by the mock collector:
//! - HTTP/JSON (application/json)
//! - HTTP/Protobuf (application/x-protobuf)
//!
//! Run with: `cargo run --example http_protocols`

use mock_collector::{MockServer, Protocol};
use opentelemetry_proto::tonic::collector::logs::v1::ExportLogsServiceRequest;
use opentelemetry_proto::tonic::common::v1::{AnyValue, KeyValue, any_value};
use opentelemetry_proto::tonic::logs::v1::{LogRecord, ResourceLogs, ScopeLogs};
use opentelemetry_proto::tonic::resource::v1::Resource;
use prost::Message;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== HTTP/JSON Protocol ===\n");

    let json_server = MockServer::builder()
        .protocol(Protocol::HttpJson)
        .start()
        .await?;

    println!("JSON server started on {}", json_server.addr());

    let log_request = ExportLogsServiceRequest {
        resource_logs: vec![ResourceLogs {
            resource: Some(Resource {
                attributes: vec![KeyValue {
                    key: "service.name".to_string(),
                    value: Some(AnyValue {
                        value: Some(any_value::Value::StringValue("json-service".to_string())),
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
                            "Sent via HTTP/JSON".to_string(),
                        )),
                    }),
                    ..Default::default()
                }],
                ..Default::default()
            }],
            ..Default::default()
        }],
    };

    let client = reqwest::Client::new();
    let json_body = serde_json::to_string(&log_request)?;
    let response = client
        .post(format!("http://{}/v1/logs", json_server.addr()))
        .header("Content-Type", "application/json")
        .body(json_body)
        .send()
        .await?;

    println!("Response status: {}", response.status());
    assert_eq!(response.status(), 200);

    json_server
        .with_collector(|collector| {
            println!("Logs received: {}\n", collector.log_count());
            collector
                .expect_log_with_body("Sent via HTTP/JSON")
                .assert_exists();
        })
        .await;

    json_server.shutdown().await?;

    println!("=== HTTP/Protobuf Protocol ===\n");

    let proto_server = MockServer::builder()
        .protocol(Protocol::HttpBinary)
        .start()
        .await?;

    println!("Protobuf server started on {}", proto_server.addr());

    let log_request = ExportLogsServiceRequest {
        resource_logs: vec![ResourceLogs {
            resource: Some(Resource {
                attributes: vec![KeyValue {
                    key: "service.name".to_string(),
                    value: Some(AnyValue {
                        value: Some(any_value::Value::StringValue("proto-service".to_string())),
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
                            "Sent via HTTP/Protobuf".to_string(),
                        )),
                    }),
                    ..Default::default()
                }],
                ..Default::default()
            }],
            ..Default::default()
        }],
    };

    let proto_bytes = log_request.encode_to_vec();

    let response = client
        .post(format!("http://{}/v1/logs", proto_server.addr()))
        .header("Content-Type", "application/x-protobuf")
        .body(proto_bytes)
        .send()
        .await?;

    println!("Response status: {}", response.status());
    assert_eq!(response.status(), 200);

    proto_server
        .with_collector(|collector| {
            println!("Logs received: {}\n", collector.log_count());
            collector
                .expect_log_with_body("Sent via HTTP/Protobuf")
                .assert_exists();
        })
        .await;

    proto_server.shutdown().await?;

    println!("Both protocols work correctly!");

    Ok(())
}
