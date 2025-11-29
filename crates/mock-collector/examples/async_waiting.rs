//! Async Waiting Example
//!
//! This example demonstrates how to use the async waiting methods to handle
//! telemetry that arrives asynchronously. This is particularly useful when
//! testing pipelines where signals are batched, buffered, or exported on
//! shutdown.
//!
//! Run with: `cargo run --example async_waiting`

use mock_collector::{MockServer, Protocol};
use opentelemetry_proto::tonic::collector::logs::v1::{
    ExportLogsServiceRequest, logs_service_client::LogsServiceClient,
};
use opentelemetry_proto::tonic::collector::trace::v1::{
    ExportTraceServiceRequest, trace_service_client::TraceServiceClient,
};
use opentelemetry_proto::tonic::common::v1::{AnyValue, KeyValue, any_value};
use opentelemetry_proto::tonic::logs::v1::{LogRecord, ResourceLogs, ScopeLogs};
use opentelemetry_proto::tonic::resource::v1::Resource;
use opentelemetry_proto::tonic::trace::v1::{ResourceSpans, ScopeSpans, Span};
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Async Waiting Example ===\n");

    demonstrate_wait_for_convenience_methods().await?;
    demonstrate_wait_until_predicate().await?;
    demonstrate_timeout_handling().await?;

    println!("\nAll examples completed successfully!");
    Ok(())
}

async fn demonstrate_wait_for_convenience_methods() -> Result<(), Box<dyn std::error::Error>> {
    println!("--- Convenience Methods (wait_for_*) ---\n");

    let server = MockServer::builder()
        .protocol(Protocol::Grpc)
        .start()
        .await?;

    let addr = server.addr();

    // Spawn a task that sends data with a delay (simulating async pipeline)
    let send_task = tokio::spawn(async move {
        // Simulate processing delay
        tokio::time::sleep(Duration::from_millis(100)).await;

        let mut client = LogsServiceClient::connect(format!("http://{}", addr))
            .await
            .unwrap();

        let request = ExportLogsServiceRequest {
            resource_logs: vec![ResourceLogs {
                resource: Some(Resource {
                    attributes: vec![KeyValue {
                        key: "service.name".to_string(),
                        value: Some(AnyValue {
                            value: Some(any_value::Value::StringValue("async-service".to_string())),
                        }),
                    }],
                    ..Default::default()
                }),
                scope_logs: vec![ScopeLogs {
                    log_records: vec![
                        create_log_record("First log message"),
                        create_log_record("Second log message"),
                        create_log_record("Third log message"),
                    ],
                    ..Default::default()
                }],
                ..Default::default()
            }],
        };

        client.export(request).await.unwrap();
        println!("  [Background] Logs sent after 100ms delay");
    });

    // Wait for logs to arrive using convenience method
    println!("  Waiting for 3 logs to arrive...");
    server.wait_for_logs(3, Duration::from_secs(5)).await?;
    println!("  Logs arrived!");

    // Now safe to assert
    server
        .with_collector(|collector| {
            assert_eq!(collector.log_count(), 3);
            collector
                .expect_log_with_body("First log message")
                .assert_exists();
            println!("  Assertions passed");
        })
        .await;

    send_task.await?;
    server.shutdown().await?;
    println!();
    Ok(())
}

async fn demonstrate_wait_until_predicate() -> Result<(), Box<dyn std::error::Error>> {
    println!("--- Generic Predicate (wait_until) ---\n");

    let server = MockServer::builder()
        .protocol(Protocol::Grpc)
        .start()
        .await?;

    let addr = server.addr();

    // Spawn a task that sends spans with specific attributes
    let send_task = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(50)).await;

        let mut client = TraceServiceClient::connect(format!("http://{}", addr))
            .await
            .unwrap();

        let request = ExportTraceServiceRequest {
            resource_spans: vec![ResourceSpans {
                resource: Some(Resource {
                    attributes: vec![KeyValue {
                        key: "service.name".to_string(),
                        value: Some(AnyValue {
                            value: Some(any_value::Value::StringValue("api-gateway".to_string())),
                        }),
                    }],
                    ..Default::default()
                }),
                scope_spans: vec![ScopeSpans {
                    spans: vec![Span {
                        name: "HTTP GET /users".to_string(),
                        attributes: vec![
                            KeyValue {
                                key: "http.method".to_string(),
                                value: Some(AnyValue {
                                    value: Some(any_value::Value::StringValue("GET".to_string())),
                                }),
                            },
                            KeyValue {
                                key: "http.status_code".to_string(),
                                value: Some(AnyValue {
                                    value: Some(any_value::Value::IntValue(200)),
                                }),
                            },
                        ],
                        ..Default::default()
                    }],
                    ..Default::default()
                }],
                ..Default::default()
            }],
        };

        client.export(request).await.unwrap();
        println!("  [Background] Span sent after 50ms delay");
    });

    // Wait for a span matching specific criteria using a predicate
    println!("  Waiting for HTTP span with status 200...");
    server
        .wait_until(
            |c| {
                c.expect_span_with_name("HTTP GET /users")
                    .with_attributes([("http.status_code", 200)])
                    .count()
                    >= 1
            },
            Duration::from_secs(5),
        )
        .await?;
    println!("  Matching span found!");

    // Detailed assertions
    server
        .with_collector(|collector| {
            collector
                .expect_span_with_name("HTTP GET /users")
                .with_attributes([("http.method", "GET")])
                .with_attributes([("http.status_code", 200)])
                .with_resource_attributes([("service.name", "api-gateway")])
                .assert_exists();
            println!("  Detailed assertions passed");
        })
        .await;

    send_task.await?;
    server.shutdown().await?;
    println!();
    Ok(())
}

async fn demonstrate_timeout_handling() -> Result<(), Box<dyn std::error::Error>> {
    println!("--- Timeout Handling ---\n");

    let server = MockServer::builder()
        .protocol(Protocol::Grpc)
        .start()
        .await?;

    // Try to wait for data that will never arrive
    println!("  Attempting to wait for spans (none will arrive)...");
    let result = server.wait_for_spans(1, Duration::from_millis(200)).await;

    match result {
        Ok(()) => println!("  Unexpected: spans arrived"),
        Err(e) => println!("  Expected timeout occurred: {}", e),
    }

    // Demonstrate that the server still works after timeout
    server
        .with_collector(|collector| {
            assert_eq!(collector.span_count(), 0);
            println!("  Server still functional after timeout");
        })
        .await;

    server.shutdown().await?;
    println!();
    Ok(())
}

fn create_log_record(body: &str) -> LogRecord {
    LogRecord {
        body: Some(AnyValue {
            value: Some(any_value::Value::StringValue(body.to_string())),
        }),
        severity_text: "INFO".to_string(),
        ..Default::default()
    }
}
