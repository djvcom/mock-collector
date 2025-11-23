//! Assertion Patterns Example
//!
//! This example demonstrates all the different assertion methods available
//! for both logs and traces in the mock collector.
//!
//! Run with: `cargo run --example assertion_patterns`

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
use opentelemetry_proto::tonic::trace::v1::{ResourceSpans, ScopeSpans, Span, span, span::Event};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Starting mock collector with gRPC...\n");

    let server = MockServer::builder()
        .protocol(Protocol::Grpc)
        .start()
        .await?;

    println!("Server: {}\n", server.addr());

    // Connect clients
    let mut log_client = LogsServiceClient::connect(format!("http://{}", server.addr())).await?;
    let mut trace_client = TraceServiceClient::connect(format!("http://{}", server.addr())).await?;

    // Send various log records
    println!("Sending log records...");
    log_client
        .export(ExportLogsServiceRequest {
            resource_logs: vec![ResourceLogs {
                resource: Some(Resource {
                    attributes: vec![
                        KeyValue {
                            key: "service.name".to_string(),
                            value: Some(AnyValue {
                                value: Some(any_value::Value::StringValue("web-api".to_string())),
                            }),
                        },
                        KeyValue {
                            key: "environment".to_string(),
                            value: Some(AnyValue {
                                value: Some(any_value::Value::StringValue(
                                    "production".to_string(),
                                )),
                            }),
                        },
                    ],
                    dropped_attributes_count: 0,
                    ..Default::default()
                }),
                scope_logs: vec![ScopeLogs {
                    scope: None,
                    log_records: vec![
                        LogRecord {
                            body: Some(AnyValue {
                                value: Some(any_value::Value::StringValue(
                                    "Request received".to_string(),
                                )),
                            }),
                            attributes: vec![KeyValue {
                                key: "http.method".to_string(),
                                value: Some(AnyValue {
                                    value: Some(any_value::Value::StringValue("GET".to_string())),
                                }),
                            }],
                            ..Default::default()
                        },
                        LogRecord {
                            body: Some(AnyValue {
                                value: Some(any_value::Value::StringValue(
                                    "Database query executed".to_string(),
                                )),
                            }),
                            ..Default::default()
                        },
                        LogRecord {
                            body: Some(AnyValue {
                                value: Some(any_value::Value::StringValue(
                                    "Response sent".to_string(),
                                )),
                            }),
                            ..Default::default()
                        },
                    ],
                    ..Default::default()
                }],
                ..Default::default()
            }],
        })
        .await?;

    // Send trace with events
    println!("Sending traces...");
    trace_client
        .export(ExportTraceServiceRequest {
            resource_spans: vec![ResourceSpans {
                resource: Some(Resource {
                    attributes: vec![KeyValue {
                        key: "service.name".to_string(),
                        value: Some(AnyValue {
                            value: Some(any_value::Value::StringValue("web-api".to_string())),
                        }),
                    }],
                    dropped_attributes_count: 0,
                    ..Default::default()
                }),
                scope_spans: vec![ScopeSpans {
                    scope: None,
                    spans: vec![
                        Span {
                            trace_id: vec![1u8; 16],
                            span_id: vec![1u8; 8],
                            name: "GET /api/users".to_string(),
                            kind: span::SpanKind::Server as i32,
                            start_time_unix_nano: 1000000,
                            end_time_unix_nano: 2000000,
                            attributes: vec![KeyValue {
                                key: "http.status_code".to_string(),
                                value: Some(AnyValue {
                                    value: Some(any_value::Value::StringValue("200".to_string())),
                                }),
                            }],
                            events: vec![Event {
                                time_unix_nano: 1500000,
                                name: "cache.hit".to_string(),
                                attributes: vec![KeyValue {
                                    key: "cache.key".to_string(),
                                    value: Some(AnyValue {
                                        value: Some(any_value::Value::StringValue(
                                            "users:all".to_string(),
                                        )),
                                    }),
                                }],
                                dropped_attributes_count: 0,
                            }],
                            ..Default::default()
                        },
                        Span {
                            trace_id: vec![1u8; 16],
                            span_id: vec![2u8; 8],
                            parent_span_id: vec![1u8; 8],
                            name: "database.query".to_string(),
                            kind: span::SpanKind::Client as i32,
                            start_time_unix_nano: 1100000,
                            end_time_unix_nano: 1900000,
                            ..Default::default()
                        },
                    ],
                    ..Default::default()
                }],
                ..Default::default()
            }],
        })
        .await?;

    println!("\n=== Assertion Patterns ===\n");

    server
        .with_collector(|collector| {
            println!("--- Basic Existence Assertions ---");

            // Assert at least one log matches
            collector
                .expect_log_with_body("Request received")
                .assert_exists();
            println!("✓ assert() - At least one log with body 'Request received'");

            // Assert no logs match
            collector
                .expect_log_with_body("Error occurred")
                .assert_not_exists();
            println!("✓ assert_not_exists() - No logs with body 'Error occurred'");

            println!("\n--- Count-Based Assertions ---");

            // Assert exact count
            collector.expect_log().assert_count(3);
            println!("✓ assert_count(3) - Exactly 3 logs");

            // Assert minimum count
            collector
                .expect_log()
                .with_resource_attributes([("service.name", "web-api")])
                .assert_at_least(3);
            println!("✓ assert_at_least(3) - At least 3 logs from web-api");

            // Assert maximum count
            collector
                .expect_log_with_body("Request received")
                .assert_at_most(1);
            println!("✓ assert_at_most(1) - At most 1 'Request received' log");

            println!("\n--- Attribute Assertions ---");

            // Log attributes
            collector
                .expect_log_with_body("Request received")
                .with_attributes([("http.method", "GET")])
                .assert_exists();
            println!("✓ with_attributes() - Log has http.method=GET");

            // Resource attributes
            collector
                .expect_log()
                .with_resource_attributes([
                    ("service.name", "web-api"),
                    ("environment", "production"),
                ])
                .assert_at_least(1);
            println!("✓ with_resource_attributes() - Logs from production web-api");

            println!("\n--- Span Assertions ---");

            // Span existence
            collector
                .expect_span_with_name("GET /api/users")
                .assert_exists();
            println!("✓ has_span_with_name() - Found span");

            // Span with attributes
            collector
                .expect_span_with_name("GET /api/users")
                .with_attributes([("http.status_code", "200")])
                .assert_exists();
            println!("✓ Span has attribute http.status_code=200");

            // Span count
            collector.expect_span().assert_count(2);
            println!("✓ Exactly 2 spans");

            println!("\n--- Event Assertions ---");

            // Span with event
            collector
                .expect_span_with_name("GET /api/users")
                .with_event("cache.hit")
                .assert_exists();
            println!("✓ with_event() - Span has 'cache.hit' event");

            // Event with attributes
            collector
                .expect_span_with_name("GET /api/users")
                .with_event_attributes("cache.hit", [("cache.key", "users:all")])
                .assert_exists();
            println!("✓ with_event_attributes() - Event has correct attributes");

            println!("\n--- Inspection Methods ---");

            // Get count
            let log_count = collector.log_count();
            let span_count = collector.span_count();
            println!("✓ log_count() = {}", log_count);
            println!("✓ span_count() = {}", span_count);

            // Get matching items
            let log_assertion = collector
                .expect_log()
                .with_resource_attributes([("service.name", "web-api")]);
            let matching_logs = log_assertion.get_all();
            println!("✓ get_all() returned {} matching logs", matching_logs.len());

            // Count matches
            let match_count = collector
                .expect_span()
                .with_resource_attributes([("service.name", "web-api")])
                .count();
            println!("✓ count() returned {} matching spans", match_count);
        })
        .await;

    server.shutdown().await?;

    println!("\nAll assertion patterns demonstrated successfully!");

    Ok(())
}
