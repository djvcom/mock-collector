use mock_collector::{MockServer, MockServerError, Protocol};
use std::fs;
use std::path::PathBuf;
use std::time::Duration;

fn example_path(filename: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("opentelemetry-proto-examples")
        .join("examples")
        .join(filename)
}

#[tokio::test]
async fn test_http_json_logs_with_official_example() {
    // Start HTTP JSON server
    let server = MockServer::builder()
        .protocol(Protocol::HttpJson)
        .start()
        .await
        .expect("Failed to start server");

    // Load official OTLP example
    let example_json =
        fs::read_to_string(example_path("logs.json")).expect("Failed to read logs.json example");

    // Send to server
    let client = reqwest::Client::new();
    let response = client
        .post(format!("http://{}/v1/logs", server.addr()))
        .header("Content-Type", "application/json")
        .body(example_json)
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(response.status(), 200);

    // Assert on collected data
    server
        .with_collector(|collector| {
            assert_eq!(collector.log_count(), 1);

            // Verify the log body
            collector
                .expect_log_with_body("Example log record")
                .assert_exists();

            // Verify resource attributes
            collector
                .expect_log_with_body("Example log record")
                .with_resource_attributes([("service.name", "my.service")])
                .assert_exists();

            // Verify scope attributes
            collector
                .expect_log_with_body("Example log record")
                .with_scope_attributes([("my.scope.attribute", "some scope attribute")])
                .assert_exists();

            // Verify log-level string attributes
            collector
                .expect_log_with_body("Example log record")
                .with_attributes([("string.attribute", "some string")])
                .assert_exists();
        })
        .await;

    server.shutdown().await.expect("Failed to shutdown");
}

#[tokio::test]
async fn test_http_json_traces_with_official_example() {
    // Start HTTP JSON server
    let server = MockServer::builder()
        .protocol(Protocol::HttpJson)
        .start()
        .await
        .expect("Failed to start server");

    // Load official OTLP example
    let example_json =
        fs::read_to_string(example_path("trace.json")).expect("Failed to read trace.json example");

    // Send to server
    let client = reqwest::Client::new();
    let response = client
        .post(format!("http://{}/v1/traces", server.addr()))
        .header("Content-Type", "application/json")
        .body(example_json)
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(response.status(), 200);

    // Assert on collected data
    server
        .with_collector(|collector| {
            assert_eq!(collector.span_count(), 1);

            // Verify the span name
            collector
                .expect_span_with_name("I'm a server span")
                .assert_exists();

            // Verify resource attributes
            collector
                .expect_span_with_name("I'm a server span")
                .with_resource_attributes([("service.name", "my.service")])
                .assert_exists();

            // Verify scope attributes
            collector
                .expect_span_with_name("I'm a server span")
                .with_scope_attributes([("my.scope.attribute", "some scope attribute")])
                .assert_exists();

            // Verify span attributes
            collector
                .expect_span_with_name("I'm a server span")
                .with_attributes([("my.span.attr", "some value")])
                .assert_exists();
        })
        .await;

    server.shutdown().await.expect("Failed to shutdown");
}

#[tokio::test]
async fn test_http_protobuf_logs_with_official_example() {
    // Start HTTP Protobuf server
    let server = MockServer::builder()
        .protocol(Protocol::HttpBinary)
        .start()
        .await
        .expect("Failed to start server");

    // Load and parse JSON example
    let example_json =
        fs::read_to_string(example_path("logs.json")).expect("Failed to read logs.json example");

    let logs_request: opentelemetry_proto::tonic::collector::logs::v1::ExportLogsServiceRequest =
        serde_json::from_str(&example_json).expect("Failed to parse JSON");

    // Convert to protobuf bytes
    use prost::Message;
    let proto_bytes = logs_request.encode_to_vec();

    // Send to server
    let client = reqwest::Client::new();
    let response = client
        .post(format!("http://{}/v1/logs", server.addr()))
        .header("Content-Type", "application/x-protobuf")
        .body(proto_bytes)
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(response.status(), 200);

    // Assert on collected data (same assertions as JSON test)
    server
        .with_collector(|collector| {
            assert_eq!(collector.log_count(), 1);

            collector
                .expect_log_with_body("Example log record")
                .with_resource_attributes([("service.name", "my.service")])
                .with_scope_attributes([("my.scope.attribute", "some scope attribute")])
                .with_attributes([("string.attribute", "some string")])
                .assert_exists();
        })
        .await;

    server.shutdown().await.expect("Failed to shutdown");
}

#[tokio::test]
async fn test_http_protobuf_traces_with_official_example() {
    // Start HTTP Protobuf server
    let server = MockServer::builder()
        .protocol(Protocol::HttpBinary)
        .start()
        .await
        .expect("Failed to start server");

    // Load and parse JSON example
    let example_json =
        fs::read_to_string(example_path("trace.json")).expect("Failed to read trace.json example");

    let trace_request: opentelemetry_proto::tonic::collector::trace::v1::ExportTraceServiceRequest =
        serde_json::from_str(&example_json).expect("Failed to parse JSON");

    // Convert to protobuf bytes
    use prost::Message;
    let proto_bytes = trace_request.encode_to_vec();

    // Send to server
    let client = reqwest::Client::new();
    let response = client
        .post(format!("http://{}/v1/traces", server.addr()))
        .header("Content-Type", "application/x-protobuf")
        .body(proto_bytes)
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(response.status(), 200);

    // Assert on collected data
    server
        .with_collector(|collector| {
            assert_eq!(collector.span_count(), 1);

            collector
                .expect_span_with_name("I'm a server span")
                .with_resource_attributes([("service.name", "my.service")])
                .with_scope_attributes([("my.scope.attribute", "some scope attribute")])
                .with_attributes([("my.span.attr", "some value")])
                .assert_exists();
        })
        .await;

    server.shutdown().await.expect("Failed to shutdown");
}

#[tokio::test]
async fn test_grpc_logs_and_traces_simultaneously() {
    // Start gRPC server (supports both logs and traces)
    let server = MockServer::builder()
        .protocol(Protocol::Grpc)
        .start()
        .await
        .expect("Failed to start server");

    // Load examples
    let logs_json =
        fs::read_to_string(example_path("logs.json")).expect("Failed to read logs.json");
    let trace_json =
        fs::read_to_string(example_path("trace.json")).expect("Failed to read trace.json");

    let logs_request: opentelemetry_proto::tonic::collector::logs::v1::ExportLogsServiceRequest =
        serde_json::from_str(&logs_json).expect("Failed to parse logs JSON");
    let trace_request: opentelemetry_proto::tonic::collector::trace::v1::ExportTraceServiceRequest =
        serde_json::from_str(&trace_json).expect("Failed to parse trace JSON");

    // Send via gRPC
    use opentelemetry_proto::tonic::collector::logs::v1::logs_service_client::LogsServiceClient;
    use opentelemetry_proto::tonic::collector::trace::v1::trace_service_client::TraceServiceClient;

    let mut logs_client = LogsServiceClient::connect(format!("http://{}", server.addr()))
        .await
        .expect("Failed to connect logs client");

    let mut trace_client = TraceServiceClient::connect(format!("http://{}", server.addr()))
        .await
        .expect("Failed to connect trace client");

    // Send logs
    let log_response = logs_client
        .export(logs_request)
        .await
        .expect("Failed to export logs");
    assert!(log_response.into_inner().partial_success.is_none());

    // Send traces
    let trace_response = trace_client
        .export(trace_request)
        .await
        .expect("Failed to export traces");
    assert!(trace_response.into_inner().partial_success.is_none());

    // Assert both were collected
    server
        .with_collector(|collector| {
            // Both logs and traces should be present
            assert_eq!(collector.log_count(), 1);
            assert_eq!(collector.span_count(), 1);

            // Verify log
            collector
                .expect_log_with_body("Example log record")
                .with_resource_attributes([("service.name", "my.service")])
                .assert_exists();

            // Verify span
            collector
                .expect_span_with_name("I'm a server span")
                .with_resource_attributes([("service.name", "my.service")])
                .assert_exists();
        })
        .await;

    server.shutdown().await.expect("Failed to shutdown");
}

#[tokio::test]
async fn test_span_event_assertions() {
    use opentelemetry_proto::tonic::collector::trace::v1::ExportTraceServiceRequest;
    use opentelemetry_proto::tonic::common::v1::{AnyValue, KeyValue, any_value};
    use opentelemetry_proto::tonic::trace::v1::{
        ResourceSpans, ScopeSpans, Span, span, span::Event,
    };
    use prost::Message;

    // Start HTTP Protobuf server
    let server = MockServer::builder()
        .protocol(Protocol::HttpBinary)
        .start()
        .await
        .expect("Failed to start server");

    // Create a span with events
    let trace_request = ExportTraceServiceRequest {
        resource_spans: vec![ResourceSpans {
            resource: None,
            scope_spans: vec![ScopeSpans {
                scope: None,
                spans: vec![Span {
                    trace_id: vec![0u8; 16],
                    span_id: vec![0u8; 8],
                    name: "OrderProcessing".to_string(),
                    kind: span::SpanKind::Internal as i32,
                    start_time_unix_nano: 1234567890,
                    end_time_unix_nano: 1234567900,
                    events: vec![
                        Event {
                            time_unix_nano: 1234567891,
                            name: "payment.initiated".to_string(),
                            attributes: vec![KeyValue {
                                key: "amount".to_string(),
                                value: Some(AnyValue {
                                    value: Some(any_value::Value::StringValue(
                                        "100.00".to_string(),
                                    )),
                                }),
                            }],
                            dropped_attributes_count: 0,
                        },
                        Event {
                            time_unix_nano: 1234567895,
                            name: "payment.completed".to_string(),
                            attributes: vec![KeyValue {
                                key: "transaction.id".to_string(),
                                value: Some(AnyValue {
                                    value: Some(any_value::Value::StringValue(
                                        "txn-12345".to_string(),
                                    )),
                                }),
                            }],
                            dropped_attributes_count: 0,
                        },
                        Event {
                            time_unix_nano: 1234567896,
                            name: "notification.sent".to_string(),
                            attributes: vec![],
                            dropped_attributes_count: 0,
                        },
                    ],
                    ..Default::default()
                }],
                ..Default::default()
            }],
            ..Default::default()
        }],
    };

    // Convert to protobuf bytes
    let proto_bytes = trace_request.encode_to_vec();

    // Send to server
    let client = reqwest::Client::new();
    let response = client
        .post(format!("http://{}/v1/traces", server.addr()))
        .header("Content-Type", "application/x-protobuf")
        .body(proto_bytes)
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(response.status(), 200);

    // Test event assertions
    server
        .with_collector(|collector| {
            assert_eq!(collector.span_count(), 1);

            // Assert span has specific event
            collector
                .expect_span_with_name("OrderProcessing")
                .with_event("payment.initiated")
                .assert_exists();

            // Assert span has multiple events
            collector
                .expect_span_with_name("OrderProcessing")
                .with_event("payment.initiated")
                .with_event("payment.completed")
                .with_event("notification.sent")
                .assert_exists();

            // Assert event with attributes
            collector
                .expect_span_with_name("OrderProcessing")
                .with_event_attributes("payment.initiated", [("amount", "100.00")])
                .assert_exists();

            // Assert event with different attributes
            collector
                .expect_span_with_name("OrderProcessing")
                .with_event_attributes("payment.completed", [("transaction.id", "txn-12345")])
                .assert_exists();

            // Assert negative case - event doesn't exist
            collector
                .expect_span_with_name("OrderProcessing")
                .with_event("payment.failed")
                .assert_not_exists();
        })
        .await;

    server.shutdown().await.expect("Failed to shutdown");
}

#[tokio::test]
async fn test_http_json_metrics_with_official_example() {
    // Start HTTP JSON server
    let server = MockServer::builder()
        .protocol(Protocol::HttpJson)
        .start()
        .await
        .expect("Failed to start server");

    // Load official OTLP example
    let example_json = fs::read_to_string(example_path("metrics.json"))
        .expect("Failed to read metrics.json example");

    // Send to server
    let client = reqwest::Client::new();
    let response = client
        .post(format!("http://{}/v1/metrics", server.addr()))
        .header("Content-Type", "application/json")
        .body(example_json)
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(response.status(), 200);

    // Assert on collected data
    server
        .with_collector(|collector| {
            assert_eq!(collector.metric_count(), 4);

            // Verify the counter metric
            collector
                .expect_metric_with_name("my.counter")
                .assert_exists();

            // Verify resource attributes
            collector
                .expect_metric_with_name("my.counter")
                .with_resource_attributes([("service.name", "my.service")])
                .assert_exists();

            // Verify scope attributes
            collector
                .expect_metric_with_name("my.counter")
                .with_scope_attributes([("my.scope.attribute", "some scope attribute")])
                .assert_exists();

            // Verify metric data point attributes
            collector
                .expect_metric_with_name("my.counter")
                .with_attributes([("my.counter.attr", "some value")])
                .assert_exists();

            // Verify gauge metric
            collector
                .expect_metric_with_name("my.gauge")
                .with_attributes([("my.gauge.attr", "some value")])
                .assert_exists();

            // Verify histogram metric
            collector
                .expect_metric_with_name("my.histogram")
                .with_attributes([("my.histogram.attr", "some value")])
                .assert_exists();

            // Verify exponential histogram metric exists (note: HTTP JSON/Protobuf has
            // a known limitation in opentelemetry-proto 0.31.0 where exponentialHistogram
            // data is not properly deserialized, so we only check name here)
            collector
                .expect_metric_with_name("my.exponential.histogram")
                .assert_exists();

            // Test count assertions
            collector
                .expect_metric_with_name("my.counter")
                .assert_count(1);

            // Test has_metrics() without name filter
            collector
                .expect_metric()
                .with_resource_attributes([("service.name", "my.service")])
                .assert_count(4);
        })
        .await;

    server.shutdown().await.expect("Failed to shutdown");
}

#[tokio::test]
async fn test_http_protobuf_metrics_with_official_example() {
    // Start HTTP Protobuf server
    let server = MockServer::builder()
        .protocol(Protocol::HttpBinary)
        .start()
        .await
        .expect("Failed to start server");

    // Load and parse JSON example
    let example_json = fs::read_to_string(example_path("metrics.json"))
        .expect("Failed to read metrics.json example");

    let metrics_request: opentelemetry_proto::tonic::collector::metrics::v1::ExportMetricsServiceRequest =
        serde_json::from_str(&example_json).expect("Failed to parse JSON");

    // Convert to protobuf bytes
    use prost::Message;
    let proto_bytes = metrics_request.encode_to_vec();

    // Send to server
    let client = reqwest::Client::new();
    let response = client
        .post(format!("http://{}/v1/metrics", server.addr()))
        .header("Content-Type", "application/x-protobuf")
        .body(proto_bytes)
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(response.status(), 200);

    // Assert on collected data (same assertions as JSON test)
    server
        .with_collector(|collector| {
            assert_eq!(collector.metric_count(), 4);

            collector
                .expect_metric_with_name("my.counter")
                .with_resource_attributes([("service.name", "my.service")])
                .with_scope_attributes([("my.scope.attribute", "some scope attribute")])
                .with_attributes([("my.counter.attr", "some value")])
                .assert_exists();

            collector
                .expect_metric_with_name("my.gauge")
                .with_attributes([("my.gauge.attr", "some value")])
                .assert_exists();

            collector
                .expect_metric_with_name("my.histogram")
                .with_attributes([("my.histogram.attr", "some value")])
                .assert_exists();

            // Exponential histogram (same limitation as JSON test)
            collector
                .expect_metric_with_name("my.exponential.histogram")
                .assert_exists();
        })
        .await;

    server.shutdown().await.expect("Failed to shutdown");
}

#[tokio::test]
async fn test_grpc_all_signals_simultaneously() {
    // Start gRPC server (supports logs, traces, and metrics)
    let server = MockServer::builder()
        .protocol(Protocol::Grpc)
        .start()
        .await
        .expect("Failed to start server");

    // Load examples
    let logs_json =
        fs::read_to_string(example_path("logs.json")).expect("Failed to read logs.json");
    let trace_json =
        fs::read_to_string(example_path("trace.json")).expect("Failed to read trace.json");
    let metrics_json =
        fs::read_to_string(example_path("metrics.json")).expect("Failed to read metrics.json");

    let logs_request: opentelemetry_proto::tonic::collector::logs::v1::ExportLogsServiceRequest =
        serde_json::from_str(&logs_json).expect("Failed to parse logs JSON");
    let trace_request: opentelemetry_proto::tonic::collector::trace::v1::ExportTraceServiceRequest =
        serde_json::from_str(&trace_json).expect("Failed to parse trace JSON");
    let metrics_request: opentelemetry_proto::tonic::collector::metrics::v1::ExportMetricsServiceRequest =
        serde_json::from_str(&metrics_json).expect("Failed to parse metrics JSON");

    // Send via gRPC
    use opentelemetry_proto::tonic::collector::logs::v1::logs_service_client::LogsServiceClient;
    use opentelemetry_proto::tonic::collector::metrics::v1::metrics_service_client::MetricsServiceClient;
    use opentelemetry_proto::tonic::collector::trace::v1::trace_service_client::TraceServiceClient;

    let mut logs_client = LogsServiceClient::connect(format!("http://{}", server.addr()))
        .await
        .expect("Failed to connect logs client");

    let mut trace_client = TraceServiceClient::connect(format!("http://{}", server.addr()))
        .await
        .expect("Failed to connect trace client");

    let mut metrics_client = MetricsServiceClient::connect(format!("http://{}", server.addr()))
        .await
        .expect("Failed to connect metrics client");

    // Send logs
    let log_response = logs_client
        .export(logs_request)
        .await
        .expect("Failed to export logs");
    assert!(log_response.into_inner().partial_success.is_none());

    // Send traces
    let trace_response = trace_client
        .export(trace_request)
        .await
        .expect("Failed to export traces");
    assert!(trace_response.into_inner().partial_success.is_none());

    // Send metrics
    let metrics_response = metrics_client
        .export(metrics_request)
        .await
        .expect("Failed to export metrics");
    assert!(metrics_response.into_inner().partial_success.is_none());

    // Assert all three signals were collected
    server
        .with_collector(|collector| {
            // All signals should be present
            assert_eq!(collector.log_count(), 1);
            assert_eq!(collector.span_count(), 1);
            assert_eq!(collector.metric_count(), 4);

            // Verify log
            collector
                .expect_log_with_body("Example log record")
                .with_resource_attributes([("service.name", "my.service")])
                .assert_exists();

            // Verify span
            collector
                .expect_span_with_name("I'm a server span")
                .with_resource_attributes([("service.name", "my.service")])
                .assert_exists();

            // Verify metrics
            collector
                .expect_metric_with_name("my.counter")
                .with_resource_attributes([("service.name", "my.service")])
                .assert_exists();

            collector
                .expect_metric_with_name("my.gauge")
                .with_resource_attributes([("service.name", "my.service")])
                .assert_exists();
        })
        .await;

    server.shutdown().await.expect("Failed to shutdown");
}
#[tokio::test]
async fn test_severity_assertions() {
    use mock_collector::SeverityNumber;
    use opentelemetry_proto::tonic::collector::logs::v1::{
        ExportLogsServiceRequest, logs_service_client::LogsServiceClient,
    };
    use opentelemetry_proto::tonic::common::v1::{AnyValue, KeyValue, any_value};
    use opentelemetry_proto::tonic::logs::v1::{LogRecord, ResourceLogs, ScopeLogs};
    use opentelemetry_proto::tonic::resource::v1::Resource;

    // Start gRPC server
    let server = MockServer::builder()
        .protocol(Protocol::Grpc)
        .start()
        .await
        .expect("Failed to start server");

    // Create a gRPC client
    let mut client = LogsServiceClient::connect(format!("http://{}", server.addr()))
        .await
        .expect("Failed to connect");

    // Send logs with different severity levels
    let request = ExportLogsServiceRequest {
        resource_logs: vec![ResourceLogs {
            resource: Some(Resource {
                attributes: vec![KeyValue {
                    key: "service.name".to_string(),
                    value: Some(AnyValue {
                        value: Some(any_value::Value::StringValue("test-service".to_string())),
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
                            value: Some(any_value::Value::StringValue("Debug message".to_string())),
                        }),
                        severity_number: SeverityNumber::Debug as i32,
                        severity_text: "DEBUG".to_string(),
                        ..Default::default()
                    },
                    LogRecord {
                        body: Some(AnyValue {
                            value: Some(any_value::Value::StringValue("Info message".to_string())),
                        }),
                        severity_number: SeverityNumber::Info as i32,
                        severity_text: "INFO".to_string(),
                        ..Default::default()
                    },
                    LogRecord {
                        body: Some(AnyValue {
                            value: Some(any_value::Value::StringValue("Error message".to_string())),
                        }),
                        severity_number: SeverityNumber::Error as i32,
                        severity_text: "ERROR".to_string(),
                        ..Default::default()
                    },
                    LogRecord {
                        body: Some(AnyValue {
                            value: Some(any_value::Value::StringValue("Another error".to_string())),
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

    client.export(request).await.expect("Failed to export logs");

    // Assert on collected data
    server
        .with_collector(|collector| {
            assert_eq!(collector.log_count(), 4);

            // Assert at least one DEBUG log exists
            collector
                .expect_log()
                .with_severity(SeverityNumber::Debug)
                .assert_exists();

            // Assert at least one INFO log exists
            collector
                .expect_log()
                .with_severity(SeverityNumber::Info)
                .assert_exists();

            // Assert exactly 2 ERROR logs
            collector
                .expect_log()
                .with_severity(SeverityNumber::Error)
                .assert_count(2);

            // Assert using severity text
            collector
                .expect_log()
                .with_severity_text("ERROR")
                .assert_count(2);

            // Combine severity with body matching
            collector
                .expect_log_with_body("Error message")
                .with_severity(SeverityNumber::Error)
                .assert_exists();

            // Combine severity with resource attributes
            collector
                .expect_log()
                .with_severity(SeverityNumber::Debug)
                .with_resource_attributes([("service.name", "test-service")])
                .assert_exists();

            // Assert no FATAL logs exist
            collector
                .expect_log()
                .with_severity(SeverityNumber::Fatal)
                .assert_not_exists();
        })
        .await;

    server.shutdown().await.expect("Failed to shutdown");
}

#[tokio::test]
async fn test_wait_for_logs() {
    use opentelemetry_proto::tonic::collector::logs::v1::{
        ExportLogsServiceRequest, logs_service_client::LogsServiceClient,
    };
    use opentelemetry_proto::tonic::common::v1::{AnyValue, any_value};
    use opentelemetry_proto::tonic::logs::v1::{LogRecord, ResourceLogs, ScopeLogs};

    let server = MockServer::builder()
        .protocol(Protocol::Grpc)
        .start()
        .await
        .expect("Failed to start server");

    let addr = server.addr();

    let send_task = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(100)).await;

        let mut client = LogsServiceClient::connect(format!("http://{}", addr))
            .await
            .unwrap();

        let request = ExportLogsServiceRequest {
            resource_logs: vec![ResourceLogs {
                resource: None,
                scope_logs: vec![ScopeLogs {
                    log_records: vec![
                        LogRecord {
                            body: Some(AnyValue {
                                value: Some(any_value::Value::StringValue("Log one".to_string())),
                            }),
                            ..Default::default()
                        },
                        LogRecord {
                            body: Some(AnyValue {
                                value: Some(any_value::Value::StringValue("Log two".to_string())),
                            }),
                            ..Default::default()
                        },
                    ],
                    ..Default::default()
                }],
                ..Default::default()
            }],
        };

        client.export(request).await.unwrap();
    });

    server
        .wait_for_logs(2, Duration::from_secs(5))
        .await
        .expect("Should receive logs before timeout");

    server
        .with_collector(|collector| {
            assert_eq!(collector.log_count(), 2);
            collector.expect_log_with_body("Log one").assert_exists();
            collector.expect_log_with_body("Log two").assert_exists();
        })
        .await;

    send_task.await.expect("Send task should complete");
    server.shutdown().await.expect("Failed to shutdown");
}

#[tokio::test]
async fn test_wait_for_spans() {
    use opentelemetry_proto::tonic::collector::trace::v1::{
        ExportTraceServiceRequest, trace_service_client::TraceServiceClient,
    };
    use opentelemetry_proto::tonic::trace::v1::{ResourceSpans, ScopeSpans, Span};

    let server = MockServer::builder()
        .protocol(Protocol::Grpc)
        .start()
        .await
        .expect("Failed to start server");

    let addr = server.addr();

    let send_task = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(50)).await;

        let mut client = TraceServiceClient::connect(format!("http://{}", addr))
            .await
            .unwrap();

        let request = ExportTraceServiceRequest {
            resource_spans: vec![ResourceSpans {
                resource: None,
                scope_spans: vec![ScopeSpans {
                    spans: vec![Span {
                        name: "test-span".to_string(),
                        ..Default::default()
                    }],
                    ..Default::default()
                }],
                ..Default::default()
            }],
        };

        client.export(request).await.unwrap();
    });

    server
        .wait_for_spans(1, Duration::from_secs(5))
        .await
        .expect("Should receive span before timeout");

    server
        .with_collector(|collector| {
            assert_eq!(collector.span_count(), 1);
            collector.expect_span_with_name("test-span").assert_exists();
        })
        .await;

    send_task.await.expect("Send task should complete");
    server.shutdown().await.expect("Failed to shutdown");
}

#[tokio::test]
async fn test_wait_for_metrics() {
    use opentelemetry_proto::tonic::collector::metrics::v1::{
        ExportMetricsServiceRequest, metrics_service_client::MetricsServiceClient,
    };
    use opentelemetry_proto::tonic::metrics::v1::{
        Gauge, Metric, ResourceMetrics, ScopeMetrics, metric,
    };

    let server = MockServer::builder()
        .protocol(Protocol::Grpc)
        .start()
        .await
        .expect("Failed to start server");

    let addr = server.addr();

    let send_task = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(75)).await;

        let mut client = MetricsServiceClient::connect(format!("http://{}", addr))
            .await
            .unwrap();

        let request = ExportMetricsServiceRequest {
            resource_metrics: vec![ResourceMetrics {
                resource: None,
                scope_metrics: vec![ScopeMetrics {
                    metrics: vec![Metric {
                        name: "test.metric".to_string(),
                        data: Some(metric::Data::Gauge(Gauge {
                            data_points: vec![],
                        })),
                        ..Default::default()
                    }],
                    ..Default::default()
                }],
                ..Default::default()
            }],
        };

        client.export(request).await.unwrap();
    });

    server
        .wait_for_metrics(1, Duration::from_secs(5))
        .await
        .expect("Should receive metric before timeout");

    server
        .with_collector(|collector| {
            assert_eq!(collector.metric_count(), 1);
            collector
                .expect_metric_with_name("test.metric")
                .assert_exists();
        })
        .await;

    send_task.await.expect("Send task should complete");
    server.shutdown().await.expect("Failed to shutdown");
}

#[tokio::test]
async fn test_wait_until_with_predicate() {
    use opentelemetry_proto::tonic::collector::logs::v1::{
        ExportLogsServiceRequest, logs_service_client::LogsServiceClient,
    };
    use opentelemetry_proto::tonic::common::v1::{AnyValue, KeyValue, any_value};
    use opentelemetry_proto::tonic::logs::v1::{LogRecord, ResourceLogs, ScopeLogs};

    let server = MockServer::builder()
        .protocol(Protocol::Grpc)
        .start()
        .await
        .expect("Failed to start server");

    let addr = server.addr();

    let send_task = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(80)).await;

        let mut client = LogsServiceClient::connect(format!("http://{}", addr))
            .await
            .unwrap();

        let request = ExportLogsServiceRequest {
            resource_logs: vec![ResourceLogs {
                resource: None,
                scope_logs: vec![ScopeLogs {
                    log_records: vec![LogRecord {
                        body: Some(AnyValue {
                            value: Some(any_value::Value::StringValue(
                                "Special message".to_string(),
                            )),
                        }),
                        attributes: vec![KeyValue {
                            key: "level".to_string(),
                            value: Some(AnyValue {
                                value: Some(any_value::Value::StringValue("critical".to_string())),
                            }),
                        }],
                        ..Default::default()
                    }],
                    ..Default::default()
                }],
                ..Default::default()
            }],
        };

        client.export(request).await.unwrap();
    });

    server
        .wait_until(
            |c| {
                c.expect_log_with_body("Special message")
                    .with_attributes([("level", "critical")])
                    .count()
                    >= 1
            },
            Duration::from_secs(5),
        )
        .await
        .expect("Should find matching log before timeout");

    server
        .with_collector(|collector| {
            collector
                .expect_log_with_body("Special message")
                .with_attributes([("level", "critical")])
                .assert_exists();
        })
        .await;

    send_task.await.expect("Send task should complete");
    server.shutdown().await.expect("Failed to shutdown");
}

#[tokio::test]
async fn test_wait_timeout_returns_error() {
    let server = MockServer::builder()
        .protocol(Protocol::Grpc)
        .start()
        .await
        .expect("Failed to start server");

    let result = server.wait_for_logs(1, Duration::from_millis(100)).await;

    assert!(result.is_err());
    match result {
        Err(MockServerError::WaitTimeout(duration)) => {
            assert_eq!(duration, Duration::from_millis(100));
        }
        _ => panic!("Expected WaitTimeout error"),
    }

    server.shutdown().await.expect("Failed to shutdown");
}

#[tokio::test]
async fn test_wait_returns_immediately_when_condition_met() {
    use opentelemetry_proto::tonic::collector::logs::v1::{
        ExportLogsServiceRequest, logs_service_client::LogsServiceClient,
    };
    use opentelemetry_proto::tonic::common::v1::{AnyValue, any_value};
    use opentelemetry_proto::tonic::logs::v1::{LogRecord, ResourceLogs, ScopeLogs};
    use std::time::Instant;

    let server = MockServer::builder()
        .protocol(Protocol::Grpc)
        .start()
        .await
        .expect("Failed to start server");

    let mut client = LogsServiceClient::connect(format!("http://{}", server.addr()))
        .await
        .unwrap();

    let request = ExportLogsServiceRequest {
        resource_logs: vec![ResourceLogs {
            resource: None,
            scope_logs: vec![ScopeLogs {
                log_records: vec![LogRecord {
                    body: Some(AnyValue {
                        value: Some(any_value::Value::StringValue("Already here".to_string())),
                    }),
                    ..Default::default()
                }],
                ..Default::default()
            }],
            ..Default::default()
        }],
    };

    client.export(request).await.unwrap();

    let start = Instant::now();
    server
        .wait_for_logs(1, Duration::from_secs(5))
        .await
        .expect("Should succeed immediately");
    let elapsed = start.elapsed();

    assert!(
        elapsed < Duration::from_millis(100),
        "wait_for_logs should return immediately when condition is already met, took {:?}",
        elapsed
    );

    server.shutdown().await.expect("Failed to shutdown");
}
