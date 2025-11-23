use mock_collector::{MockServer, Protocol};
use std::fs;

#[tokio::test]
async fn test_http_json_logs_with_official_example() {
    // Start HTTP JSON server
    let server = MockServer::builder()
        .protocol(Protocol::HttpJson)
        .start()
        .await
        .expect("Failed to start server");

    // Load official OTLP example
    let example_json = fs::read_to_string("opentelemetry-proto-examples/examples/logs.json")
        .expect("Failed to read logs.json example");

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
            collector.has_log_with_body("Example log record").assert();

            // Verify resource attributes
            collector
                .has_log_with_body("Example log record")
                .with_resource_attributes([("service.name", "my.service")])
                .assert();

            // Verify scope attributes
            collector
                .has_log_with_body("Example log record")
                .with_scope_attributes([("my.scope.attribute", "some scope attribute")])
                .assert();

            // Verify log-level string attributes
            collector
                .has_log_with_body("Example log record")
                .with_attributes([("string.attribute", "some string")])
                .assert();
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
    let example_json = fs::read_to_string("opentelemetry-proto-examples/examples/trace.json")
        .expect("Failed to read trace.json example");

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
            collector.has_span_with_name("I'm a server span").assert();

            // Verify resource attributes
            collector
                .has_span_with_name("I'm a server span")
                .with_resource_attributes([("service.name", "my.service")])
                .assert();

            // Verify scope attributes
            collector
                .has_span_with_name("I'm a server span")
                .with_scope_attributes([("my.scope.attribute", "some scope attribute")])
                .assert();

            // Verify span attributes
            collector
                .has_span_with_name("I'm a server span")
                .with_attributes([("my.span.attr", "some value")])
                .assert();
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
    let example_json = fs::read_to_string("opentelemetry-proto-examples/examples/logs.json")
        .expect("Failed to read logs.json example");

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
                .has_log_with_body("Example log record")
                .with_resource_attributes([("service.name", "my.service")])
                .with_scope_attributes([("my.scope.attribute", "some scope attribute")])
                .with_attributes([("string.attribute", "some string")])
                .assert();
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
    let example_json = fs::read_to_string("opentelemetry-proto-examples/examples/trace.json")
        .expect("Failed to read trace.json example");

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
                .has_span_with_name("I'm a server span")
                .with_resource_attributes([("service.name", "my.service")])
                .with_scope_attributes([("my.scope.attribute", "some scope attribute")])
                .with_attributes([("my.span.attr", "some value")])
                .assert();
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
    let logs_json = fs::read_to_string("opentelemetry-proto-examples/examples/logs.json")
        .expect("Failed to read logs.json");
    let trace_json = fs::read_to_string("opentelemetry-proto-examples/examples/trace.json")
        .expect("Failed to read trace.json");

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
                .has_log_with_body("Example log record")
                .with_resource_attributes([("service.name", "my.service")])
                .assert();

            // Verify span
            collector
                .has_span_with_name("I'm a server span")
                .with_resource_attributes([("service.name", "my.service")])
                .assert();
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
                .has_span_with_name("OrderProcessing")
                .with_event("payment.initiated")
                .assert();

            // Assert span has multiple events
            collector
                .has_span_with_name("OrderProcessing")
                .with_event("payment.initiated")
                .with_event("payment.completed")
                .with_event("notification.sent")
                .assert();

            // Assert event with attributes
            collector
                .has_span_with_name("OrderProcessing")
                .with_event_attributes("payment.initiated", [("amount", "100.00")])
                .assert();

            // Assert event with different attributes
            collector
                .has_span_with_name("OrderProcessing")
                .with_event_attributes("payment.completed", [("transaction.id", "txn-12345")])
                .assert();

            // Assert negative case - event doesn't exist
            collector
                .has_span_with_name("OrderProcessing")
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
    let example_json = fs::read_to_string("opentelemetry-proto-examples/examples/metrics.json")
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
            collector.has_metric_with_name("my.counter").assert();

            // Verify resource attributes
            collector
                .has_metric_with_name("my.counter")
                .with_resource_attributes([("service.name", "my.service")])
                .assert();

            // Verify scope attributes
            collector
                .has_metric_with_name("my.counter")
                .with_scope_attributes([("my.scope.attribute", "some scope attribute")])
                .assert();

            // Verify metric data point attributes
            collector
                .has_metric_with_name("my.counter")
                .with_attributes([("my.counter.attr", "some value")])
                .assert();

            // Verify gauge metric
            collector
                .has_metric_with_name("my.gauge")
                .with_attributes([("my.gauge.attr", "some value")])
                .assert();

            // Verify histogram metric
            collector
                .has_metric_with_name("my.histogram")
                .with_attributes([("my.histogram.attr", "some value")])
                .assert();

            // Verify exponential histogram metric exists (note: HTTP JSON/Protobuf has
            // a known limitation in opentelemetry-proto 0.31.0 where exponentialHistogram
            // data is not properly deserialized, so we only check name here)
            collector
                .has_metric_with_name("my.exponential.histogram")
                .assert();

            // Test count assertions
            collector.has_metric_with_name("my.counter").assert_count(1);

            // Test has_metrics() without name filter
            collector
                .has_metrics()
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
    let example_json = fs::read_to_string("opentelemetry-proto-examples/examples/metrics.json")
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
                .has_metric_with_name("my.counter")
                .with_resource_attributes([("service.name", "my.service")])
                .with_scope_attributes([("my.scope.attribute", "some scope attribute")])
                .with_attributes([("my.counter.attr", "some value")])
                .assert();

            collector
                .has_metric_with_name("my.gauge")
                .with_attributes([("my.gauge.attr", "some value")])
                .assert();

            collector
                .has_metric_with_name("my.histogram")
                .with_attributes([("my.histogram.attr", "some value")])
                .assert();

            // Exponential histogram (same limitation as JSON test)
            collector
                .has_metric_with_name("my.exponential.histogram")
                .assert();
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
    let logs_json = fs::read_to_string("opentelemetry-proto-examples/examples/logs.json")
        .expect("Failed to read logs.json");
    let trace_json = fs::read_to_string("opentelemetry-proto-examples/examples/trace.json")
        .expect("Failed to read trace.json");
    let metrics_json = fs::read_to_string("opentelemetry-proto-examples/examples/metrics.json")
        .expect("Failed to read metrics.json");

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
                .has_log_with_body("Example log record")
                .with_resource_attributes([("service.name", "my.service")])
                .assert();

            // Verify span
            collector
                .has_span_with_name("I'm a server span")
                .with_resource_attributes([("service.name", "my.service")])
                .assert();

            // Verify metrics
            collector
                .has_metric_with_name("my.counter")
                .with_resource_attributes([("service.name", "my.service")])
                .assert();

            collector
                .has_metric_with_name("my.gauge")
                .with_resource_attributes([("service.name", "my.service")])
                .assert();
        })
        .await;

    server.shutdown().await.expect("Failed to shutdown");
}
