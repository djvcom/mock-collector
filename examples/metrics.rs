//! Metrics Example
//!
//! This example demonstrates how to use the mock OTLP collector to test metrics collection
//! and perform assertions on collected metrics data.
//!
//! Run with: `cargo run --example metrics`

use mock_collector::{MockServer, Protocol};
use opentelemetry_proto::tonic::collector::metrics::v1::{
    ExportMetricsServiceRequest, metrics_service_client::MetricsServiceClient,
};
use opentelemetry_proto::tonic::common::v1::{AnyValue, KeyValue, any_value};
use opentelemetry_proto::tonic::metrics::v1::{
    Metric, NumberDataPoint, ResourceMetrics, ScopeMetrics, Sum, metric, number_data_point::Value,
};
use opentelemetry_proto::tonic::resource::v1::Resource;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Starting mock OTLP collector with gRPC protocol...");

    let server = MockServer::builder()
        .protocol(Protocol::Grpc)
        .start()
        .await?;

    println!("Server started on {}", server.addr());

    let mut client = MetricsServiceClient::connect(format!("http://{}", server.addr())).await?;

    println!("Sending metrics via gRPC...");

    let request = ExportMetricsServiceRequest {
        resource_metrics: vec![ResourceMetrics {
            resource: Some(Resource {
                attributes: vec![
                    KeyValue {
                        key: "service.name".to_string(),
                        value: Some(AnyValue {
                            value: Some(any_value::Value::StringValue("api-gateway".to_string())),
                        }),
                    },
                    KeyValue {
                        key: "deployment.environment".to_string(),
                        value: Some(AnyValue {
                            value: Some(any_value::Value::StringValue("production".to_string())),
                        }),
                    },
                ],
                dropped_attributes_count: 0,
                ..Default::default()
            }),
            scope_metrics: vec![ScopeMetrics {
                scope: None,
                metrics: vec![
                    Metric {
                        name: "http_requests_total".to_string(),
                        description: "Total HTTP requests".to_string(),
                        unit: "1".to_string(),
                        metadata: vec![],
                        data: Some(metric::Data::Sum(Sum {
                            data_points: vec![
                                NumberDataPoint {
                                    attributes: vec![
                                        KeyValue {
                                            key: "method".to_string(),
                                            value: Some(AnyValue {
                                                value: Some(any_value::Value::StringValue(
                                                    "GET".to_string(),
                                                )),
                                            }),
                                        },
                                        KeyValue {
                                            key: "status".to_string(),
                                            value: Some(AnyValue {
                                                value: Some(any_value::Value::StringValue(
                                                    "200".to_string(),
                                                )),
                                            }),
                                        },
                                    ],
                                    value: Some(Value::AsInt(1523)),
                                    ..Default::default()
                                },
                                NumberDataPoint {
                                    attributes: vec![
                                        KeyValue {
                                            key: "method".to_string(),
                                            value: Some(AnyValue {
                                                value: Some(any_value::Value::StringValue(
                                                    "POST".to_string(),
                                                )),
                                            }),
                                        },
                                        KeyValue {
                                            key: "status".to_string(),
                                            value: Some(AnyValue {
                                                value: Some(any_value::Value::StringValue(
                                                    "201".to_string(),
                                                )),
                                            }),
                                        },
                                    ],
                                    value: Some(Value::AsInt(342)),
                                    ..Default::default()
                                },
                            ],
                            aggregation_temporality: 2, // Cumulative
                            is_monotonic: true,
                        })),
                    },
                    Metric {
                        name: "db_query_duration_ms".to_string(),
                        description: "Database query duration in milliseconds".to_string(),
                        unit: "ms".to_string(),
                        metadata: vec![],
                        data: Some(metric::Data::Sum(Sum {
                            data_points: vec![NumberDataPoint {
                                attributes: vec![KeyValue {
                                    key: "table".to_string(),
                                    value: Some(AnyValue {
                                        value: Some(any_value::Value::StringValue(
                                            "users".to_string(),
                                        )),
                                    }),
                                }],
                                value: Some(Value::AsDouble(125.5)),
                                ..Default::default()
                            }],
                            aggregation_temporality: 2,
                            is_monotonic: false,
                        })),
                    },
                    Metric {
                        name: "cache_hits_total".to_string(),
                        description: "Total cache hits".to_string(),
                        unit: "1".to_string(),
                        metadata: vec![],
                        data: Some(metric::Data::Sum(Sum {
                            data_points: vec![NumberDataPoint {
                                value: Some(Value::AsInt(892)),
                                ..Default::default()
                            }],
                            aggregation_temporality: 2,
                            is_monotonic: true,
                        })),
                    },
                ],
                ..Default::default()
            }],
            ..Default::default()
        }],
    };

    client.export(request).await?;

    println!("Metrics sent successfully!\n");

    println!("Performing assertions...");

    server
        .with_collector(|collector| {
            println!("Total metrics collected: {}", collector.metric_count());

            assert_eq!(collector.metric_count(), 3);

            collector
                .expect_metric_with_name("http_requests_total")
                .with_resource_attributes([
                    ("service.name", "api-gateway"),
                    ("deployment.environment", "production"),
                ])
                .with_attributes([("method", "GET"), ("status", "200")])
                .assert_exists();

            println!("✓ Found 'http_requests_total' metric with GET/200");

            collector
                .expect_metric_with_name("http_requests_total")
                .with_attributes([("method", "POST"), ("status", "201")])
                .assert_exists();

            println!("✓ Found 'http_requests_total' metric with POST/201");

            let http_request_metrics = collector
                .expect_metric_with_name("http_requests_total")
                .count();

            println!(
                "✓ Found {} metric(s) named http_requests_total",
                http_request_metrics
            );
            assert_eq!(http_request_metrics, 1); // One metric (with multiple data points)

            collector
                .expect_metric_with_name("db_query_duration_ms")
                .with_attributes([("table", "users")])
                .assert_exists();

            println!("✓ Found 'db_query_duration_ms' metric for users table");

            collector
                .expect_metric_with_name("cache_hits_total")
                .assert_exists();

            println!("✓ Found 'cache_hits_total' metric");

            collector
                .expect_metric()
                .with_resource_attributes([("service.name", "api-gateway")])
                .assert_at_least(1);

            println!("✓ At least one metric from api-gateway service");

            collector
                .expect_metric_with_name("deprecated_metric")
                .assert_not_exists();

            println!("✓ Verified 'deprecated_metric' doesn't exist");

            collector
                .expect_metric()
                .with_resource_attributes([("deployment.environment", "production")])
                .assert_at_least(3);

            println!("✓ At least 3 metrics from production environment");
        })
        .await;

    println!("\nAll assertions passed!");

    server.shutdown().await?;
    println!("Server shut down successfully");

    Ok(())
}
