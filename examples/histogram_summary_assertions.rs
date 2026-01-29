//! Histogram and Summary Assertions Example
//!
//! This example demonstrates type-specific assertion methods for histogram,
//! exponential histogram, and summary metrics.
//!
//! Run with: `cargo run --example histogram_summary_assertions`

use mock_collector::{MockServer, Protocol};
use opentelemetry_proto::tonic::collector::metrics::v1::{
    ExportMetricsServiceRequest, metrics_service_client::MetricsServiceClient,
};
use opentelemetry_proto::tonic::common::v1::{AnyValue, KeyValue, any_value};
use opentelemetry_proto::tonic::metrics::v1::{
    ExponentialHistogram, ExponentialHistogramDataPoint, Histogram, HistogramDataPoint, Metric,
    ResourceMetrics, ScopeMetrics, Summary, SummaryDataPoint,
    exponential_histogram_data_point::Buckets, summary_data_point::ValueAtQuantile,
};
use opentelemetry_proto::tonic::resource::v1::Resource;

fn make_string_kv(key: &str, value: &str) -> KeyValue {
    KeyValue {
        key: key.to_string(),
        value: Some(AnyValue {
            value: Some(any_value::Value::StringValue(value.to_string())),
        }),
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Starting mock OTLP collector for histogram/summary assertions...\n");

    let server = MockServer::builder()
        .protocol(Protocol::Grpc)
        .start()
        .await?;

    println!("Server started on {}", server.addr());

    let mut client = MetricsServiceClient::connect(format!("http://{}", server.addr())).await?;

    println!("Sending histogram, exponential histogram, and summary metrics...\n");

    let request = ExportMetricsServiceRequest {
        resource_metrics: vec![ResourceMetrics {
            resource: Some(Resource {
                attributes: vec![make_string_kv("service.name", "web-api")],
                dropped_attributes_count: 0,
                ..Default::default()
            }),
            scope_metrics: vec![ScopeMetrics {
                scope: None,
                metrics: vec![
                    // Histogram metric
                    Metric {
                        name: "http_request_duration".to_string(),
                        description: "HTTP request duration in milliseconds".to_string(),
                        unit: "ms".to_string(),
                        metadata: vec![],
                        data: Some(
                            opentelemetry_proto::tonic::metrics::v1::metric::Data::Histogram(
                                Histogram {
                                    data_points: vec![HistogramDataPoint {
                                        attributes: vec![make_string_kv("method", "GET")],
                                        count: 150,
                                        sum: Some(7500.0),
                                        min: Some(10.0),
                                        max: Some(250.0),
                                        bucket_counts: vec![10, 40, 60, 30, 10],
                                        explicit_bounds: vec![25.0, 50.0, 100.0, 200.0],
                                        ..Default::default()
                                    }],
                                    aggregation_temporality: 2,
                                },
                            ),
                        ),
                    },
                    // Exponential histogram metric
                    Metric {
                        name: "latency".to_string(),
                        description: "Request latency".to_string(),
                        unit: "ms".to_string(),
                        metadata: vec![],
                        data: Some(
                            opentelemetry_proto::tonic::metrics::v1::metric::Data::ExponentialHistogram(
                                ExponentialHistogram {
                                    data_points: vec![ExponentialHistogramDataPoint {
                                        attributes: vec![make_string_kv("endpoint", "/api/users")],
                                        count: 200,
                                        sum: Some(10000.0),
                                        min: Some(5.0),
                                        max: Some(300.0),
                                        zero_count: 2,
                                        scale: 3,
                                        positive: Some(Buckets {
                                            offset: 0,
                                            bucket_counts: vec![50, 100, 50],
                                        }),
                                        negative: None,
                                        ..Default::default()
                                    }],
                                    aggregation_temporality: 2,
                                },
                            ),
                        ),
                    },
                    // Summary metric
                    Metric {
                        name: "response_time".to_string(),
                        description: "Response time summary".to_string(),
                        unit: "ms".to_string(),
                        metadata: vec![],
                        data: Some(
                            opentelemetry_proto::tonic::metrics::v1::metric::Data::Summary(
                                Summary {
                                    data_points: vec![SummaryDataPoint {
                                        attributes: vec![make_string_kv("handler", "index")],
                                        count: 1000,
                                        sum: 50000.0,
                                        quantile_values: vec![
                                            ValueAtQuantile {
                                                quantile: 0.5,
                                                value: 45.0,
                                            },
                                            ValueAtQuantile {
                                                quantile: 0.95,
                                                value: 120.0,
                                            },
                                            ValueAtQuantile {
                                                quantile: 0.99,
                                                value: 180.0,
                                            },
                                        ],
                                        ..Default::default()
                                    }],
                                },
                            ),
                        ),
                    },
                ],
                ..Default::default()
            }],
            ..Default::default()
        }],
    };

    client.export(request).await?;
    println!("Metrics sent successfully!\n");

    println!("=== Histogram Assertions ===\n");

    server
        .with_collector(|collector| {
            // Basic histogram existence check
            collector
                .expect_histogram("http_request_duration")
                .assert_exists();
            println!("Found 'http_request_duration' histogram");

            // Histogram with attribute matching
            collector
                .expect_histogram("http_request_duration")
                .with_attributes([("method", "GET")])
                .assert_exists();
            println!("Found histogram with method=GET attribute");

            // Count assertions
            collector
                .expect_histogram("http_request_duration")
                .with_count_eq(150)
                .assert_exists();
            println!("Histogram has exactly 150 observations");

            collector
                .expect_histogram("http_request_duration")
                .with_count_gte(100)
                .assert_exists();
            println!("Histogram has at least 100 observations");

            // Sum assertions
            collector
                .expect_histogram("http_request_duration")
                .with_sum_eq(7500.0)
                .assert_exists();
            println!("Histogram sum is 7500.0");

            collector
                .expect_histogram("http_request_duration")
                .with_sum_gte(5000.0)
                .assert_exists();
            println!("Histogram sum is at least 5000.0");

            // Min/max assertions
            collector
                .expect_histogram("http_request_duration")
                .with_min_lte(20.0)
                .with_max_gte(200.0)
                .assert_exists();
            println!("Histogram min <= 20.0 and max >= 200.0");

            // Bucket count assertions
            collector
                .expect_histogram("http_request_duration")
                .with_bucket_count_gte(2, 50)
                .assert_exists();
            println!("Bucket at index 2 has at least 50 observations");

            // Combined assertions
            collector
                .expect_histogram("http_request_duration")
                .with_attributes([("method", "GET")])
                .with_count_gte(100)
                .with_sum_gte(1000.0)
                .with_min_lte(50.0)
                .assert_exists();
            println!("Combined histogram assertions passed");

            println!("\n=== Exponential Histogram Assertions ===\n");

            // Basic exponential histogram check
            collector
                .expect_exponential_histogram("latency")
                .assert_exists();
            println!("Found 'latency' exponential histogram");

            // With attribute matching
            collector
                .expect_exponential_histogram("latency")
                .with_attributes([("endpoint", "/api/users")])
                .assert_exists();
            println!("Found exponential histogram with endpoint attribute");

            // Count and sum assertions (same as regular histogram)
            collector
                .expect_exponential_histogram("latency")
                .with_count_gte(100)
                .with_sum_gte(5000.0)
                .assert_exists();
            println!("Exponential histogram count >= 100 and sum >= 5000.0");

            // Zero count assertion
            collector
                .expect_exponential_histogram("latency")
                .with_zero_count_lte(5)
                .assert_exists();
            println!("Exponential histogram has at most 5 zero values");

            // Scale assertion
            collector
                .expect_exponential_histogram("latency")
                .with_scale_eq(3)
                .assert_exists();
            println!("Exponential histogram has scale = 3");

            // Min/max assertions
            collector
                .expect_exponential_histogram("latency")
                .with_min_lte(10.0)
                .with_max_gte(250.0)
                .assert_exists();
            println!("Exponential histogram min <= 10.0 and max >= 250.0");

            println!("\n=== Summary Assertions ===\n");

            // Basic summary check
            collector.expect_summary("response_time").assert_exists();
            println!("Found 'response_time' summary");

            // With attribute matching
            collector
                .expect_summary("response_time")
                .with_attributes([("handler", "index")])
                .assert_exists();
            println!("Found summary with handler=index attribute");

            // Count and sum assertions
            collector
                .expect_summary("response_time")
                .with_count_eq(1000)
                .with_sum_eq(50000.0)
                .assert_exists();
            println!("Summary has count=1000 and sum=50000.0");

            // Quantile assertions
            collector
                .expect_summary("response_time")
                .with_quantile_lte(0.5, 50.0)
                .assert_exists();
            println!("Median (p50) is at most 50.0ms");

            collector
                .expect_summary("response_time")
                .with_quantile_lte(0.95, 150.0)
                .assert_exists();
            println!("p95 is at most 150.0ms");

            collector
                .expect_summary("response_time")
                .with_quantile_lte(0.99, 200.0)
                .assert_exists();
            println!("p99 is at most 200.0ms");

            // Combined quantile assertions
            collector
                .expect_summary("response_time")
                .with_count_gte(500)
                .with_quantile_lte(0.5, 100.0)
                .with_quantile_lte(0.99, 250.0)
                .assert_exists();
            println!("Combined summary assertions passed");

            println!("\n=== Negative Assertions ===\n");

            // Verify non-existent histograms don't match
            collector
                .expect_histogram("nonexistent_histogram")
                .assert_not_exists();
            println!("Verified 'nonexistent_histogram' doesn't exist");

            // Verify histogram with wrong count doesn't match
            collector
                .expect_histogram("http_request_duration")
                .with_count_gt(1000)
                .assert_not_exists();
            println!("Verified histogram with count > 1000 doesn't exist");

            // Debug output
            println!("\n=== Debug Output ===\n");
            println!("{}", collector.dump());
        })
        .await;

    println!("All assertions passed!");

    server.shutdown().await?;
    println!("Server shut down successfully");

    Ok(())
}
