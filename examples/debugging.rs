//! Debugging Example
//!
//! This example demonstrates how to use the `dump()` method and other
//! debugging features to troubleshoot test failures.
//!
//! Run with: `cargo run --example debugging`

use mock_collector::{MockServer, Protocol};
use opentelemetry_proto::tonic::collector::logs::v1::{
    ExportLogsServiceRequest, logs_service_client::LogsServiceClient,
};
use opentelemetry_proto::tonic::common::v1::{AnyValue, KeyValue, any_value};
use opentelemetry_proto::tonic::logs::v1::{LogRecord, ResourceLogs, ScopeLogs};
use opentelemetry_proto::tonic::resource::v1::Resource;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Starting mock collector for debugging demonstration...\n");

    let server = MockServer::builder()
        .protocol(Protocol::Grpc)
        .start()
        .await?;

    let mut client = LogsServiceClient::connect(format!("http://{}", server.addr())).await?;

    // Send logs with various attributes
    client
        .export(ExportLogsServiceRequest {
            resource_logs: vec![ResourceLogs {
                resource: Some(Resource {
                    attributes: vec![
                        KeyValue {
                            key: "service.name".to_string(),
                            value: Some(AnyValue {
                                value: Some(any_value::Value::StringValue(
                                    "payment-service".to_string(),
                                )),
                            }),
                        },
                        KeyValue {
                            key: "environment".to_string(),
                            value: Some(AnyValue {
                                value: Some(any_value::Value::StringValue("staging".to_string())),
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
                                    "Payment initiated".to_string(),
                                )),
                            }),
                            attributes: vec![
                                KeyValue {
                                    key: "payment.id".to_string(),
                                    value: Some(AnyValue {
                                        value: Some(any_value::Value::StringValue(
                                            "pay-12345".to_string(),
                                        )),
                                    }),
                                },
                                KeyValue {
                                    key: "amount".to_string(),
                                    value: Some(AnyValue {
                                        value: Some(any_value::Value::StringValue(
                                            "99.99".to_string(),
                                        )),
                                    }),
                                },
                            ],
                            ..Default::default()
                        },
                        LogRecord {
                            body: Some(AnyValue {
                                value: Some(any_value::Value::StringValue(
                                    "Payment processed".to_string(),
                                )),
                            }),
                            attributes: vec![KeyValue {
                                key: "payment.id".to_string(),
                                value: Some(AnyValue {
                                    value: Some(any_value::Value::StringValue(
                                        "pay-12345".to_string(),
                                    )),
                                }),
                            }],
                            ..Default::default()
                        },
                        LogRecord {
                            body: Some(AnyValue {
                                value: Some(any_value::Value::StringValue(
                                    "Notification sent".to_string(),
                                )),
                            }),
                            attributes: vec![KeyValue {
                                key: "channel".to_string(),
                                value: Some(AnyValue {
                                    value: Some(any_value::Value::StringValue("email".to_string())),
                                }),
                            }],
                            ..Default::default()
                        },
                    ],
                    ..Default::default()
                }],
                ..Default::default()
            }],
        })
        .await?;

    println!("=== Debugging Techniques ===\n");

    server
        .with_collector(|collector| {
            println!("--- 1. Check Total Count ---");
            println!("Total logs: {}", collector.log_count());
            println!("Total spans: {}\n", collector.span_count());

            println!("--- 2. Dump All Collected Data ---");
            println!("{}\n", collector.dump());

            println!("--- 3. Count Matching Items ---");
            let payment_logs = collector
                .has_logs()
                .with_resource_attributes([("service.name", "payment-service")])
                .count();
            println!("Logs from payment-service: {}\n", payment_logs);

            println!("--- 4. Get All Matching Items ---");
            let assertion = collector
                .has_logs()
                .with_attributes([("payment.id", "pay-12345")]);
            let logs_with_payment_id = assertion.get_all();

            println!(
                "Found {} logs with payment.id=pay-12345:",
                logs_with_payment_id.len()
            );
            for log in &logs_with_payment_id {
                if let Some(body) = &log.log_record().body
                    && let Some(any_value::Value::StringValue(s)) = &body.value
                {
                    println!("  - {}", s);
                }
            }
            println!();

            println!("--- 5. Verify Specific Assertions ---");

            // This will pass
            match std::panic::catch_unwind(|| {
                collector.has_log_with_body("Payment initiated").assert();
            }) {
                Ok(_) => println!("✓ 'Payment initiated' log found"),
                Err(_) => println!("✗ 'Payment initiated' log NOT found"),
            }

            // This will fail and show a detailed error message
            println!("\n--- 6. Demonstrating Assertion Failure ---");
            println!("Attempting to find non-existent log...\n");

            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                collector
                    .has_log_with_body("Payment failed")
                    .with_attributes([("error.code", "INSUFFICIENT_FUNDS")])
                    .assert();
            }));

            if let Err(e) = result
                && let Some(msg) = e.downcast_ref::<String>()
            {
                println!("Caught expected panic:\n{}\n", msg);
            }
        })
        .await;

    // Demonstrate clear() with mutable access
    println!("--- 7. Clear Collected Data ---");
    server
        .with_collector_mut(|collector| {
            println!("Before clear: {} logs", collector.log_count());
            collector.clear();
            println!("After clear: {} logs", collector.log_count());
            println!(
                "Note: In tests, you typically wouldn't clear data, but it's useful for reusing a collector.\n"
            );
        })
        .await;

    server.shutdown().await?;

    println!("Debugging demonstration complete!");
    println!("\nKey takeaways:");
    println!("- Use dump() to see all collected data");
    println!("- Use count() to verify expected counts before asserting");
    println!("- Use get_all() to inspect matching items");
    println!("- Assertion failures provide detailed error messages");
    println!("- Use clear() to reset collector state between test sections");

    Ok(())
}
