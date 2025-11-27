//! OpenTelemetry SDK initialisation helpers for AWS Lambda
//!
//! This library provides utilities to initialise the OpenTelemetry SDK for AWS Lambda functions,
//! with support for custom resource attributes, multiple protocols (gRPC/HTTP), and tracing integration.
//!
//! # Features
//!
//! - **Resource Detection**: Automatically detects AWS Lambda resource attributes
//! - **Custom Attributes**: Add custom resource attributes to your telemetry
//! - **Multiple Protocols**: Support for gRPC and HTTP (Protobuf/JSON) via OTLP
//! - **Tracing Integration**: Seamless integration with the `tracing` crate for logs and traces
//!
//! # Quick Start
//!
//! ```no_run
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! use otel_lambda_init::OtelConfigBuilder;
//! use mock_collector::Protocol;
//!
//! // Create configuration with custom attributes
//! let config = OtelConfigBuilder::new()
//!     .with_protocol(Protocol::Grpc)
//!     .with_endpoint("http://localhost:4317")
//!     .with_resource_attribute("service.name", "my-lambda")
//!     .with_resource_attribute("environment", "production")
//!     .build()?;
//!
//! // Initialise the OpenTelemetry SDK
//! let _guard = config.init().await?;
//!
//! // Now you can use tracing macros
//! tracing::info!("Lambda function initialised");
//! # Ok(())
//! # }
//! ```

mod config;
mod error;

pub use config::{OtelConfig, OtelConfigBuilder, OtelGuard};
pub use error::OtelError;
pub use mock_collector::Protocol;
