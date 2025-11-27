use thiserror::Error;

/// Errors that can occur during OpenTelemetry initialisation
#[derive(Debug, Error)]
pub enum OtelError {
    /// Error initialising the OTLP exporter
    #[error("Failed to initialise OTLP exporter: {0}")]
    ExporterInit(String),

    /// Error setting up the tracing subscriber
    #[error("Failed to set up tracing subscriber: {0}")]
    TracingSetup(String),

    /// Error with resource configuration
    #[error("Resource configuration error: {0}")]
    ResourceConfig(String),

    /// Error shutting down providers
    #[error("Failed to shut down provider: {0}")]
    ProviderShutdown(String),

    /// Generic OpenTelemetry error
    #[error("OpenTelemetry error: {0}")]
    OpenTelemetry(#[from] opentelemetry_sdk::trace::TraceError),
}
