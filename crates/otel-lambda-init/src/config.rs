use crate::error::OtelError;
use mock_collector::Protocol;
use opentelemetry::KeyValue;
use opentelemetry::trace::TracerProvider;
use opentelemetry_appender_tracing::layer::OpenTelemetryTracingBridge;
use opentelemetry_otlp::{WithExportConfig, WithTonicConfig};
use opentelemetry_sdk::Resource;
use opentelemetry_sdk::logs::SdkLoggerProvider;
use opentelemetry_sdk::metrics::SdkMeterProvider;
use opentelemetry_sdk::trace::SdkTracerProvider;
use std::collections::HashMap;
use std::time::Duration;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

/// Configuration for OpenTelemetry SDK initialisation
#[derive(Debug, Clone)]
pub struct OtelConfig {
    endpoint: String,
    protocol: Protocol,
    use_tls: bool,
    resource_attributes: HashMap<String, String>,
}

/// Builder for creating an `OtelConfig`
#[derive(Debug, Default)]
pub struct OtelConfigBuilder {
    endpoint: Option<String>,
    protocol: Option<Protocol>,
    use_tls: Option<bool>,
    resource_attributes: HashMap<String, String>,
}

impl OtelConfigBuilder {
    /// Create a new builder
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the OTLP endpoint
    pub fn with_endpoint(mut self, endpoint: impl Into<String>) -> Self {
        self.endpoint = Some(endpoint.into());
        self
    }

    /// Set the protocol (gRPC, HTTP/Protobuf, or HTTP/JSON)
    pub fn with_protocol(mut self, protocol: Protocol) -> Self {
        self.protocol = Some(protocol);
        self
    }

    /// Enable or disable TLS for the connection
    pub fn with_tls(mut self, use_tls: bool) -> Self {
        self.use_tls = Some(use_tls);
        self
    }

    /// Add a resource attribute
    pub fn with_resource_attribute(
        mut self,
        key: impl Into<String>,
        value: impl Into<String>,
    ) -> Self {
        self.resource_attributes.insert(key.into(), value.into());
        self
    }

    /// Add multiple resource attributes
    pub fn with_resource_attributes<K, V>(mut self, attrs: impl IntoIterator<Item = (K, V)>) -> Self
    where
        K: Into<String>,
        V: Into<String>,
    {
        for (key, value) in attrs {
            self.resource_attributes.insert(key.into(), value.into());
        }
        self
    }

    /// Build the configuration
    pub fn build(self) -> Result<OtelConfig, OtelError> {
        let endpoint = self
            .endpoint
            .ok_or_else(|| OtelError::ResourceConfig("OTLP endpoint is required".to_string()))?;

        let protocol = self.protocol.unwrap_or(Protocol::Grpc);
        let use_tls = self.use_tls.unwrap_or(false);

        Ok(OtelConfig {
            endpoint,
            protocol,
            use_tls,
            resource_attributes: self.resource_attributes,
        })
    }
}

impl OtelConfig {
    /// Initialise the OpenTelemetry SDK with tracing integration
    ///
    /// Returns an `OtelGuard` that will shut down all providers when dropped.
    pub async fn init(self) -> Result<OtelGuard, OtelError> {
        let resource = self.build_resource()?;

        let (tracer_provider, logger_provider, meter_provider) = match self.protocol {
            Protocol::Grpc => self.init_grpc_providers(resource).await?,
            Protocol::HttpBinary => self.init_http_binary_providers(resource).await?,
            Protocol::HttpJson => self.init_http_json_providers(resource).await?,
        };

        let tracer = tracer_provider.tracer("otel-lambda-init");

        let telemetry_layer = tracing_opentelemetry::layer().with_tracer(tracer);
        let log_layer = OpenTelemetryTracingBridge::new(&logger_provider);

        let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));

        tracing_subscriber::registry()
            .with(telemetry_layer)
            .with(log_layer)
            .with(tracing_subscriber::fmt::layer().with_target(false))
            .with(env_filter)
            .try_init()
            .map_err(|e| {
                OtelError::TracingSetup(format!("Failed to initialise tracing subscriber: {}", e))
            })?;

        Ok(OtelGuard {
            tracer_provider: Some(tracer_provider),
            logger_provider: Some(logger_provider),
            meter_provider: Some(meter_provider),
        })
    }

    fn build_resource(&self) -> Result<Resource, OtelError> {
        let custom_kvs: Vec<KeyValue> = self
            .resource_attributes
            .iter()
            .map(|(k, v)| KeyValue::new(k.clone(), v.clone()))
            .collect();

        let resource = Resource::builder().with_attributes(custom_kvs).build();

        Ok(resource)
    }

    async fn init_grpc_providers(
        &self,
        resource: Resource,
    ) -> Result<(SdkTracerProvider, SdkLoggerProvider, SdkMeterProvider), OtelError> {
        let span_exporter = if self.use_tls {
            let tls_config = tonic::transport::ClientTlsConfig::new();
            let channel = tonic::transport::Channel::from_shared(self.endpoint.clone())
                .map_err(|e| OtelError::ExporterInit(e.to_string()))?
                .tls_config(tls_config)
                .map_err(|e| OtelError::ExporterInit(e.to_string()))?
                .connect_lazy();

            opentelemetry_otlp::SpanExporter::builder()
                .with_tonic()
                .with_channel(channel.clone())
                .build()
                .map_err(|e| OtelError::ExporterInit(e.to_string()))?
        } else {
            opentelemetry_otlp::SpanExporter::builder()
                .with_tonic()
                .with_endpoint(&self.endpoint)
                .build()
                .map_err(|e| OtelError::ExporterInit(e.to_string()))?
        };

        let log_exporter = if self.use_tls {
            let tls_config = tonic::transport::ClientTlsConfig::new();
            let channel = tonic::transport::Channel::from_shared(self.endpoint.clone())
                .map_err(|e| OtelError::ExporterInit(e.to_string()))?
                .tls_config(tls_config)
                .map_err(|e| OtelError::ExporterInit(e.to_string()))?
                .connect_lazy();

            opentelemetry_otlp::LogExporter::builder()
                .with_tonic()
                .with_channel(channel)
                .build()
                .map_err(|e| OtelError::ExporterInit(e.to_string()))?
        } else {
            opentelemetry_otlp::LogExporter::builder()
                .with_tonic()
                .with_endpoint(&self.endpoint)
                .build()
                .map_err(|e| OtelError::ExporterInit(e.to_string()))?
        };

        let tracer_provider = SdkTracerProvider::builder()
            .with_batch_exporter(span_exporter)
            .with_resource(resource.clone())
            .build();

        let logger_provider = SdkLoggerProvider::builder()
            .with_batch_exporter(log_exporter)
            .with_resource(resource.clone())
            .build();

        let metric_exporter = if self.use_tls {
            let tls_config = tonic::transport::ClientTlsConfig::new();
            let channel = tonic::transport::Channel::from_shared(self.endpoint.clone())
                .map_err(|e| OtelError::ExporterInit(e.to_string()))?
                .tls_config(tls_config)
                .map_err(|e| OtelError::ExporterInit(e.to_string()))?
                .connect_lazy();

            opentelemetry_otlp::MetricExporter::builder()
                .with_tonic()
                .with_channel(channel)
                .build()
                .map_err(|e| OtelError::ExporterInit(e.to_string()))?
        } else {
            opentelemetry_otlp::MetricExporter::builder()
                .with_tonic()
                .with_endpoint(&self.endpoint)
                .build()
                .map_err(|e| OtelError::ExporterInit(e.to_string()))?
        };

        let reader = opentelemetry_sdk::metrics::PeriodicReader::builder(metric_exporter)
            .with_interval(Duration::from_secs(5))
            .build();

        let meter_provider = SdkMeterProvider::builder()
            .with_reader(reader)
            .with_resource(resource)
            .build();

        Ok((tracer_provider, logger_provider, meter_provider))
    }

    async fn init_http_binary_providers(
        &self,
        resource: Resource,
    ) -> Result<(SdkTracerProvider, SdkLoggerProvider, SdkMeterProvider), OtelError> {
        let traces_endpoint = self.build_signal_endpoint("/v1/traces");
        let logs_endpoint = self.build_signal_endpoint("/v1/logs");

        let span_exporter = opentelemetry_otlp::SpanExporter::builder()
            .with_http()
            .with_endpoint(&traces_endpoint)
            .with_protocol(opentelemetry_otlp::Protocol::HttpBinary)
            .build()
            .map_err(|e| OtelError::ExporterInit(e.to_string()))?;

        let log_exporter = opentelemetry_otlp::LogExporter::builder()
            .with_http()
            .with_endpoint(&logs_endpoint)
            .with_protocol(opentelemetry_otlp::Protocol::HttpBinary)
            .build()
            .map_err(|e| OtelError::ExporterInit(e.to_string()))?;

        let tracer_provider = SdkTracerProvider::builder()
            .with_batch_exporter(span_exporter)
            .with_resource(resource.clone())
            .build();

        let logger_provider = SdkLoggerProvider::builder()
            .with_batch_exporter(log_exporter)
            .with_resource(resource.clone())
            .build();

        let metrics_endpoint = self.build_signal_endpoint("/v1/metrics");

        let metric_exporter = opentelemetry_otlp::MetricExporter::builder()
            .with_http()
            .with_endpoint(&metrics_endpoint)
            .with_protocol(opentelemetry_otlp::Protocol::HttpBinary)
            .build()
            .map_err(|e| OtelError::ExporterInit(e.to_string()))?;

        let reader = opentelemetry_sdk::metrics::PeriodicReader::builder(metric_exporter)
            .with_interval(Duration::from_secs(5))
            .build();

        let meter_provider = SdkMeterProvider::builder()
            .with_reader(reader)
            .with_resource(resource)
            .build();

        Ok((tracer_provider, logger_provider, meter_provider))
    }

    async fn init_http_json_providers(
        &self,
        resource: Resource,
    ) -> Result<(SdkTracerProvider, SdkLoggerProvider, SdkMeterProvider), OtelError> {
        let traces_endpoint = self.build_signal_endpoint("/v1/traces");
        let logs_endpoint = self.build_signal_endpoint("/v1/logs");

        let span_exporter = opentelemetry_otlp::SpanExporter::builder()
            .with_http()
            .with_endpoint(&traces_endpoint)
            .with_protocol(opentelemetry_otlp::Protocol::HttpJson)
            .build()
            .map_err(|e| OtelError::ExporterInit(e.to_string()))?;

        let log_exporter = opentelemetry_otlp::LogExporter::builder()
            .with_http()
            .with_endpoint(&logs_endpoint)
            .with_protocol(opentelemetry_otlp::Protocol::HttpJson)
            .build()
            .map_err(|e| OtelError::ExporterInit(e.to_string()))?;

        let tracer_provider = SdkTracerProvider::builder()
            .with_batch_exporter(span_exporter)
            .with_resource(resource.clone())
            .build();

        let logger_provider = SdkLoggerProvider::builder()
            .with_batch_exporter(log_exporter)
            .with_resource(resource.clone())
            .build();

        let metrics_endpoint = self.build_signal_endpoint("/v1/metrics");

        let metric_exporter = opentelemetry_otlp::MetricExporter::builder()
            .with_http()
            .with_endpoint(&metrics_endpoint)
            .with_protocol(opentelemetry_otlp::Protocol::HttpJson)
            .build()
            .map_err(|e| OtelError::ExporterInit(e.to_string()))?;

        let reader = opentelemetry_sdk::metrics::PeriodicReader::builder(metric_exporter)
            .with_interval(Duration::from_secs(5))
            .build();

        let meter_provider = SdkMeterProvider::builder()
            .with_reader(reader)
            .with_resource(resource)
            .build();

        Ok((tracer_provider, logger_provider, meter_provider))
    }

    fn build_signal_endpoint(&self, signal_path: &str) -> String {
        let base = self.endpoint.trim_end_matches('/');
        format!("{}{}", base, signal_path)
    }
}

/// Guard that ensures proper shutdown of the OpenTelemetry providers
///
/// When dropped, this will flush and shut down all providers.
pub struct OtelGuard {
    tracer_provider: Option<SdkTracerProvider>,
    logger_provider: Option<SdkLoggerProvider>,
    meter_provider: Option<SdkMeterProvider>,
}

impl OtelGuard {
    /// Explicitly shutdown the providers, flushing all pending spans, logs, and metrics
    pub fn shutdown(mut self) -> Result<(), OtelError> {
        if let Some(provider) = self.tracer_provider.take() {
            let _ = provider.force_flush();
            provider
                .shutdown()
                .map_err(|e| OtelError::ProviderShutdown(e.to_string()))?;
        }
        if let Some(provider) = self.logger_provider.take() {
            provider
                .shutdown()
                .map_err(|e| OtelError::ProviderShutdown(e.to_string()))?;
        }
        if let Some(provider) = self.meter_provider.take() {
            provider
                .shutdown()
                .map_err(|e| OtelError::ProviderShutdown(e.to_string()))?;
        }
        Ok(())
    }

    /// Get a reference to the meter provider for creating meters and instruments
    pub fn meter_provider(&self) -> Option<&SdkMeterProvider> {
        self.meter_provider.as_ref()
    }
}

impl Drop for OtelGuard {
    fn drop(&mut self) {
        if let Some(provider) = self.tracer_provider.take()
            && let Err(e) = provider.shutdown()
        {
            eprintln!("Error shutting down tracer provider: {}", e);
        }
        if let Some(provider) = self.logger_provider.take()
            && let Err(e) = provider.shutdown()
        {
            eprintln!("Error shutting down logger provider: {}", e);
        }
        if let Some(provider) = self.meter_provider.take()
            && let Err(e) = provider.shutdown()
        {
            eprintln!("Error shutting down meter provider: {}", e);
        }
    }
}
