use axum::{Router, extract::State, http::StatusCode, response::IntoResponse, routing::post};
use opentelemetry_otlp::Protocol;
use opentelemetry_proto::tonic::collector::logs::v1::{
    ExportLogsServiceRequest, ExportLogsServiceResponse,
    logs_service_server::{LogsService, LogsServiceServer},
};
use opentelemetry_proto::tonic::collector::metrics::v1::{
    ExportMetricsServiceRequest, ExportMetricsServiceResponse,
    metrics_service_server::{MetricsService, MetricsServiceServer},
};
use opentelemetry_proto::tonic::collector::trace::v1::{
    ExportTraceServiceRequest, ExportTraceServiceResponse,
    trace_service_server::{TraceService, TraceServiceServer},
};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::TcpListener;
use tokio::sync::RwLock;
use tonic::{Request, Response, Status, codec::CompressionEncoding};
use tower_http::decompression::RequestDecompressionLayer;

use crate::collector::MockCollector;
use crate::error::MockServerError;

/// A builder for configuring a mock OTLP server.
///
/// # Example
///
/// ```no_run
/// use mock_collector::{MockServer, Protocol};
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let server = MockServer::builder()
///     .protocol(Protocol::HttpJson)
///     .port(4318)
///     .start()
///     .await?;
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Default)]
pub struct MockServerBuilder {
    collector: Option<Arc<RwLock<MockCollector>>>,
    protocol: Option<Protocol>,
    host: Option<IpAddr>,
    port: Option<u16>,
}

impl MockServerBuilder {
    /// Creates a new builder with default settings.
    ///
    /// Defaults:
    /// - Protocol: gRPC
    /// - Host: localhost (127.0.0.1)
    /// - Port: 0 (OS-assigned)
    /// - Collector: new empty collector
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the collector to use.
    ///
    /// By default, a new collector is created. Use this to share a collector
    /// between multiple servers.
    #[must_use]
    pub fn collector(mut self, collector: Arc<RwLock<MockCollector>>) -> Self {
        self.collector = Some(collector);
        self
    }

    /// Sets the protocol (gRPC, HTTP/JSON, or HTTP/Protobuf).
    ///
    /// Default: gRPC
    #[must_use]
    pub fn protocol(mut self, protocol: Protocol) -> Self {
        self.protocol = Some(protocol);
        self
    }

    /// Sets the host to bind to.
    ///
    /// Default: localhost (127.0.0.1)
    #[must_use]
    pub fn host(mut self, host: IpAddr) -> Self {
        self.host = Some(host);
        self
    }

    /// Sets the port to bind to.
    ///
    /// Use 0 for an OS-assigned port. Retrieve the actual port using
    /// `ServerHandle::addr()` after starting.
    ///
    /// Default: 0 (OS-assigned)
    #[must_use]
    pub fn port(mut self, port: u16) -> Self {
        self.port = Some(port);
        self
    }

    /// Builds the `MockServer` without starting it.
    ///
    /// Call `.start()` on the returned `MockServer` to actually start the server,
    /// or use `builder.start()` to build and start in one step.
    pub fn build(self) -> MockServer {
        MockServer {
            collector: self
                .collector
                .unwrap_or_else(|| Arc::new(RwLock::new(MockCollector::new()))),
            protocol: self.protocol.unwrap_or(Protocol::Grpc),
            host: self.host.unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            port: self.port.unwrap_or(0),
        }
    }

    /// Builds and starts the server in one step.
    ///
    /// # Errors
    ///
    /// Returns an error if the server fails to bind to the specified address.
    pub async fn start(self) -> Result<ServerHandle, MockServerError> {
        self.build().start().await
    }
}

/// A mock OTLP server for testing.
pub struct MockServer {
    collector: Arc<RwLock<MockCollector>>,
    protocol: Protocol,
    host: IpAddr,
    port: u16,
}

impl MockServer {
    /// Creates a new mock server with the specified protocol and port.
    ///
    /// Binds to localhost (127.0.0.1) by default. Use `builder()` for more control.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use mock_collector::{MockServer, Protocol};
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let server = MockServer::new(Protocol::Grpc, 4317).start().await?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn new(protocol: Protocol, port: u16) -> Self {
        Self {
            collector: Arc::new(RwLock::new(MockCollector::new())),
            protocol,
            host: IpAddr::V4(Ipv4Addr::LOCALHOST),
            port,
        }
    }

    /// Creates a new mock server with an existing collector.
    ///
    /// This allows sharing a collector between multiple servers or
    /// inspecting logs without starting a server.
    pub fn with_collector(
        protocol: Protocol,
        port: u16,
        collector: Arc<RwLock<MockCollector>>,
    ) -> Self {
        Self {
            collector,
            protocol,
            host: IpAddr::V4(Ipv4Addr::LOCALHOST),
            port,
        }
    }

    /// Returns a builder for configuring the server.
    ///
    /// Use this for simplified initialization with defaults (gRPC on OS-assigned port):
    ///
    /// ```no_run
    /// use mock_collector::MockServer;
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// // Start with defaults
    /// let server = MockServer::builder().start().await?;
    /// println!("Server running on {}", server.addr());
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// Or configure specific options:
    ///
    /// ```no_run
    /// use mock_collector::{MockServer, Protocol};
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let server = MockServer::builder()
    ///     .protocol(Protocol::HttpJson)
    ///     .port(4318)
    ///     .start()
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn builder() -> MockServerBuilder {
        MockServerBuilder::new()
    }

    /// Starts the server and returns a handle for interacting with it.
    ///
    /// # Errors
    ///
    /// Returns an error if the server fails to bind to the specified address.
    pub async fn start(self) -> Result<ServerHandle, MockServerError> {
        match self.protocol {
            Protocol::Grpc => self.start_grpc().await,
            Protocol::HttpBinary => self.start_http_binary().await,
            Protocol::HttpJson => self.start_http_json().await,
        }
    }

    async fn start_grpc(self) -> Result<ServerHandle, MockServerError> {
        let collector = self.collector.clone();
        let logs_service = GrpcLogsService {
            collector: collector.clone(),
        };
        let trace_service = GrpcTraceService {
            collector: collector.clone(),
        };
        let metrics_service = GrpcMetricsService { collector };

        let addr = SocketAddr::new(self.host, self.port);
        let listener = TcpListener::bind(addr)
            .await
            .map_err(|source| MockServerError::BindError { addr, source })?;
        let bound_addr = listener
            .local_addr()
            .map_err(|source| MockServerError::BindError { addr, source })?;

        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();

        let server_task = tokio::spawn(async move {
            tonic::transport::Server::builder()
                .add_service(
                    LogsServiceServer::new(logs_service)
                        .accept_compressed(CompressionEncoding::Gzip)
                        .accept_compressed(CompressionEncoding::Zstd),
                )
                .add_service(
                    TraceServiceServer::new(trace_service)
                        .accept_compressed(CompressionEncoding::Gzip)
                        .accept_compressed(CompressionEncoding::Zstd),
                )
                .add_service(
                    MetricsServiceServer::new(metrics_service)
                        .accept_compressed(CompressionEncoding::Gzip)
                        .accept_compressed(CompressionEncoding::Zstd),
                )
                .serve_with_incoming_shutdown(
                    tokio_stream::wrappers::TcpListenerStream::new(listener),
                    async {
                        shutdown_rx.await.ok();
                    },
                )
                .await
                .map_err(|e| MockServerError::ServerError(e.to_string()))
        });

        Ok(ServerHandle {
            collector: self.collector,
            addr: bound_addr,
            shutdown_tx: Some(shutdown_tx),
            task: Some(server_task),
        })
    }

    async fn start_http_binary(self) -> Result<ServerHandle, MockServerError> {
        self.start_http(HttpProtocol::Binary).await
    }

    async fn start_http_json(self) -> Result<ServerHandle, MockServerError> {
        self.start_http(HttpProtocol::Json).await
    }

    async fn start_http(self, protocol: HttpProtocol) -> Result<ServerHandle, MockServerError> {
        let collector = self.collector.clone();

        let app = Router::new()
            .route("/v1/logs", post(handle_http_logs))
            .route("/v1/traces", post(handle_http_traces))
            .route("/v1/metrics", post(handle_http_metrics))
            .layer(RequestDecompressionLayer::new())
            .with_state(HttpServerState {
                collector: collector.clone(),
                protocol,
            });

        let addr = SocketAddr::new(self.host, self.port);
        let listener = TcpListener::bind(addr)
            .await
            .map_err(|source| MockServerError::BindError { addr, source })?;
        let bound_addr = listener
            .local_addr()
            .map_err(|source| MockServerError::BindError { addr, source })?;

        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();

        let server_task = tokio::spawn(async move {
            axum::serve(listener, app)
                .with_graceful_shutdown(async {
                    shutdown_rx.await.ok();
                })
                .await
                .map_err(|e| MockServerError::ServerError(e.to_string()))
        });

        Ok(ServerHandle {
            collector,
            addr: bound_addr,
            shutdown_tx: Some(shutdown_tx),
            task: Some(server_task),
        })
    }
}

/// A handle to a running mock server.
///
/// This struct provides access to the underlying [`MockCollector`] and control
/// over the server's lifecycle. It is returned by [`MockServer::start`] and
/// [`MockServerBuilder::start`].
///
/// # Key Methods
///
/// - [`with_collector()`](Self::with_collector) - Run assertions with read access to the collector
/// - [`with_collector_mut()`](Self::with_collector_mut) - Modify the collector (e.g., call `clear()`)
/// - [`addr()`](Self::addr) - Get the server's bound address
/// - [`shutdown()`](Self::shutdown) - Gracefully shut down the server
///
/// # Lifecycle
///
/// The server runs in the background while this handle exists. When the handle
/// is dropped, the server is automatically shut down. For explicit shutdown control,
/// use the [`shutdown()`](Self::shutdown) method.
///
/// # Examples
///
/// ## Basic Usage
///
/// ```no_run
/// use mock_collector::{MockServer, Protocol};
///
/// # #[tokio::main]
/// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let server = MockServer::builder().start().await?;
///
/// // Get the bound address (useful when using port 0)
/// println!("Server listening on: {}", server.addr());
///
/// // Your application exports telemetry here...
///
/// // Run assertions with read access
/// server.with_collector(|collector| {
///     assert_eq!(collector.log_count(), 5);
/// }).await;
///
/// // Graceful shutdown
/// server.shutdown().await?;
/// # Ok(())
/// # }
/// ```
///
/// ## Clearing the Collector
///
/// ```no_run
/// use mock_collector::{MockServer, Protocol};
///
/// # #[tokio::main]
/// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let server = MockServer::builder().start().await?;
///
/// // Export some logs...
///
/// // Assert on first batch
/// server.with_collector(|collector| {
///     assert_eq!(collector.log_count(), 3);
/// }).await;
///
/// // Clear and test a second batch
/// server.with_collector_mut(|collector| {
///     collector.clear();
/// }).await;
///
/// // Export more logs...
///
/// server.with_collector(|collector| {
///     assert_eq!(collector.log_count(), 2); // Only new logs
/// }).await;
/// # server.shutdown().await?;
/// # Ok(())
/// # }
/// ```
///
/// ## Direct Arc Access
///
/// For advanced use cases, you can get direct access to the collector's Arc:
///
/// ```no_run
/// use std::sync::Arc;
/// use tokio::sync::RwLock;
/// use mock_collector::{MockCollector, MockServer};
///
/// # #[tokio::main]
/// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let server = MockServer::builder().start().await?;
/// let collector_arc: Arc<RwLock<MockCollector>> = server.collector();
///
/// // Use the Arc directly (e.g., share between tasks)
/// let count = collector_arc.read().await.log_count();
/// # server.shutdown().await?;
/// # Ok(())
/// # }
/// ```
pub struct ServerHandle {
    collector: Arc<RwLock<MockCollector>>,
    addr: SocketAddr,
    shutdown_tx: Option<tokio::sync::oneshot::Sender<()>>,
    task: Option<tokio::task::JoinHandle<Result<(), MockServerError>>>,
}

impl std::fmt::Debug for ServerHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServerHandle")
            .field("addr", &self.addr)
            .field("collector", &"<RwLock<MockCollector>>")
            .finish()
    }
}

impl ServerHandle {
    /// Returns a clone of the collector's Arc for direct access.
    ///
    /// For convenience, prefer using `with_collector()` or `with_collector_mut()`
    /// which handle the locking for you.
    pub fn collector(&self) -> Arc<RwLock<MockCollector>> {
        self.collector.clone()
    }

    /// Runs a closure with read access to the collector.
    pub async fn with_collector<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&MockCollector) -> R,
    {
        let collector = self.collector.read().await;
        f(&collector)
    }

    /// Runs a closure with write access to the collector.
    pub async fn with_collector_mut<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&mut MockCollector) -> R,
    {
        let mut collector = self.collector.write().await;
        f(&mut collector)
    }

    /// Returns the actual bound address of the server.
    ///
    /// This is useful when using port 0 for OS-assigned ports.
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// Waits until a predicate returns `true` or the timeout expires.
    ///
    /// This method polls the collector at 50ms intervals, running the predicate
    /// against the current state. It returns `Ok(())` as soon as the predicate
    /// returns `true`, or `Err(MockServerError::WaitTimeout)` if the timeout
    /// is exceeded.
    ///
    /// # Arguments
    ///
    /// * `predicate` - A function that receives a reference to the collector and
    ///   returns `true` when the desired condition is met.
    /// * `timeout` - Maximum duration to wait before returning an error.
    ///
    /// # Errors
    ///
    /// Returns [`MockServerError::WaitTimeout`] if the timeout expires before
    /// the predicate returns `true`.
    ///
    /// # Examples
    ///
    /// Wait for a specific span to arrive:
    ///
    /// ```no_run
    /// use std::time::Duration;
    /// use mock_collector::MockServer;
    ///
    /// # #[tokio::main]
    /// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let server = MockServer::builder().start().await?;
    ///
    /// // ... trigger telemetry export ...
    ///
    /// server.wait_until(
    ///     |c| c.expect_span_with_name("http.request").count() >= 1,
    ///     Duration::from_secs(5),
    /// ).await?;
    ///
    /// // Now safe to run assertions
    /// server.with_collector(|c| {
    ///     c.expect_span_with_name("http.request")
    ///         .with_attributes([("http.method", "GET")])
    ///         .assert_exists();
    /// }).await;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// Wait for logs with specific attributes:
    ///
    /// ```no_run
    /// use std::time::Duration;
    /// use mock_collector::MockServer;
    ///
    /// # #[tokio::main]
    /// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let server = MockServer::builder().start().await?;
    ///
    /// server.wait_until(
    ///     |c| c.expect_log_with_body("Request processed")
    ///         .with_attributes([("status", "success")])
    ///         .count() >= 1,
    ///     Duration::from_secs(5),
    /// ).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn wait_until<F>(
        &self,
        predicate: F,
        timeout: Duration,
    ) -> Result<(), MockServerError>
    where
        F: Fn(&MockCollector) -> bool,
    {
        let poll_interval = Duration::from_millis(50);
        let deadline = Instant::now() + timeout;

        loop {
            {
                let collector = self.collector.read().await;
                if predicate(&collector) {
                    return Ok(());
                }
            }

            if Instant::now() >= deadline {
                return Err(MockServerError::WaitTimeout(timeout));
            }

            tokio::time::sleep(poll_interval).await;
        }
    }

    /// Waits until at least `count` spans have been collected.
    ///
    /// This is a convenience method equivalent to:
    ///
    /// ```ignore
    /// server.wait_until(|c| c.span_count() >= count, timeout).await
    /// ```
    ///
    /// # Arguments
    ///
    /// * `count` - Minimum number of spans to wait for.
    /// * `timeout` - Maximum duration to wait before returning an error.
    ///
    /// # Errors
    ///
    /// Returns [`MockServerError::WaitTimeout`] if the timeout expires before
    /// the required number of spans arrive.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use std::time::Duration;
    /// use mock_collector::MockServer;
    ///
    /// # #[tokio::main]
    /// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let server = MockServer::builder().start().await?;
    ///
    /// // ... trigger span generation ...
    ///
    /// server.wait_for_spans(3, Duration::from_secs(5)).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn wait_for_spans(
        &self,
        count: usize,
        timeout: Duration,
    ) -> Result<(), MockServerError> {
        self.wait_until(|c| c.span_count() >= count, timeout).await
    }

    /// Waits until at least `count` logs have been collected.
    ///
    /// This is a convenience method equivalent to:
    ///
    /// ```ignore
    /// server.wait_until(|c| c.log_count() >= count, timeout).await
    /// ```
    ///
    /// # Arguments
    ///
    /// * `count` - Minimum number of logs to wait for.
    /// * `timeout` - Maximum duration to wait before returning an error.
    ///
    /// # Errors
    ///
    /// Returns [`MockServerError::WaitTimeout`] if the timeout expires before
    /// the required number of logs arrive.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use std::time::Duration;
    /// use mock_collector::MockServer;
    ///
    /// # #[tokio::main]
    /// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let server = MockServer::builder().start().await?;
    ///
    /// // ... trigger log generation ...
    ///
    /// server.wait_for_logs(5, Duration::from_secs(5)).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn wait_for_logs(
        &self,
        count: usize,
        timeout: Duration,
    ) -> Result<(), MockServerError> {
        self.wait_until(|c| c.log_count() >= count, timeout).await
    }

    /// Waits until at least `count` metrics have been collected.
    ///
    /// This is a convenience method equivalent to:
    ///
    /// ```ignore
    /// server.wait_until(|c| c.metric_count() >= count, timeout).await
    /// ```
    ///
    /// # Arguments
    ///
    /// * `count` - Minimum number of metrics to wait for.
    /// * `timeout` - Maximum duration to wait before returning an error.
    ///
    /// # Errors
    ///
    /// Returns [`MockServerError::WaitTimeout`] if the timeout expires before
    /// the required number of metrics arrive.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use std::time::Duration;
    /// use mock_collector::MockServer;
    ///
    /// # #[tokio::main]
    /// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let server = MockServer::builder().start().await?;
    ///
    /// // ... trigger metric generation ...
    ///
    /// server.wait_for_metrics(10, Duration::from_secs(5)).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn wait_for_metrics(
        &self,
        count: usize,
        timeout: Duration,
    ) -> Result<(), MockServerError> {
        self.wait_until(|c| c.metric_count() >= count, timeout)
            .await
    }

    /// Gracefully shuts down the server.
    ///
    /// # Errors
    ///
    /// Returns an error if the server task panicked.
    pub async fn shutdown(mut self) -> Result<(), MockServerError> {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
        if let Some(task) = self.task.take() {
            task.await?
        } else {
            Ok(())
        }
    }
}

impl Drop for ServerHandle {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
    }
}

#[derive(Clone)]
struct GrpcLogsService {
    collector: Arc<RwLock<MockCollector>>,
}

#[tonic::async_trait]
impl LogsService for GrpcLogsService {
    async fn export(
        &self,
        request: Request<ExportLogsServiceRequest>,
    ) -> Result<Response<ExportLogsServiceResponse>, Status> {
        let req = request.into_inner();

        self.collector.write().await.add_logs(req);

        Ok(Response::new(ExportLogsServiceResponse {
            partial_success: None,
        }))
    }
}

#[derive(Clone)]
struct GrpcTraceService {
    collector: Arc<RwLock<MockCollector>>,
}

#[tonic::async_trait]
impl TraceService for GrpcTraceService {
    async fn export(
        &self,
        request: Request<ExportTraceServiceRequest>,
    ) -> Result<Response<ExportTraceServiceResponse>, Status> {
        let req = request.into_inner();

        self.collector.write().await.add_traces(req);

        Ok(Response::new(ExportTraceServiceResponse {
            partial_success: None,
        }))
    }
}

#[derive(Clone)]
struct GrpcMetricsService {
    collector: Arc<RwLock<MockCollector>>,
}

#[tonic::async_trait]
impl MetricsService for GrpcMetricsService {
    async fn export(
        &self,
        request: Request<ExportMetricsServiceRequest>,
    ) -> Result<Response<ExportMetricsServiceResponse>, Status> {
        let req = request.into_inner();

        self.collector.write().await.add_metrics(req);

        Ok(Response::new(ExportMetricsServiceResponse {
            partial_success: None,
        }))
    }
}

#[derive(Clone, Copy, Debug)]
enum HttpProtocol {
    Json,
    Binary,
}

impl HttpProtocol {
    fn decode<T: prost::Message + Default + serde::de::DeserializeOwned>(
        &self,
        body: &[u8],
    ) -> Result<T, MockServerError> {
        match self {
            HttpProtocol::Json => {
                serde_json::from_slice(body).map_err(MockServerError::JsonParseError)
            }
            HttpProtocol::Binary => {
                <T as prost::Message>::decode(body).map_err(MockServerError::ProtobufParseError)
            }
        }
    }

    fn encode<T: prost::Message + serde::Serialize>(
        &self,
        response: &T,
    ) -> Result<Vec<u8>, MockServerError> {
        match self {
            HttpProtocol::Json => {
                serde_json::to_vec(response).map_err(MockServerError::JsonParseError)
            }
            HttpProtocol::Binary => {
                let mut buf = Vec::new();
                prost::Message::encode(response, &mut buf)
                    .map_err(|e| MockServerError::EncodeError(e.to_string()))?;
                Ok(buf)
            }
        }
    }

    fn content_type(&self) -> &'static str {
        match self {
            HttpProtocol::Json => "application/json",
            HttpProtocol::Binary => "application/x-protobuf",
        }
    }
}

#[derive(Clone)]
struct HttpServerState {
    collector: Arc<RwLock<MockCollector>>,
    protocol: HttpProtocol,
}

async fn handle_http_signal<Req, Resp>(
    state: &HttpServerState,
    body: &[u8],
    add_fn: fn(&mut MockCollector, Req),
    response: Resp,
) -> axum::response::Response
where
    Req: prost::Message + Default + serde::de::DeserializeOwned,
    Resp: prost::Message + serde::Serialize,
{
    let request: Req = match state.protocol.decode(body) {
        Ok(req) => req,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                format!("Failed to parse request: {}", e),
            )
                .into_response();
        }
    };

    add_fn(&mut *state.collector.write().await, request);

    match state.protocol.encode(&response) {
        Ok(bytes) => (
            StatusCode::OK,
            [(
                axum::http::header::CONTENT_TYPE,
                state.protocol.content_type(),
            )],
            bytes,
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to encode response: {}", e),
        )
            .into_response(),
    }
}

async fn handle_http_logs(
    State(state): State<HttpServerState>,
    body: axum::body::Bytes,
) -> axum::response::Response {
    handle_http_signal(
        &state,
        &body,
        MockCollector::add_logs,
        ExportLogsServiceResponse {
            partial_success: None,
        },
    )
    .await
}

async fn handle_http_traces(
    State(state): State<HttpServerState>,
    body: axum::body::Bytes,
) -> axum::response::Response {
    handle_http_signal(
        &state,
        &body,
        MockCollector::add_traces,
        ExportTraceServiceResponse {
            partial_success: None,
        },
    )
    .await
}

async fn handle_http_metrics(
    State(state): State<HttpServerState>,
    body: axum::body::Bytes,
) -> axum::response::Response {
    handle_http_signal(
        &state,
        &body,
        MockCollector::add_metrics,
        ExportMetricsServiceResponse {
            partial_success: None,
        },
    )
    .await
}
