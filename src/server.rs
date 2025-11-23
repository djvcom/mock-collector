use axum::{Router, extract::State, http::StatusCode, response::IntoResponse, routing::post};
use opentelemetry_otlp::Protocol;
use opentelemetry_proto::tonic::collector::logs::v1::{
    ExportLogsServiceRequest, ExportLogsServiceResponse,
    logs_service_server::{LogsService, LogsServiceServer},
};
use opentelemetry_proto::tonic::collector::trace::v1::{
    ExportTraceServiceRequest, ExportTraceServiceResponse,
    trace_service_server::{TraceService, TraceServiceServer},
};
use opentelemetry_proto::tonic::collector::metrics::v1::{
    ExportMetricsServiceRequest, ExportMetricsServiceResponse,
    metrics_service_server::{MetricsService, MetricsServiceServer},
};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::RwLock;
use tonic::{Request, Response, Status};

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
                .add_service(LogsServiceServer::new(logs_service))
                .add_service(TraceServiceServer::new(trace_service))
                .add_service(MetricsServiceServer::new(metrics_service))
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
/// Use this to access the collector, get the bound address, or shut down the server.
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

// gRPC service implementation
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

// HTTP protocol type
#[derive(Clone, Copy, Debug)]
enum HttpProtocol {
    Json,
    Binary,
}

impl HttpProtocol {
    fn decode_logs(&self, body: &[u8]) -> Result<ExportLogsServiceRequest, MockServerError> {
        match self {
            HttpProtocol::Json => {
                serde_json::from_slice(body).map_err(MockServerError::JsonParseError)
            }
            HttpProtocol::Binary => {
                prost::Message::decode(body).map_err(MockServerError::ProtobufParseError)
            }
        }
    }

    fn encode_logs(
        &self,
        response: &ExportLogsServiceResponse,
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

    fn decode_traces(&self, body: &[u8]) -> Result<ExportTraceServiceRequest, MockServerError> {
        match self {
            HttpProtocol::Json => {
                serde_json::from_slice(body).map_err(MockServerError::JsonParseError)
            }
            HttpProtocol::Binary => {
                prost::Message::decode(body).map_err(MockServerError::ProtobufParseError)
            }
        }
    }

    fn encode_traces(
        &self,
        response: &ExportTraceServiceResponse,
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

    fn decode_metrics(
        &self,
        body: &[u8],
    ) -> Result<ExportMetricsServiceRequest, MockServerError> {
        match self {
            HttpProtocol::Json => {
                serde_json::from_slice(body).map_err(MockServerError::JsonParseError)
            }
            HttpProtocol::Binary => {
                prost::Message::decode(body).map_err(MockServerError::ProtobufParseError)
            }
        }
    }

    fn encode_metrics(
        &self,
        response: &ExportMetricsServiceResponse,
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

// HTTP service implementation
#[derive(Clone)]
struct HttpServerState {
    collector: Arc<RwLock<MockCollector>>,
    protocol: HttpProtocol,
}

async fn handle_http_logs(
    State(state): State<HttpServerState>,
    body: axum::body::Bytes,
) -> impl IntoResponse {
    let request = match state.protocol.decode_logs(&body) {
        Ok(req) => req,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                format!("Failed to parse request: {}", e),
            )
                .into_response();
        }
    };

    state.collector.write().await.add_logs(request);

    let response = ExportLogsServiceResponse {
        partial_success: None,
    };

    match state.protocol.encode_logs(&response) {
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

async fn handle_http_traces(
    State(state): State<HttpServerState>,
    body: axum::body::Bytes,
) -> impl IntoResponse {
    let request = match state.protocol.decode_traces(&body) {
        Ok(req) => req,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                format!("Failed to parse request: {}", e),
            )
                .into_response();
        }
    };

    state.collector.write().await.add_traces(request);

    let response = ExportTraceServiceResponse {
        partial_success: None,
    };

    match state.protocol.encode_traces(&response) {
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

async fn handle_http_metrics(
    State(state): State<HttpServerState>,
    body: axum::body::Bytes,
) -> impl IntoResponse {
    let request = match state.protocol.decode_metrics(&body) {
        Ok(req) => req,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                format!("Failed to parse request: {}", e),
            )
                .into_response();
        }
    };

    state.collector.write().await.add_metrics(request);

    let response = ExportMetricsServiceResponse {
        partial_success: None,
    };

    match state.protocol.encode_metrics(&response) {
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
