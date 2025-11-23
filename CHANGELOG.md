# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0](https://github.com/djvcom/mock-collector/releases/tag/v0.1.0) - 2025-11-23

### Other

- fix release-plz action path
- initialize git submodules for tests
- set up automated releases and CI pipeline
- Add more examples, add check for log levels and span errors
- Small refactors, some project metadata updates
- Implement Metrics, handling json serialization issues.
- Clean up and small refactors
- added examples, used real data for tests (from the otel-proto repo), add traces (including span events)
- Refactor & Implement different protocol handling
- Initial Commit

### Added
- Initial release
- Support for gRPC, HTTP/JSON, and HTTP/Protobuf OTLP protocols
- **Support for all three OTLP signals: Logs, Traces, and Metrics**
- Fluent assertion API with builder pattern for all three signals
- Count-based assertions (`assert_count`, `assert_at_least`, `assert_at_most`)
- Negative assertions (`assert_not_exists`)
- Scope attribute assertions
- Resource attribute assertions
- Signal-specific attribute assertions:
  - Log attribute assertions
  - Span attribute assertions
  - Metric data point attribute assertions
- Span event assertions (`with_event`, `with_event_attributes`)
- **Metrics support**:
  - `MetricAssertion` builder with full assertion API
  - `expect_metric_with_name()` and `expect_metric()` entry points
  - Support for all metric types (Gauge, Sum, Histogram, ExponentialHistogram, Summary)
  - Metric data point attribute matching
  - `metric_count()` inspection method
- **Trace support**:
  - `SpanAssertion` builder with full assertion API
  - `expect_span_with_name()` and `expect_span()` entry points
  - Span event and event attribute assertions
  - `span_count()` inspection method
- **Log support**:
  - `LogAssertion` builder with full assertion API
  - `expect_log_with_body()` and `expect_log()` entry points
  - `log_count()` inspection method
- Graceful server shutdown with `ServerHandle::shutdown()`
- Helper methods for accessing collector (`with_collector`, `with_collector_mut`)
- Debug dump functionality for inspecting collected data
- Arc-optimised storage for resource and scope attributes
- Comprehensive error types with `MockServerError`
- `MockCollector` inspection methods (`log_count()`, `span_count()`, `metric_count()`, `clear()`, `dump()`)
