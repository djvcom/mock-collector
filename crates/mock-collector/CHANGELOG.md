# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.4](https://github.com/djvcom/mock-collector/compare/v0.2.3...v0.2.4) - 2025-12-03

### Other

- repository improvements

## [0.2.3](https://github.com/djvcom/mock-collector/compare/v0.2.2...v0.2.3) - 2025-12-02

### Added

- improve assertion error messages and dump() output

## [0.2.2](https://github.com/djvcom/mock-collector/compare/v0.2.1...v0.2.2) - 2025-12-01

### Fixed

- disable opentelemetry-otlp default features to avoid HTTP client conflicts

## [0.2.1](https://github.com/djvcom/mock-collector/compare/v0.2.0...v0.2.1) - 2025-11-29

### Added

- add async waiting methods for assertions

## [0.2.0](https://github.com/djvcom/mock-collector/compare/v0.1.2...v0.2.0) - 2025-11-27

### Added

- [**breaking**] add otel-lambda-init package and workspace structure

## [0.1.2](https://github.com/djvcom/mock-collector/compare/v0.1.1...v0.1.2) - 2025-11-23

### Added

- add crates.io and docs badges to README
- auto-update README version and remove deployment approval

### Fixed

- correct release-plz config syntax for version replacement

## [0.1.1](https://github.com/djvcom/mock-collector/compare/v0.1.0...v0.1.1) - 2025-11-23

### Other

- Merge pull request #1 from djvcom/dependabot/github_actions/actions/checkout-6

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
