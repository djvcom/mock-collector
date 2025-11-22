# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Initial release
- Support for gRPC, HTTP/JSON, and HTTP/Protobuf OTLP protocols
- Fluent assertion API with builder pattern
- Count-based assertions (`assert_count`, `assert_at_least`, `assert_at_most`)
- Negative assertions (`assert_not_exists`)
- Scope attribute assertions
- Resource attribute assertions
- Log attribute assertions
- Graceful server shutdown with `ServerHandle::shutdown()`
- Helper methods for accessing collector (`with_collector`, `with_collector_mut`)
- Debug dump functionality for inspecting collected logs
- Arc-optimised storage for resource and scope attributes
- Comprehensive error types with `MockServerError`
- `MockCollector` inspection methods (`logs()`, `log_count()`, `clear()`, `dump()`)
