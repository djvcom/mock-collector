/// Fields where `opentelemetry-proto`'s serde expects a JSON number but the
/// protobuf JSON mapping spec encodes as a string (uint64/fixed64 without a
/// custom `deserialize_string_to_u64` attribute in the generated code).
const UINT64_FIELDS: &[&str] = &["count", "zeroCount", "bucketCounts"];

/// Normalises string-encoded uint64 fields in OTLP JSON so they deserialise
/// correctly with `opentelemetry-proto`'s serde support.
///
/// The protobuf JSON mapping spec encodes uint64/fixed64 values as strings
/// (e.g. `"count": "2"`), but `opentelemetry-proto` does not attach custom
/// deserialisers to all such fields. This function converts the affected
/// fields from strings to numbers in-place, allowing both `"count": "2"` and
/// `"count": 2` to parse successfully.
///
/// Use this when constructing OTLP requests from spec-compliant JSON fixtures:
///
/// ```no_run
/// use mock_collector::normalise_json_uint64s;
///
/// let json = std::fs::read_to_string("metrics.json").unwrap();
/// let mut value: serde_json::Value = serde_json::from_str(&json).unwrap();
/// normalise_json_uint64s(&mut value);
///
/// let request: opentelemetry_proto::tonic::collector::metrics::v1::ExportMetricsServiceRequest =
///     serde_json::from_value(value).unwrap();
/// ```
pub fn normalise_json_uint64s(value: &mut serde_json::Value) {
    walk(value, false);
}

fn walk(value: &mut serde_json::Value, convert: bool) {
    match value {
        serde_json::Value::String(s) if convert => {
            if let Ok(n) = s.parse::<u64>() {
                *value = serde_json::Value::Number(n.into());
            }
        }
        serde_json::Value::Array(arr) => {
            for item in arr {
                walk(item, convert);
            }
        }
        serde_json::Value::Object(map) => {
            for (key, v) in map {
                walk(v, UINT64_FIELDS.contains(&key.as_str()));
            }
        }
        _ => {}
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn converts_known_uint64_fields() {
        let mut value = serde_json::json!({
            "count": "2",
            "bucketCounts": ["1", "1"],
            "zeroCount": "1",
            "sum": 2.0,
            "unit": "1",
            "stringValue": "8080",
            "nested": {
                "timeUnixNano": "1544712660300000000",
                "count": "5",
            }
        });
        normalise_json_uint64s(&mut value);

        assert_eq!(value["count"], serde_json::json!(2));
        assert_eq!(value["bucketCounts"], serde_json::json!([1, 1]));
        assert_eq!(value["zeroCount"], serde_json::json!(1));
        assert_eq!(value["sum"], serde_json::json!(2.0));
        assert_eq!(value["unit"], serde_json::json!("1"));
        assert_eq!(value["stringValue"], serde_json::json!("8080"));
        assert_eq!(
            value["nested"]["timeUnixNano"],
            serde_json::json!("1544712660300000000")
        );
        assert_eq!(value["nested"]["count"], serde_json::json!(5));
    }

    #[test]
    fn preserves_non_numeric_strings() {
        let mut value = serde_json::json!({
            "name": "my.counter",
            "description": "A counter metric",
            "key": "service.name"
        });
        let expected = value.clone();
        normalise_json_uint64s(&mut value);

        assert_eq!(value, expected);
    }

    #[test]
    fn accepts_already_numeric_values() {
        let mut value = serde_json::json!({
            "count": 2,
            "bucketCounts": [1, 1]
        });
        let expected = value.clone();
        normalise_json_uint64s(&mut value);

        assert_eq!(value, expected);
    }

    #[test]
    fn parses_official_metrics_example() {
        use opentelemetry_proto::tonic::collector::metrics::v1::ExportMetricsServiceRequest;

        let json = std::fs::read_to_string(
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("opentelemetry-proto-examples/examples/metrics.json"),
        )
        .unwrap();

        let mut value: serde_json::Value = serde_json::from_str(&json).unwrap();
        normalise_json_uint64s(&mut value);

        let req: ExportMetricsServiceRequest =
            serde_json::from_value(value).expect("normalised JSON should deserialise");
        assert_eq!(req.resource_metrics.len(), 1);
    }
}
