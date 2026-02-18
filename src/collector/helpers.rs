use opentelemetry_proto::tonic::common::v1::{AnyValue, KeyValue};
use opentelemetry_proto::tonic::metrics::v1::Metric;
use serde_json::Value;

pub(crate) fn format_any_value(value: &Option<AnyValue>) -> String {
    use opentelemetry_proto::tonic::common::v1::any_value::Value as AnyValueInner;

    match value {
        Some(av) => match &av.value {
            Some(AnyValueInner::StringValue(s)) => format!("\"{}\"", s),
            Some(AnyValueInner::IntValue(i)) => i.to_string(),
            Some(AnyValueInner::DoubleValue(d)) => format!("{:.6}", d),
            Some(AnyValueInner::BoolValue(b)) => b.to_string(),
            Some(AnyValueInner::ArrayValue(arr)) => {
                let items: Vec<String> = arr
                    .values
                    .iter()
                    .map(|v| format_any_value(&Some(v.clone())))
                    .collect();
                format!("[{}]", items.join(", "))
            }
            Some(AnyValueInner::KvlistValue(kv)) => {
                let items: Vec<String> = kv
                    .values
                    .iter()
                    .map(|kv| format!("{}={}", kv.key, format_any_value(&kv.value)))
                    .collect();
                format!("{{{}}}", items.join(", "))
            }
            Some(AnyValueInner::BytesValue(b)) => format!("<bytes: {} bytes>", b.len()),
            None => "<empty>".to_string(),
        },
        None => "<none>".to_string(),
    }
}

pub(crate) fn format_attributes(attrs: &[KeyValue], max_items: usize) -> String {
    let mut output = String::from("{");
    for (i, attr) in attrs.iter().take(max_items).enumerate() {
        if i > 0 {
            output.push_str(", ");
        }
        output.push_str(&attr.key);
        output.push('=');
        output.push_str(&format_any_value(&attr.value));
    }
    if attrs.len() > max_items {
        output.push_str(&format!(", ... +{}", attrs.len() - max_items));
    }
    output.push('}');
    output
}

pub(crate) fn check_attributes(attrs: &[KeyValue], expected: &[(String, Value)]) -> bool {
    expected.iter().all(|(key, value)| {
        attrs
            .iter()
            .any(|kv| &kv.key == key && any_value_matches(&kv.value, value))
    })
}

pub(crate) fn any_value_matches(
    attr_value: &Option<opentelemetry_proto::tonic::common::v1::AnyValue>,
    expected: &Value,
) -> bool {
    use opentelemetry_proto::tonic::common::v1::any_value::Value as AnyValueInner;

    match attr_value {
        Some(av) => match &av.value {
            Some(AnyValueInner::StringValue(s)) => {
                expected.as_str().map(|exp| s == exp).unwrap_or(false)
            }
            Some(AnyValueInner::IntValue(i)) => {
                expected.as_i64().map(|exp| *i == exp).unwrap_or(false)
            }
            Some(AnyValueInner::DoubleValue(d)) => expected
                .as_f64()
                .map(|n| (*d - n).abs() < f64::EPSILON)
                .unwrap_or(false),
            Some(AnyValueInner::BoolValue(b)) => {
                expected.as_bool().map(|exp| *b == exp).unwrap_or(false)
            }
            _ => false,
        },
        None => false,
    }
}

pub(crate) fn get_metric_type_name(metric: &Metric) -> &'static str {
    use opentelemetry_proto::tonic::metrics::v1::metric::Data;
    match &metric.data {
        Some(Data::Gauge(_)) => "Gauge",
        Some(Data::Sum(_)) => "Sum",
        Some(Data::Histogram(_)) => "Histogram",
        Some(Data::ExponentialHistogram(_)) => "ExponentialHistogram",
        Some(Data::Summary(_)) => "Summary",
        None => "None",
    }
}
