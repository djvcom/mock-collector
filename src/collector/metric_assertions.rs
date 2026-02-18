use serde_json::Value;

use super::helpers::{check_attributes, get_metric_type_name};
use super::predicates::{
    BucketPredicate, CountPredicate, MetricValue, MetricValuePredicate, QuantilePredicate,
    impl_assertion_methods, impl_attribute_methods, impl_count_predicates, impl_min_max_predicates,
    impl_sum_predicates,
};
use super::types::TestMetric;

/// A builder for constructing histogram metric assertions.
///
/// Provides type-specific assertions for histogram data points, including
/// count, sum, min, max, and bucket-level assertions.
#[derive(Debug)]
pub struct HistogramAssertion<'a> {
    metrics: &'a [TestMetric],
    name: Option<String>,
    attributes: Option<Vec<(String, Value)>>,
    resource_attributes: Option<Vec<(String, Value)>>,
    scope_attributes: Option<Vec<(String, Value)>>,
    count_predicates: Vec<CountPredicate>,
    sum_predicates: Vec<MetricValuePredicate>,
    min_predicates: Vec<MetricValuePredicate>,
    max_predicates: Vec<MetricValuePredicate>,
    bucket_predicates: Vec<BucketPredicate>,
}

impl<'a> HistogramAssertion<'a> {
    pub(crate) fn new(metrics: &'a [TestMetric], name: Option<String>) -> Self {
        Self {
            metrics,
            name,
            attributes: None,
            resource_attributes: None,
            scope_attributes: None,
            count_predicates: Vec::new(),
            sum_predicates: Vec::new(),
            min_predicates: Vec::new(),
            max_predicates: Vec::new(),
            bucket_predicates: Vec::new(),
        }
    }

    impl_assertion_methods!(metrics, TestMetric, "histograms", format_matching_metrics);
    impl_attribute_methods!();
    impl_count_predicates!(count_predicates);
    impl_sum_predicates!(sum_predicates);
    impl_min_max_predicates!(min_predicates, max_predicates);

    /// Adds a bucket count equality assertion for a specific bucket index.
    #[must_use]
    pub fn with_bucket_count_eq(mut self, index: usize, count: u64) -> Self {
        self.bucket_predicates.push(BucketPredicate {
            index,
            predicate: CountPredicate::Eq(count),
        });
        self
    }

    /// Adds a bucket count greater-than assertion for a specific bucket index.
    #[must_use]
    pub fn with_bucket_count_gt(mut self, index: usize, count: u64) -> Self {
        self.bucket_predicates.push(BucketPredicate {
            index,
            predicate: CountPredicate::Gt(count),
        });
        self
    }

    /// Adds a bucket count greater-than-or-equal assertion for a specific bucket index.
    #[must_use]
    pub fn with_bucket_count_gte(mut self, index: usize, count: u64) -> Self {
        self.bucket_predicates.push(BucketPredicate {
            index,
            predicate: CountPredicate::Gte(count),
        });
        self
    }

    /// Adds a bucket count less-than assertion for a specific bucket index.
    #[must_use]
    pub fn with_bucket_count_lt(mut self, index: usize, count: u64) -> Self {
        self.bucket_predicates.push(BucketPredicate {
            index,
            predicate: CountPredicate::Lt(count),
        });
        self
    }

    /// Adds a bucket count less-than-or-equal assertion for a specific bucket index.
    #[must_use]
    pub fn with_bucket_count_lte(mut self, index: usize, count: u64) -> Self {
        self.bucket_predicates.push(BucketPredicate {
            index,
            predicate: CountPredicate::Lte(count),
        });
        self
    }

    fn matches(&self, metric: &TestMetric) -> bool {
        use opentelemetry_proto::tonic::metrics::v1::metric::Data;

        if let Some(ref expected_name) = self.name
            && &metric.metric.name != expected_name
        {
            return false;
        }

        let histogram = match &metric.metric.data {
            Some(Data::Histogram(h)) => h,
            _ => return false,
        };

        if let Some(ref expected_attrs) = self.resource_attributes
            && !check_attributes(&metric.resource_attrs, expected_attrs)
        {
            return false;
        }

        if let Some(ref expected_attrs) = self.scope_attributes
            && !check_attributes(&metric.scope_attrs, expected_attrs)
        {
            return false;
        }

        histogram.data_points.iter().any(|dp| {
            if let Some(ref expected_attrs) = self.attributes
                && !check_attributes(&dp.attributes, expected_attrs)
            {
                return false;
            }

            if !self
                .count_predicates
                .iter()
                .all(|pred| pred.matches(dp.count))
            {
                return false;
            }

            if !self.sum_predicates.is_empty() {
                match dp.sum {
                    Some(sum) => {
                        if !self.sum_predicates.iter().all(|pred| pred.matches_f64(sum)) {
                            return false;
                        }
                    }
                    None => return false,
                }
            }

            if !self.min_predicates.is_empty() {
                match dp.min {
                    Some(min) => {
                        if !self.min_predicates.iter().all(|pred| pred.matches_f64(min)) {
                            return false;
                        }
                    }
                    None => return false,
                }
            }

            if !self.max_predicates.is_empty() {
                match dp.max {
                    Some(max) => {
                        if !self.max_predicates.iter().all(|pred| pred.matches_f64(max)) {
                            return false;
                        }
                    }
                    None => return false,
                }
            }

            for bucket_pred in &self.bucket_predicates {
                if let Some(&bucket_count) = dp.bucket_counts.get(bucket_pred.index) {
                    if !bucket_pred.predicate.matches(bucket_count) {
                        return false;
                    }
                } else {
                    return false;
                }
            }

            true
        })
    }

    fn format_criteria(&self) -> String {
        let mut criteria = Vec::new();
        if let Some(name) = &self.name {
            criteria.push(format!("name={:?}", name));
        }
        if let Some(attrs) = &self.attributes {
            criteria.push(format!("attributes={:?}", attrs));
        }
        if let Some(res_attrs) = &self.resource_attributes {
            criteria.push(format!("resource_attributes={:?}", res_attrs));
        }
        if let Some(scope_attrs) = &self.scope_attributes {
            criteria.push(format!("scope_attributes={:?}", scope_attrs));
        }
        if !self.count_predicates.is_empty() {
            let preds: Vec<String> = self.count_predicates.iter().map(|p| p.format()).collect();
            criteria.push(format!("count({})", preds.join(" AND ")));
        }
        if !self.sum_predicates.is_empty() {
            let preds: Vec<String> = self.sum_predicates.iter().map(|p| p.format()).collect();
            criteria.push(format!("sum({})", preds.join(" AND ")));
        }
        if !self.min_predicates.is_empty() {
            let preds: Vec<String> = self.min_predicates.iter().map(|p| p.format()).collect();
            criteria.push(format!("min({})", preds.join(" AND ")));
        }
        if !self.max_predicates.is_empty() {
            let preds: Vec<String> = self.max_predicates.iter().map(|p| p.format()).collect();
            criteria.push(format!("max({})", preds.join(" AND ")));
        }
        for bp in &self.bucket_predicates {
            criteria.push(format!("bucket[{}]({})", bp.index, bp.predicate.format()));
        }
        criteria.join(", ")
    }

    fn format_matching_metrics(&self) -> String {
        let matching: Vec<_> = self.get_all();
        if matching.is_empty() {
            return String::new();
        }

        let mut output = String::from("Matching histograms:\n");
        for (idx, metric) in matching.iter().enumerate() {
            output.push_str(&format!("  [{}] name=\"{}\"\n", idx, metric.metric.name));
        }
        output
    }

    fn build_error_message(&self) -> String {
        use opentelemetry_proto::tonic::metrics::v1::metric::Data;

        let mut msg = String::from("No histograms matched the assertion.\n\nExpected:\n");

        if let Some(ref name) = self.name {
            msg.push_str(&format!("  name: \"{}\"\n", name));
        }

        if let Some(ref attrs) = self.attributes {
            msg.push_str("  attributes:\n");
            for (k, v) in attrs {
                msg.push_str(&format!("    {}={:?}\n", k, v));
            }
        }

        if let Some(ref attrs) = self.resource_attributes {
            msg.push_str("  resource_attributes:\n");
            for (k, v) in attrs {
                msg.push_str(&format!("    {}={:?}\n", k, v));
            }
        }

        if let Some(ref attrs) = self.scope_attributes {
            msg.push_str("  scope_attributes:\n");
            for (k, v) in attrs {
                msg.push_str(&format!("    {}={:?}\n", k, v));
            }
        }

        if !self.count_predicates.is_empty() {
            msg.push_str("  count:\n");
            for pred in &self.count_predicates {
                msg.push_str(&format!("    {}\n", pred.format()));
            }
        }

        if !self.sum_predicates.is_empty() {
            msg.push_str("  sum:\n");
            for pred in &self.sum_predicates {
                msg.push_str(&format!("    {}\n", pred.format()));
            }
        }

        if !self.min_predicates.is_empty() {
            msg.push_str("  min:\n");
            for pred in &self.min_predicates {
                msg.push_str(&format!("    {}\n", pred.format()));
            }
        }

        if !self.max_predicates.is_empty() {
            msg.push_str("  max:\n");
            for pred in &self.max_predicates {
                msg.push_str(&format!("    {}\n", pred.format()));
            }
        }

        for bp in &self.bucket_predicates {
            msg.push_str(&format!(
                "  bucket[{}]: {}\n",
                bp.index,
                bp.predicate.format()
            ));
        }

        let name_matches: Vec<_> = self
            .metrics
            .iter()
            .filter(|m| {
                self.name
                    .as_ref()
                    .map(|n| &m.metric.name == n)
                    .unwrap_or(true)
            })
            .collect();

        msg.push_str(&format!(
            "\nFound {} metric(s) named {:?}:\n",
            name_matches.len(),
            self.name.as_deref().unwrap_or("*")
        ));

        for (idx, metric) in name_matches.iter().take(10).enumerate() {
            let type_name = get_metric_type_name(&metric.metric);
            msg.push_str(&format!("  [{}] type={}", idx, type_name));

            if let Some(Data::Histogram(h)) = &metric.metric.data
                && let Some(dp) = h.data_points.first()
            {
                msg.push_str(&format!(", count={}", dp.count));
                if let Some(sum) = dp.sum {
                    msg.push_str(&format!(", sum={}", sum));
                }
            }

            msg.push('\n');
        }

        if name_matches.len() > 10 {
            msg.push_str(&format!("  ... and {} more\n", name_matches.len() - 10));
        }

        if name_matches.iter().any(|m| {
            !matches!(
                &m.metric.data,
                Some(opentelemetry_proto::tonic::metrics::v1::metric::Data::Histogram(_))
            )
        }) {
            msg.push_str("\nHint: Use expect_metric_with_name() for Sum/Gauge metrics, or check the metric type.\n");
        }

        msg
    }
}

/// A builder for constructing exponential histogram metric assertions.
///
/// Provides type-specific assertions for exponential histogram data points, including
/// count, sum, min, max, zero_count, and scale assertions.
#[derive(Debug)]
pub struct ExponentialHistogramAssertion<'a> {
    metrics: &'a [TestMetric],
    name: Option<String>,
    attributes: Option<Vec<(String, Value)>>,
    resource_attributes: Option<Vec<(String, Value)>>,
    scope_attributes: Option<Vec<(String, Value)>>,
    count_predicates: Vec<CountPredicate>,
    sum_predicates: Vec<MetricValuePredicate>,
    min_predicates: Vec<MetricValuePredicate>,
    max_predicates: Vec<MetricValuePredicate>,
    zero_count_predicates: Vec<CountPredicate>,
    scale_predicate: Option<i32>,
}

impl<'a> ExponentialHistogramAssertion<'a> {
    pub(crate) fn new(metrics: &'a [TestMetric], name: Option<String>) -> Self {
        Self {
            metrics,
            name,
            attributes: None,
            resource_attributes: None,
            scope_attributes: None,
            count_predicates: Vec::new(),
            sum_predicates: Vec::new(),
            min_predicates: Vec::new(),
            max_predicates: Vec::new(),
            zero_count_predicates: Vec::new(),
            scale_predicate: None,
        }
    }

    impl_assertion_methods!(
        metrics,
        TestMetric,
        "exponential histograms",
        format_matching_metrics
    );
    impl_attribute_methods!();
    impl_count_predicates!(count_predicates);
    impl_sum_predicates!(sum_predicates);
    impl_min_max_predicates!(min_predicates, max_predicates);

    /// Adds a zero count equality assertion.
    #[must_use]
    pub fn with_zero_count_eq(mut self, count: u64) -> Self {
        self.zero_count_predicates.push(CountPredicate::Eq(count));
        self
    }

    /// Adds a zero count greater-than assertion.
    #[must_use]
    pub fn with_zero_count_gt(mut self, count: u64) -> Self {
        self.zero_count_predicates.push(CountPredicate::Gt(count));
        self
    }

    /// Adds a zero count greater-than-or-equal assertion.
    #[must_use]
    pub fn with_zero_count_gte(mut self, count: u64) -> Self {
        self.zero_count_predicates.push(CountPredicate::Gte(count));
        self
    }

    /// Adds a zero count less-than assertion.
    #[must_use]
    pub fn with_zero_count_lt(mut self, count: u64) -> Self {
        self.zero_count_predicates.push(CountPredicate::Lt(count));
        self
    }

    /// Adds a zero count less-than-or-equal assertion.
    #[must_use]
    pub fn with_zero_count_lte(mut self, count: u64) -> Self {
        self.zero_count_predicates.push(CountPredicate::Lte(count));
        self
    }

    /// Adds a scale equality assertion.
    #[must_use]
    pub fn with_scale_eq(mut self, scale: i32) -> Self {
        self.scale_predicate = Some(scale);
        self
    }

    fn matches(&self, metric: &TestMetric) -> bool {
        use opentelemetry_proto::tonic::metrics::v1::metric::Data;

        if let Some(ref expected_name) = self.name
            && &metric.metric.name != expected_name
        {
            return false;
        }

        let exp_histogram = match &metric.metric.data {
            Some(Data::ExponentialHistogram(h)) => h,
            _ => return false,
        };

        if let Some(ref expected_attrs) = self.resource_attributes
            && !check_attributes(&metric.resource_attrs, expected_attrs)
        {
            return false;
        }

        if let Some(ref expected_attrs) = self.scope_attributes
            && !check_attributes(&metric.scope_attrs, expected_attrs)
        {
            return false;
        }

        exp_histogram.data_points.iter().any(|dp| {
            if let Some(ref expected_attrs) = self.attributes
                && !check_attributes(&dp.attributes, expected_attrs)
            {
                return false;
            }

            if !self
                .count_predicates
                .iter()
                .all(|pred| pred.matches(dp.count))
            {
                return false;
            }

            if !self.sum_predicates.is_empty() {
                match dp.sum {
                    Some(sum) => {
                        if !self.sum_predicates.iter().all(|pred| pred.matches_f64(sum)) {
                            return false;
                        }
                    }
                    None => return false,
                }
            }

            if !self.min_predicates.is_empty() {
                match dp.min {
                    Some(min) => {
                        if !self.min_predicates.iter().all(|pred| pred.matches_f64(min)) {
                            return false;
                        }
                    }
                    None => return false,
                }
            }

            if !self.max_predicates.is_empty() {
                match dp.max {
                    Some(max) => {
                        if !self.max_predicates.iter().all(|pred| pred.matches_f64(max)) {
                            return false;
                        }
                    }
                    None => return false,
                }
            }

            if !self
                .zero_count_predicates
                .iter()
                .all(|pred| pred.matches(dp.zero_count))
            {
                return false;
            }

            if let Some(expected_scale) = self.scale_predicate
                && dp.scale != expected_scale
            {
                return false;
            }

            true
        })
    }

    fn format_criteria(&self) -> String {
        let mut criteria = Vec::new();
        if let Some(name) = &self.name {
            criteria.push(format!("name={:?}", name));
        }
        if let Some(attrs) = &self.attributes {
            criteria.push(format!("attributes={:?}", attrs));
        }
        if let Some(res_attrs) = &self.resource_attributes {
            criteria.push(format!("resource_attributes={:?}", res_attrs));
        }
        if let Some(scope_attrs) = &self.scope_attributes {
            criteria.push(format!("scope_attributes={:?}", scope_attrs));
        }
        if !self.count_predicates.is_empty() {
            let preds: Vec<String> = self.count_predicates.iter().map(|p| p.format()).collect();
            criteria.push(format!("count({})", preds.join(" AND ")));
        }
        if !self.sum_predicates.is_empty() {
            let preds: Vec<String> = self.sum_predicates.iter().map(|p| p.format()).collect();
            criteria.push(format!("sum({})", preds.join(" AND ")));
        }
        if !self.min_predicates.is_empty() {
            let preds: Vec<String> = self.min_predicates.iter().map(|p| p.format()).collect();
            criteria.push(format!("min({})", preds.join(" AND ")));
        }
        if !self.max_predicates.is_empty() {
            let preds: Vec<String> = self.max_predicates.iter().map(|p| p.format()).collect();
            criteria.push(format!("max({})", preds.join(" AND ")));
        }
        if !self.zero_count_predicates.is_empty() {
            let preds: Vec<String> = self
                .zero_count_predicates
                .iter()
                .map(|p| p.format())
                .collect();
            criteria.push(format!("zero_count({})", preds.join(" AND ")));
        }
        if let Some(scale) = self.scale_predicate {
            criteria.push(format!("scale == {}", scale));
        }
        criteria.join(", ")
    }

    fn format_matching_metrics(&self) -> String {
        let matching: Vec<_> = self.get_all();
        if matching.is_empty() {
            return String::new();
        }

        let mut output = String::from("Matching exponential histograms:\n");
        for (idx, metric) in matching.iter().enumerate() {
            output.push_str(&format!("  [{}] name=\"{}\"\n", idx, metric.metric.name));
        }
        output
    }

    fn build_error_message(&self) -> String {
        use opentelemetry_proto::tonic::metrics::v1::metric::Data;

        let mut msg =
            String::from("No exponential histograms matched the assertion.\n\nExpected:\n");

        if let Some(ref name) = self.name {
            msg.push_str(&format!("  name: \"{}\"\n", name));
        }

        if let Some(ref attrs) = self.attributes {
            msg.push_str("  attributes:\n");
            for (k, v) in attrs {
                msg.push_str(&format!("    {}={:?}\n", k, v));
            }
        }

        if let Some(ref attrs) = self.resource_attributes {
            msg.push_str("  resource_attributes:\n");
            for (k, v) in attrs {
                msg.push_str(&format!("    {}={:?}\n", k, v));
            }
        }

        if let Some(ref attrs) = self.scope_attributes {
            msg.push_str("  scope_attributes:\n");
            for (k, v) in attrs {
                msg.push_str(&format!("    {}={:?}\n", k, v));
            }
        }

        if !self.count_predicates.is_empty() {
            msg.push_str("  count:\n");
            for pred in &self.count_predicates {
                msg.push_str(&format!("    {}\n", pred.format()));
            }
        }

        if !self.sum_predicates.is_empty() {
            msg.push_str("  sum:\n");
            for pred in &self.sum_predicates {
                msg.push_str(&format!("    {}\n", pred.format()));
            }
        }

        if !self.min_predicates.is_empty() {
            msg.push_str("  min:\n");
            for pred in &self.min_predicates {
                msg.push_str(&format!("    {}\n", pred.format()));
            }
        }

        if !self.max_predicates.is_empty() {
            msg.push_str("  max:\n");
            for pred in &self.max_predicates {
                msg.push_str(&format!("    {}\n", pred.format()));
            }
        }

        if !self.zero_count_predicates.is_empty() {
            msg.push_str("  zero_count:\n");
            for pred in &self.zero_count_predicates {
                msg.push_str(&format!("    {}\n", pred.format()));
            }
        }

        if let Some(scale) = self.scale_predicate {
            msg.push_str(&format!("  scale: == {}\n", scale));
        }

        let name_matches: Vec<_> = self
            .metrics
            .iter()
            .filter(|m| {
                self.name
                    .as_ref()
                    .map(|n| &m.metric.name == n)
                    .unwrap_or(true)
            })
            .collect();

        msg.push_str(&format!(
            "\nFound {} metric(s) named {:?}:\n",
            name_matches.len(),
            self.name.as_deref().unwrap_or("*")
        ));

        for (idx, metric) in name_matches.iter().take(10).enumerate() {
            let type_name = get_metric_type_name(&metric.metric);
            msg.push_str(&format!("  [{}] type={}", idx, type_name));

            if let Some(Data::ExponentialHistogram(h)) = &metric.metric.data
                && let Some(dp) = h.data_points.first()
            {
                msg.push_str(&format!(", count={}", dp.count));
                if let Some(sum) = dp.sum {
                    msg.push_str(&format!(", sum={}", sum));
                }
                msg.push_str(&format!(
                    ", zero_count={}, scale={}",
                    dp.zero_count, dp.scale
                ));
            }

            msg.push('\n');
        }

        if name_matches.len() > 10 {
            msg.push_str(&format!("  ... and {} more\n", name_matches.len() - 10));
        }

        if name_matches.iter().any(|m| {
            !matches!(
                &m.metric.data,
                Some(
                    opentelemetry_proto::tonic::metrics::v1::metric::Data::ExponentialHistogram(_)
                )
            )
        }) {
            msg.push_str("\nHint: Use expect_histogram() for regular histograms, or expect_metric_with_name() for Sum/Gauge metrics.\n");
        }

        msg
    }
}

/// A builder for constructing summary metric assertions.
///
/// Provides type-specific assertions for summary data points, including
/// count, sum, and quantile-level assertions.
#[derive(Debug)]
pub struct SummaryAssertion<'a> {
    metrics: &'a [TestMetric],
    name: Option<String>,
    attributes: Option<Vec<(String, Value)>>,
    resource_attributes: Option<Vec<(String, Value)>>,
    scope_attributes: Option<Vec<(String, Value)>>,
    count_predicates: Vec<CountPredicate>,
    sum_predicates: Vec<MetricValuePredicate>,
    quantile_predicates: Vec<QuantilePredicate>,
}

impl<'a> SummaryAssertion<'a> {
    pub(crate) fn new(metrics: &'a [TestMetric], name: Option<String>) -> Self {
        Self {
            metrics,
            name,
            attributes: None,
            resource_attributes: None,
            scope_attributes: None,
            count_predicates: Vec::new(),
            sum_predicates: Vec::new(),
            quantile_predicates: Vec::new(),
        }
    }

    impl_assertion_methods!(metrics, TestMetric, "summaries", format_matching_metrics);
    impl_attribute_methods!();
    impl_count_predicates!(count_predicates);
    impl_sum_predicates!(sum_predicates);

    /// Adds a quantile value equality assertion.
    #[must_use]
    pub fn with_quantile_eq(mut self, quantile: f64, value: f64) -> Self {
        self.quantile_predicates.push(QuantilePredicate {
            quantile,
            predicate: MetricValuePredicate::Eq(MetricValue::Double(value)),
        });
        self
    }

    /// Adds a quantile value greater-than assertion.
    #[must_use]
    pub fn with_quantile_gt(mut self, quantile: f64, value: f64) -> Self {
        self.quantile_predicates.push(QuantilePredicate {
            quantile,
            predicate: MetricValuePredicate::Gt(MetricValue::Double(value)),
        });
        self
    }

    /// Adds a quantile value greater-than-or-equal assertion.
    #[must_use]
    pub fn with_quantile_gte(mut self, quantile: f64, value: f64) -> Self {
        self.quantile_predicates.push(QuantilePredicate {
            quantile,
            predicate: MetricValuePredicate::Gte(MetricValue::Double(value)),
        });
        self
    }

    /// Adds a quantile value less-than assertion.
    #[must_use]
    pub fn with_quantile_lt(mut self, quantile: f64, value: f64) -> Self {
        self.quantile_predicates.push(QuantilePredicate {
            quantile,
            predicate: MetricValuePredicate::Lt(MetricValue::Double(value)),
        });
        self
    }

    /// Adds a quantile value less-than-or-equal assertion.
    #[must_use]
    pub fn with_quantile_lte(mut self, quantile: f64, value: f64) -> Self {
        self.quantile_predicates.push(QuantilePredicate {
            quantile,
            predicate: MetricValuePredicate::Lte(MetricValue::Double(value)),
        });
        self
    }

    fn matches(&self, metric: &TestMetric) -> bool {
        use opentelemetry_proto::tonic::metrics::v1::metric::Data;

        if let Some(ref expected_name) = self.name
            && &metric.metric.name != expected_name
        {
            return false;
        }

        let summary = match &metric.metric.data {
            Some(Data::Summary(s)) => s,
            _ => return false,
        };

        if let Some(ref expected_attrs) = self.resource_attributes
            && !check_attributes(&metric.resource_attrs, expected_attrs)
        {
            return false;
        }

        if let Some(ref expected_attrs) = self.scope_attributes
            && !check_attributes(&metric.scope_attrs, expected_attrs)
        {
            return false;
        }

        summary.data_points.iter().any(|dp| {
            if let Some(ref expected_attrs) = self.attributes
                && !check_attributes(&dp.attributes, expected_attrs)
            {
                return false;
            }

            if !self
                .count_predicates
                .iter()
                .all(|pred| pred.matches(dp.count))
            {
                return false;
            }

            if !self.sum_predicates.is_empty()
                && !self
                    .sum_predicates
                    .iter()
                    .all(|pred| pred.matches_f64(dp.sum))
            {
                return false;
            }

            for qp in &self.quantile_predicates {
                let quantile_match = dp.quantile_values.iter().any(|qv| {
                    (qv.quantile - qp.quantile).abs() < f64::EPSILON
                        && qp.predicate.matches_f64(qv.value)
                });
                if !quantile_match {
                    return false;
                }
            }

            true
        })
    }

    fn format_criteria(&self) -> String {
        let mut criteria = Vec::new();
        if let Some(name) = &self.name {
            criteria.push(format!("name={:?}", name));
        }
        if let Some(attrs) = &self.attributes {
            criteria.push(format!("attributes={:?}", attrs));
        }
        if let Some(res_attrs) = &self.resource_attributes {
            criteria.push(format!("resource_attributes={:?}", res_attrs));
        }
        if let Some(scope_attrs) = &self.scope_attributes {
            criteria.push(format!("scope_attributes={:?}", scope_attrs));
        }
        if !self.count_predicates.is_empty() {
            let preds: Vec<String> = self.count_predicates.iter().map(|p| p.format()).collect();
            criteria.push(format!("count({})", preds.join(" AND ")));
        }
        if !self.sum_predicates.is_empty() {
            let preds: Vec<String> = self.sum_predicates.iter().map(|p| p.format()).collect();
            criteria.push(format!("sum({})", preds.join(" AND ")));
        }
        for qp in &self.quantile_predicates {
            criteria.push(format!(
                "quantile[{}]({})",
                qp.quantile,
                qp.predicate.format()
            ));
        }
        criteria.join(", ")
    }

    fn format_matching_metrics(&self) -> String {
        let matching: Vec<_> = self.get_all();
        if matching.is_empty() {
            return String::new();
        }

        let mut output = String::from("Matching summaries:\n");
        for (idx, metric) in matching.iter().enumerate() {
            output.push_str(&format!("  [{}] name=\"{}\"\n", idx, metric.metric.name));
        }
        output
    }

    fn build_error_message(&self) -> String {
        use opentelemetry_proto::tonic::metrics::v1::metric::Data;

        let mut msg = String::from("No summaries matched the assertion.\n\nExpected:\n");

        if let Some(ref name) = self.name {
            msg.push_str(&format!("  name: \"{}\"\n", name));
        }

        if let Some(ref attrs) = self.attributes {
            msg.push_str("  attributes:\n");
            for (k, v) in attrs {
                msg.push_str(&format!("    {}={:?}\n", k, v));
            }
        }

        if let Some(ref attrs) = self.resource_attributes {
            msg.push_str("  resource_attributes:\n");
            for (k, v) in attrs {
                msg.push_str(&format!("    {}={:?}\n", k, v));
            }
        }

        if let Some(ref attrs) = self.scope_attributes {
            msg.push_str("  scope_attributes:\n");
            for (k, v) in attrs {
                msg.push_str(&format!("    {}={:?}\n", k, v));
            }
        }

        if !self.count_predicates.is_empty() {
            msg.push_str("  count:\n");
            for pred in &self.count_predicates {
                msg.push_str(&format!("    {}\n", pred.format()));
            }
        }

        if !self.sum_predicates.is_empty() {
            msg.push_str("  sum:\n");
            for pred in &self.sum_predicates {
                msg.push_str(&format!("    {}\n", pred.format()));
            }
        }

        for qp in &self.quantile_predicates {
            msg.push_str(&format!(
                "  quantile[{}]: {}\n",
                qp.quantile,
                qp.predicate.format()
            ));
        }

        let name_matches: Vec<_> = self
            .metrics
            .iter()
            .filter(|m| {
                self.name
                    .as_ref()
                    .map(|n| &m.metric.name == n)
                    .unwrap_or(true)
            })
            .collect();

        msg.push_str(&format!(
            "\nFound {} metric(s) named {:?}:\n",
            name_matches.len(),
            self.name.as_deref().unwrap_or("*")
        ));

        for (idx, metric) in name_matches.iter().take(10).enumerate() {
            let type_name = get_metric_type_name(&metric.metric);
            msg.push_str(&format!("  [{}] type={}", idx, type_name));

            if let Some(Data::Summary(s)) = &metric.metric.data
                && let Some(dp) = s.data_points.first()
            {
                msg.push_str(&format!(", count={}, sum={}", dp.count, dp.sum));
                if !dp.quantile_values.is_empty() {
                    let quantiles: Vec<String> = dp
                        .quantile_values
                        .iter()
                        .take(3)
                        .map(|qv| format!("p{}={}", (qv.quantile * 100.0) as i32, qv.value))
                        .collect();
                    msg.push_str(&format!(", quantiles=[{}]", quantiles.join(", ")));
                }
            }

            msg.push('\n');
        }

        if name_matches.len() > 10 {
            msg.push_str(&format!("  ... and {} more\n", name_matches.len() - 10));
        }

        if name_matches.iter().any(|m| {
            !matches!(
                &m.metric.data,
                Some(opentelemetry_proto::tonic::metrics::v1::metric::Data::Summary(_))
            )
        }) {
            msg.push_str("\nHint: Use expect_histogram() for histograms, or expect_metric_with_name() for Sum/Gauge metrics.\n");
        }

        msg
    }
}
