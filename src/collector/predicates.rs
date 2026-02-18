/// Represents a numeric metric value for assertions.
///
/// Metric data points can contain either integer or floating-point values.
/// This enum provides a unified representation for both types, enabling
/// value-based assertions on Gauge and Sum metrics.
#[derive(Debug, Clone, Copy)]
pub enum MetricValue {
    /// An integer value (i64).
    Int(i64),
    /// A floating-point value (f64).
    Double(f64),
}

impl MetricValue {
    /// Compares two metric values for approximate equality.
    ///
    /// For integer comparisons, uses exact equality.
    /// For floating-point comparisons, uses epsilon-based comparison.
    /// Mixed comparisons convert to f64.
    pub(crate) fn approx_eq(&self, other: &MetricValue) -> bool {
        match (self, other) {
            (MetricValue::Int(a), MetricValue::Int(b)) => a == b,
            (MetricValue::Double(a), MetricValue::Double(b)) => (a - b).abs() < f64::EPSILON,
            (MetricValue::Int(a), MetricValue::Double(b))
            | (MetricValue::Double(b), MetricValue::Int(a)) => {
                ((*a as f64) - b).abs() < f64::EPSILON
            }
        }
    }

    pub(crate) fn as_f64(&self) -> f64 {
        match self {
            MetricValue::Int(i) => *i as f64,
            MetricValue::Double(d) => *d,
        }
    }
}

impl std::fmt::Display for MetricValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MetricValue::Int(i) => write!(f, "{}", i),
            MetricValue::Double(d) => write!(f, "{}", d),
        }
    }
}

impl From<i64> for MetricValue {
    fn from(v: i64) -> Self {
        MetricValue::Int(v)
    }
}

impl From<i32> for MetricValue {
    fn from(v: i32) -> Self {
        MetricValue::Int(v.into())
    }
}

impl From<i16> for MetricValue {
    fn from(v: i16) -> Self {
        MetricValue::Int(v.into())
    }
}

impl From<i8> for MetricValue {
    fn from(v: i8) -> Self {
        MetricValue::Int(v.into())
    }
}

impl From<u32> for MetricValue {
    fn from(v: u32) -> Self {
        MetricValue::Int(v.into())
    }
}

impl From<u16> for MetricValue {
    fn from(v: u16) -> Self {
        MetricValue::Int(v.into())
    }
}

impl From<u8> for MetricValue {
    fn from(v: u8) -> Self {
        MetricValue::Int(v.into())
    }
}

impl From<f64> for MetricValue {
    fn from(v: f64) -> Self {
        MetricValue::Double(v)
    }
}

impl From<f32> for MetricValue {
    fn from(v: f32) -> Self {
        MetricValue::Double(v.into())
    }
}

#[derive(Debug, Clone)]
pub(crate) enum MetricValuePredicate {
    Eq(MetricValue),
    Gt(MetricValue),
    Gte(MetricValue),
    Lt(MetricValue),
    Lte(MetricValue),
}

impl MetricValuePredicate {
    pub(crate) fn matches(&self, actual: &MetricValue) -> bool {
        match self {
            MetricValuePredicate::Eq(expected) => actual.approx_eq(expected),
            MetricValuePredicate::Gt(expected) => actual.as_f64() > expected.as_f64(),
            MetricValuePredicate::Gte(expected) => {
                actual.as_f64() >= expected.as_f64() || actual.approx_eq(expected)
            }
            MetricValuePredicate::Lt(expected) => actual.as_f64() < expected.as_f64(),
            MetricValuePredicate::Lte(expected) => {
                actual.as_f64() <= expected.as_f64() || actual.approx_eq(expected)
            }
        }
    }

    pub(crate) fn matches_f64(&self, actual: f64) -> bool {
        self.matches(&MetricValue::Double(actual))
    }

    pub(crate) fn format(&self) -> String {
        match self {
            MetricValuePredicate::Eq(v) => format!("== {}", v),
            MetricValuePredicate::Gt(v) => format!("> {}", v),
            MetricValuePredicate::Gte(v) => format!(">= {}", v),
            MetricValuePredicate::Lt(v) => format!("< {}", v),
            MetricValuePredicate::Lte(v) => format!("<= {}", v),
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) enum CountPredicate {
    Eq(u64),
    Gt(u64),
    Gte(u64),
    Lt(u64),
    Lte(u64),
}

impl CountPredicate {
    pub(crate) fn matches(&self, actual: u64) -> bool {
        match self {
            CountPredicate::Eq(expected) => actual == *expected,
            CountPredicate::Gt(expected) => actual > *expected,
            CountPredicate::Gte(expected) => actual >= *expected,
            CountPredicate::Lt(expected) => actual < *expected,
            CountPredicate::Lte(expected) => actual <= *expected,
        }
    }

    pub(crate) fn format(&self) -> String {
        match self {
            CountPredicate::Eq(v) => format!("== {}", v),
            CountPredicate::Gt(v) => format!("> {}", v),
            CountPredicate::Gte(v) => format!(">= {}", v),
            CountPredicate::Lt(v) => format!("< {}", v),
            CountPredicate::Lte(v) => format!("<= {}", v),
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct BucketPredicate {
    pub(crate) index: usize,
    pub(crate) predicate: CountPredicate,
}

#[derive(Debug, Clone)]
pub(crate) struct QuantilePredicate {
    pub(crate) quantile: f64,
    pub(crate) predicate: MetricValuePredicate,
}

/// Generates count predicate methods (with_count_eq, with_count_gt, etc.)
macro_rules! impl_count_predicates {
    ($field:ident) => {
        /// Adds a count equality assertion.
        #[must_use]
        pub fn with_count_eq(mut self, count: u64) -> Self {
            self.$field.push(CountPredicate::Eq(count));
            self
        }

        /// Adds a count greater-than assertion.
        #[must_use]
        pub fn with_count_gt(mut self, count: u64) -> Self {
            self.$field.push(CountPredicate::Gt(count));
            self
        }

        /// Adds a count greater-than-or-equal assertion.
        #[must_use]
        pub fn with_count_gte(mut self, count: u64) -> Self {
            self.$field.push(CountPredicate::Gte(count));
            self
        }

        /// Adds a count less-than assertion.
        #[must_use]
        pub fn with_count_lt(mut self, count: u64) -> Self {
            self.$field.push(CountPredicate::Lt(count));
            self
        }

        /// Adds a count less-than-or-equal assertion.
        #[must_use]
        pub fn with_count_lte(mut self, count: u64) -> Self {
            self.$field.push(CountPredicate::Lte(count));
            self
        }
    };
}

/// Generates sum predicate methods (with_sum_eq, with_sum_gt, etc.)
macro_rules! impl_sum_predicates {
    ($field:ident) => {
        /// Adds a sum equality assertion.
        #[must_use]
        pub fn with_sum_eq<V: Into<MetricValue>>(mut self, value: V) -> Self {
            self.$field.push(MetricValuePredicate::Eq(value.into()));
            self
        }

        /// Adds a sum greater-than assertion.
        #[must_use]
        pub fn with_sum_gt<V: Into<MetricValue>>(mut self, value: V) -> Self {
            self.$field.push(MetricValuePredicate::Gt(value.into()));
            self
        }

        /// Adds a sum greater-than-or-equal assertion.
        #[must_use]
        pub fn with_sum_gte<V: Into<MetricValue>>(mut self, value: V) -> Self {
            self.$field.push(MetricValuePredicate::Gte(value.into()));
            self
        }

        /// Adds a sum less-than assertion.
        #[must_use]
        pub fn with_sum_lt<V: Into<MetricValue>>(mut self, value: V) -> Self {
            self.$field.push(MetricValuePredicate::Lt(value.into()));
            self
        }

        /// Adds a sum less-than-or-equal assertion.
        #[must_use]
        pub fn with_sum_lte<V: Into<MetricValue>>(mut self, value: V) -> Self {
            self.$field.push(MetricValuePredicate::Lte(value.into()));
            self
        }
    };
}

/// Generates min/max predicate methods
macro_rules! impl_min_max_predicates {
    ($min_field:ident, $max_field:ident) => {
        /// Adds a min value equality assertion.
        #[must_use]
        pub fn with_min_eq<V: Into<MetricValue>>(mut self, value: V) -> Self {
            self.$min_field.push(MetricValuePredicate::Eq(value.into()));
            self
        }

        /// Adds a min value greater-than assertion.
        #[must_use]
        pub fn with_min_gt<V: Into<MetricValue>>(mut self, value: V) -> Self {
            self.$min_field.push(MetricValuePredicate::Gt(value.into()));
            self
        }

        /// Adds a min value greater-than-or-equal assertion.
        #[must_use]
        pub fn with_min_gte<V: Into<MetricValue>>(mut self, value: V) -> Self {
            self.$min_field
                .push(MetricValuePredicate::Gte(value.into()));
            self
        }

        /// Adds a min value less-than assertion.
        #[must_use]
        pub fn with_min_lt<V: Into<MetricValue>>(mut self, value: V) -> Self {
            self.$min_field.push(MetricValuePredicate::Lt(value.into()));
            self
        }

        /// Adds a min value less-than-or-equal assertion.
        #[must_use]
        pub fn with_min_lte<V: Into<MetricValue>>(mut self, value: V) -> Self {
            self.$min_field
                .push(MetricValuePredicate::Lte(value.into()));
            self
        }

        /// Adds a max value equality assertion.
        #[must_use]
        pub fn with_max_eq<V: Into<MetricValue>>(mut self, value: V) -> Self {
            self.$max_field.push(MetricValuePredicate::Eq(value.into()));
            self
        }

        /// Adds a max value greater-than assertion.
        #[must_use]
        pub fn with_max_gt<V: Into<MetricValue>>(mut self, value: V) -> Self {
            self.$max_field.push(MetricValuePredicate::Gt(value.into()));
            self
        }

        /// Adds a max value greater-than-or-equal assertion.
        #[must_use]
        pub fn with_max_gte<V: Into<MetricValue>>(mut self, value: V) -> Self {
            self.$max_field
                .push(MetricValuePredicate::Gte(value.into()));
            self
        }

        /// Adds a max value less-than assertion.
        #[must_use]
        pub fn with_max_lt<V: Into<MetricValue>>(mut self, value: V) -> Self {
            self.$max_field.push(MetricValuePredicate::Lt(value.into()));
            self
        }

        /// Adds a max value less-than-or-equal assertion.
        #[must_use]
        pub fn with_max_lte<V: Into<MetricValue>>(mut self, value: V) -> Self {
            self.$max_field
                .push(MetricValuePredicate::Lte(value.into()));
            self
        }
    };
}

pub(crate) use impl_count_predicates;
pub(crate) use impl_min_max_predicates;
pub(crate) use impl_sum_predicates;

/// Generates the 6 common attribute builder methods shared by all assertion types.
///
/// Requires the struct to have `attributes`, `resource_attributes`, and
/// `scope_attributes` fields of type `Option<Vec<(String, Value)>>`.
macro_rules! impl_attribute_methods {
    () => {
        /// Adds attribute criteria.
        ///
        /// All attributes must have the same value type. For mixed types, use
        /// [`with_attribute`](Self::with_attribute) instead.
        #[must_use]
        pub fn with_attributes<I, K, V>(mut self, attributes: I) -> Self
        where
            I: IntoIterator<Item = (K, V)>,
            K: Into<String>,
            V: Into<Value>,
        {
            self.attributes = Some(
                attributes
                    .into_iter()
                    .map(|(k, v)| (k.into(), v.into()))
                    .collect(),
            );
            self
        }

        /// Adds a single attribute criterion.
        ///
        /// Can be chained to add multiple attributes of different types.
        #[must_use]
        pub fn with_attribute<K, V>(mut self, key: K, value: V) -> Self
        where
            K: Into<String>,
            V: Into<Value>,
        {
            self.attributes
                .get_or_insert_with(Vec::new)
                .push((key.into(), value.into()));
            self
        }

        /// Adds resource attribute criteria.
        ///
        /// All attributes must have the same value type. For mixed types, use
        /// [`with_resource_attribute`](Self::with_resource_attribute) instead.
        #[must_use]
        pub fn with_resource_attributes<I, K, V>(mut self, resource_attributes: I) -> Self
        where
            I: IntoIterator<Item = (K, V)>,
            K: Into<String>,
            V: Into<Value>,
        {
            self.resource_attributes = Some(
                resource_attributes
                    .into_iter()
                    .map(|(k, v)| (k.into(), v.into()))
                    .collect(),
            );
            self
        }

        /// Adds a single resource attribute criterion.
        #[must_use]
        pub fn with_resource_attribute<K, V>(mut self, key: K, value: V) -> Self
        where
            K: Into<String>,
            V: Into<Value>,
        {
            self.resource_attributes
                .get_or_insert_with(Vec::new)
                .push((key.into(), value.into()));
            self
        }

        /// Adds scope attribute criteria.
        ///
        /// All attributes must have the same value type. For mixed types, use
        /// [`with_scope_attribute`](Self::with_scope_attribute) instead.
        #[must_use]
        pub fn with_scope_attributes<I, K, V>(mut self, scope_attributes: I) -> Self
        where
            I: IntoIterator<Item = (K, V)>,
            K: Into<String>,
            V: Into<Value>,
        {
            self.scope_attributes = Some(
                scope_attributes
                    .into_iter()
                    .map(|(k, v)| (k.into(), v.into()))
                    .collect(),
            );
            self
        }

        /// Adds a single scope attribute criterion.
        #[must_use]
        pub fn with_scope_attribute<K, V>(mut self, key: K, value: V) -> Self
        where
            K: Into<String>,
            V: Into<Value>,
        {
            self.scope_attributes
                .get_or_insert_with(Vec::new)
                .push((key.into(), value.into()));
            self
        }
    };
}

pub(crate) use impl_attribute_methods;

/// Generates common assertion methods (assert_exists, assert_not_exists, etc.)
/// shared by all assertion types.
///
/// Requires the struct to have:
/// - A field named `$items_field` containing the items slice
/// - `matches(&self, item)`, `matches_any(&self)`, `build_error_message(&self)`,
///   `format_criteria(&self)`, and `format_matching(&self)` methods
macro_rules! impl_assertion_methods {
    ($items_field:ident, $item_type:ty, $plural:expr, $format_matching:ident) => {
        /// Asserts that at least one item matches all specified criteria.
        ///
        /// # Panics
        ///
        /// Panics with a descriptive message if no match is found.
        #[allow(clippy::panic)]
        #[track_caller]
        pub fn assert_exists(&self) {
            if !self.matches_any() {
                panic!("{}", self.build_error_message());
            }
        }

        /// Asserts that no items match the specified criteria.
        ///
        /// # Panics
        ///
        /// Panics if any items match the criteria.
        #[allow(clippy::panic)]
        #[track_caller]
        pub fn assert_not_exists(&self) {
            if self.matches_any() {
                panic!(
                    "Expected no {} to match, but found {} matching.\nCriteria: {}",
                    $plural,
                    self.count(),
                    self.format_criteria()
                );
            }
        }

        /// Asserts that exactly the specified number of items match.
        ///
        /// # Panics
        ///
        /// Panics if the count doesn't match.
        #[allow(clippy::panic)]
        #[track_caller]
        pub fn assert_count(&self, expected: usize) {
            let actual = self.count();
            if actual != expected {
                panic!(
                    "Expected {} matching {}, but found {}.\nCriteria: {}\n\n{}",
                    expected,
                    $plural,
                    actual,
                    self.format_criteria(),
                    self.$format_matching()
                );
            }
        }

        /// Asserts that at least the specified number of items match.
        ///
        /// # Panics
        ///
        /// Panics if fewer items match.
        #[allow(clippy::panic)]
        #[track_caller]
        pub fn assert_at_least(&self, min: usize) {
            let actual = self.count();
            if actual < min {
                panic!(
                    "Expected at least {} matching {}, but found {}.\nCriteria: {}",
                    min,
                    $plural,
                    actual,
                    self.format_criteria()
                );
            }
        }

        /// Asserts that no more than the specified number of items match.
        ///
        /// # Panics
        ///
        /// Panics if more items match.
        #[allow(clippy::panic)]
        #[track_caller]
        pub fn assert_at_most(&self, max: usize) {
            let actual = self.count();
            if actual > max {
                panic!(
                    "Expected at most {} matching {}, but found {}.\nCriteria: {}",
                    max,
                    $plural,
                    actual,
                    self.format_criteria()
                );
            }
        }

        /// Returns the number of items that match the criteria.
        #[must_use = "the count should be used"]
        pub fn count(&self) -> usize {
            self.$items_field
                .iter()
                .filter(|item| self.matches(item))
                .count()
        }

        /// Returns all items that match the criteria.
        #[must_use = "the matching items should be used"]
        pub fn get_all(&self) -> Vec<&$item_type> {
            self.$items_field
                .iter()
                .filter(|item| self.matches(item))
                .collect()
        }

        fn matches_any(&self) -> bool {
            self.$items_field.iter().any(|item| self.matches(item))
        }
    };
}

pub(crate) use impl_assertion_methods;
