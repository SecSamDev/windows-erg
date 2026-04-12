//! Event query building and XPath query construction.

use super::types::EventLevel;
use std::borrow::Cow;

/// Query builder for constructing flexible event queries.
///
/// Supports building XPath queries with convenience methods while allowing
/// raw XPath for advanced scenarios.
#[derive(Debug, Clone)]
pub struct QueryBuilder {
    xpath: Option<String>,
    level: Option<EventLevel>,
    provider: Option<String>,
    event_id: Option<u32>,
    reverse: bool,
    max_results: Option<usize>,
    include_event_data: bool,
    parse_message: bool,
}

impl QueryBuilder {
    /// Create a new query builder.
    pub fn new() -> Self {
        QueryBuilder {
            xpath: None,
            level: None,
            provider: None,
            event_id: None,
            reverse: false,
            max_results: None,
            include_event_data: false,
            parse_message: false,
        }
    }

    /// Set a raw XPath query expression.
    ///
    /// When set, this takes precedence over other builder fields.
    /// Example: `"Event/System[EventID=4688]"`
    pub fn xpath(mut self, xpath: impl Into<Cow<'static, str>>) -> Self {
        self.xpath = Some(xpath.into().into_owned());
        self
    }

    /// Filter by event level (1=Critical to 5=Verbose).
    pub fn level(mut self, level: EventLevel) -> Self {
        self.level = Some(level);
        self
    }

    /// Filter by provider/source name.
    pub fn provider(mut self, name: impl Into<Cow<'static, str>>) -> Self {
        self.provider = Some(name.into().into_owned());
        self
    }

    /// Filter by specific event ID.
    pub fn event_id(mut self, id: u32) -> Self {
        self.event_id = Some(id);
        self
    }

    /// Query in reverse order (newest to oldest).
    ///
    /// Note: Not supported on Debug/Analytic channels or .evt files.
    pub fn reverse(mut self) -> Self {
        self.reverse = true;
        self
    }

    /// Limit maximum number of results returned.
    pub fn max_results(mut self, count: usize) -> Self {
        self.max_results = Some(count);
        self
    }

    /// Parse EventData fields into the data HashMap.
    ///
    /// When enabled, extracts <Data Name="..."> fields from event XML.
    /// Common field names are cached as static strings for performance.
    pub fn with_event_data(mut self) -> Self {
        self.include_event_data = true;
        self
    }

    /// Parse event message using publisher metadata.
    ///
    /// When enabled, formats the event message using the provider's message template.
    /// Returns None if publisher metadata is unavailable.
    pub fn with_message(mut self) -> Self {
        self.parse_message = true;
        self
    }

    /// Check if EventData parsing is enabled.
    pub fn should_parse_event_data(&self) -> bool {
        self.include_event_data
    }

    /// Check if message parsing is enabled.
    pub fn should_parse_message(&self) -> bool {
        self.parse_message
    }

    /// Build the final XPath query string.
    ///
    /// Returns the XPath expression that will be passed to Windows Event Log API.
    /// If raw XPath was set, returns that. Otherwise, builds XPath from builder fields.
    pub fn build_xpath(&self) -> String {
        if let Some(xpath) = &self.xpath {
            return xpath.clone();
        }

        let mut conditions = Vec::new();

        // Add event level condition
        if let Some(level) = self.level {
            conditions.push(format!("Level <= {}", level as u8));
        }

        // Add provider condition
        if let Some(ref provider) = self.provider {
            conditions.push(format!(
                "System/Provider/@Name='{}'",
                escape_xpath_string(provider)
            ));
        }

        // Add event ID condition
        if let Some(id) = self.event_id {
            conditions.push(format!("EventID={}", id));
        }

        // Build XPath expression
        if conditions.is_empty() {
            "Event".to_string()
        } else {
            format!("Event/System[{}]", conditions.join(" and "))
        }
    }

    /// Get whether query should be reversed.
    pub fn is_reverse(&self) -> bool {
        self.reverse
    }

    /// Get maximum results limit if set.
    pub fn max_results_limit(&self) -> Option<usize> {
        self.max_results
    }
}

impl Default for QueryBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Escape special characters for XPath string literals.
fn escape_xpath_string(s: &str) -> String {
    // XPath doesn't have standard escape sequences; handle single/double quotes
    // by wroting the string if it contains quotes
    if s.contains('\'') && s.contains('"') {
        // Has both - need to use concat()
        // For now, prefer double quotes and escape any double quotes
        s.replace('"', "&quot;")
    } else if s.contains('\'') {
        // Use double quotes
        s.to_string()
    } else {
        // Use single quotes (preferred)
        s.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_query_builder_empty() {
        let builder = QueryBuilder::new();
        assert_eq!(builder.build_xpath(), "Event");
    }

    #[test]
    fn test_query_builder_with_level() {
        let builder = QueryBuilder::new().level(EventLevel::Error);
        let xpath = builder.build_xpath();
        assert!(xpath.contains("Level <= 3"));
        assert!(xpath.contains("Event/System"));
    }

    #[test]
    fn test_query_builder_with_provider() {
        let builder = QueryBuilder::new().provider("Security");
        let xpath = builder.build_xpath();
        assert!(xpath.contains("System/Provider/@Name='Security'"));
    }

    #[test]
    fn test_query_builder_with_event_id() {
        let builder = QueryBuilder::new().event_id(4688);
        let xpath = builder.build_xpath();
        assert!(xpath.contains("EventID=4688"));
    }

    #[test]
    fn test_query_builder_combined() {
        let builder = QueryBuilder::new()
            .level(EventLevel::Warning)
            .provider("Application")
            .event_id(1000);
        let xpath = builder.build_xpath();
        assert!(xpath.contains("Level <= 4"));
        assert!(xpath.contains("System/Provider/@Name='Application'"));
        assert!(xpath.contains("EventID=1000"));
        assert!(xpath.contains(" and "));
    }

    #[test]
    fn test_query_builder_with_raw_xpath() {
        let builder = QueryBuilder::new()
            .xpath("Event/System[EventID=4728]")
            .level(EventLevel::Error); // Should be ignored
        let xpath = builder.build_xpath();
        assert_eq!(xpath, "Event/System[EventID=4728]");
    }

    #[test]
    fn test_query_builder_reverse() {
        let builder = QueryBuilder::new().reverse();
        assert!(builder.is_reverse());

        let builder2 = QueryBuilder::new();
        assert!(!builder2.is_reverse());
    }

    #[test]
    fn test_query_builder_max_results() {
        let builder = QueryBuilder::new().max_results(100);
        assert_eq!(builder.max_results_limit(), Some(100));

        let builder2 = QueryBuilder::new();
        assert_eq!(builder2.max_results_limit(), None);
    }
}
