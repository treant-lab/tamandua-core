//! Event collector trait and implementations

use super::TelemetryEvent;
use crate::error::Result;

/// Event collector trait
///
/// Each collector is responsible for monitoring a specific
/// telemetry source (process, file, network, etc.) and
/// producing events.
pub trait EventCollector: Send + Sync {
    /// Collector name
    fn name(&self) -> &str;

    /// Start collecting events
    fn start(&mut self) -> Result<()>;

    /// Stop collecting events
    fn stop(&mut self) -> Result<()>;

    /// Get the next event (non-blocking)
    fn next_event(&mut self) -> Option<TelemetryEvent>;

    /// Check if collector is running
    fn is_running(&self) -> bool;
}
