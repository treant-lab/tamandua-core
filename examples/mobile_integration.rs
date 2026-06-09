//! Example: Mobile integration
//!
//! This demonstrates how to use Tamandua Core in a mobile-optimized way.
//!
//! Usage:
//! ```
//! cargo run --example mobile_integration --features mobile
//! ```

use tamandua_core::{AgentConfig, TamanduaCore};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize logging
    tracing_subscriber::fmt::init();

    // Create mobile-optimized configuration
    let mut config = AgentConfig::default();
    config.agent_id = "mobile-agent-001".to_string();

    // Reduce resource usage for mobile
    config.telemetry.batch_size = 50; // Smaller batches
    config.telemetry.batch_timeout_secs = 60; // Less frequent sends
    config.telemetry.collection_interval_ms = 5000; // Slower polling

    // Disable expensive features
    config.detection.entropy_analysis = false;
    config.detection.ml_enabled = false;

    println!("Starting Tamandua Core (mobile mode)...");

    // Create agent
    let mut agent = TamanduaCore::new(config).await?;
    agent.start().await?;

    println!("Mobile agent started!");

    // Simulate app running
    tokio::time::sleep(tokio::time::Duration::from_secs(10)).await;

    println!("Stopping mobile agent...");
    agent.stop().await?;

    Ok(())
}
