//! Example: Embedded agent
//!
//! This demonstrates how to embed Tamandua Core in a custom application.
//!
//! Usage:
//! ```
//! cargo run --example embedded_agent --features full
//! ```

use tamandua_core::{AgentConfig, TamanduaCore};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize logging
    tracing_subscriber::fmt::init();

    // Create configuration
    let mut config = AgentConfig::default();
    config.agent_id = "embedded-agent-001".to_string();
    config.server_url = "wss://localhost:4000/socket/agent".to_string();
    config.telemetry.enabled = true;
    config.detection.enabled = true;
    config.response.enabled = true;

    println!("Starting Tamandua Core agent...");
    println!("Agent ID: {}", config.agent_id);
    println!("Server URL: {}", config.server_url);

    // Create and start agent
    let mut agent = TamanduaCore::new(config).await?;
    agent.start().await?;

    println!("Agent started successfully!");
    println!("Press Ctrl+C to stop...");

    // Wait for Ctrl+C
    tokio::signal::ctrl_c().await?;

    println!("\nStopping agent...");
    agent.stop().await?;

    println!("Agent stopped. Goodbye!");

    Ok(())
}
