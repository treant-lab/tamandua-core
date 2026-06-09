//! Integration tests for tamandua-core

use tamandua_core::{AgentConfig, TamanduaCore};

// Requires a live Tamandua server: `agent.start()` opens a real transport
// connection. Ignored by default; run with `cargo test -- --ignored`.
#[tokio::test]
#[ignore = "requires a live Tamandua server (network transport connection)"]
async fn test_agent_lifecycle() {
    let config = AgentConfig::default();
    let mut agent = TamanduaCore::new(config).await.unwrap();

    // Start agent
    agent.start().await.unwrap();

    // Agent should be running
    #[cfg(feature = "transport")]
    {
        let status = agent.status().await;
        assert!(matches!(
            status,
            tamandua_core::AgentStatus::Running | tamandua_core::AgentStatus::Connected
        ));
    }

    // Stop agent
    agent.stop().await.unwrap();

    // Agent should be stopped
    #[cfg(feature = "transport")]
    {
        let status = agent.status().await;
        assert_eq!(status, tamandua_core::AgentStatus::Stopped);
    }
}

#[tokio::test]
async fn test_agent_health() {
    let config = AgentConfig::default();
    let agent = TamanduaCore::new(config).await.unwrap();

    #[cfg(feature = "transport")]
    {
        let health = agent.health().await;
        assert_eq!(health.events_collected, 0);
        assert_eq!(health.detections_triggered, 0);
    }
}

#[test]
fn test_config_validation() {
    let mut config = AgentConfig::default();

    // Valid config
    assert!(config.validate().is_ok());

    // Invalid entropy threshold
    config.detection.entropy_threshold = 10.0;
    assert!(config.validate().is_err());

    // Fix it
    config.detection.entropy_threshold = 7.2;
    assert!(config.validate().is_ok());

    // Invalid server URL
    config.server_url = "http://invalid".to_string();
    assert!(config.validate().is_err());
}

#[cfg(feature = "detection")]
#[test]
fn test_detection_engine() {
    use tamandua_core::detection::DetectionEngine;

    let config = AgentConfig::default();
    let engine = DetectionEngine::new(&config).unwrap();

    let metrics = engine.metrics();
    assert_eq!(metrics.files_scanned, 0);
    assert_eq!(metrics.detections_triggered, 0);
}

#[cfg(feature = "response")]
#[test]
fn test_response_executor() {
    use tamandua_core::response::ResponseExecutor;

    let config = AgentConfig::default();
    let executor = ResponseExecutor::new(&config).unwrap();

    let metrics = executor.metrics();
    assert_eq!(metrics.responses_executed, 0);
}

#[test]
fn test_platform_entropy() {
    use tamandua_core::platform::calculate_entropy;

    // Low entropy
    let data = vec![0u8; 1024];
    let entropy = calculate_entropy(&data);
    assert!(entropy < 0.1);

    // High entropy
    let data: Vec<u8> = (0..=255).cycle().take(1024).collect();
    let entropy = calculate_entropy(&data);
    assert!(entropy > 7.0);
}

#[test]
fn test_platform_hashing() {
    use tamandua_core::platform::{calculate_blake3, calculate_sha256};

    let data = b"hello world";

    let sha256 = calculate_sha256(data);
    assert_eq!(
        sha256,
        "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
    );

    let blake3 = calculate_blake3(data);
    assert!(!blake3.is_empty());
}
