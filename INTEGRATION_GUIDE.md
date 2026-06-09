# Tamandua Core - Integration Guide

## Quick Start: Updating the Desktop Agent

### Step 1: Add Dependency

In `apps/tamandua_agent/Cargo.toml`, add:

```toml
[dependencies]
# Tamandua Core Library
tamandua-core = { path = "../../libs/tamandua-core", features = ["full"] }

# ... rest of dependencies
```

### Step 2: Replace Imports

Old code:
```rust
// Local modules
use crate::telemetry::TelemetryManager;
use crate::detection::DetectionEngine;
use crate::response::ResponseExecutor;
```

New code:
```rust
// Use shared library
use tamandua_core::telemetry::TelemetryManager;
use tamandua_core::detection::DetectionEngine;
use tamandua_core::response::ResponseExecutor;
use tamandua_core::{AgentConfig, TamanduaCore};
```

### Step 3: Simplify Main

```rust
use tamandua_core::{AgentConfig, TamanduaCore};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize logging
    tracing_subscriber::fmt::init();

    // Load configuration
    let config = AgentConfig::from_file("config.toml")
        .or_else(|_| AgentConfig::from_env())?;

    // Create and start agent
    let mut agent = TamanduaCore::new(config).await?;
    agent.start().await?;

    // Run until shutdown
    tokio::signal::ctrl_c().await?;
    agent.stop().await?;

    Ok(())
}
```

### Step 4: Remove Duplicate Code

You can now remove these modules from `apps/tamandua_agent/src/`:
- `telemetry/mod.rs` (use `tamandua_core::telemetry`)
- `detection/engine.rs` (use `tamandua_core::detection`)
- `response/executor.rs` (use `tamandua_core::response`)
- `transport/websocket.rs` (use `tamandua_core::transport`)

Keep platform-specific collectors that aren't in the core library yet:
- Windows ETW collector
- Linux auditd collector
- macOS FSEvents collector

## Mobile Integration

### iOS (Swift)

#### 1. Add Rust Library to Xcode

```bash
# Build for iOS
cd libs/tamandua-core
cargo build --release --target aarch64-apple-ios --features mobile

# Create bridging header
cat > TamanduaCore-Bridging-Header.h <<EOF
#ifndef TamanduaCore_Bridging_Header_h
#define TamanduaCore_Bridging_Header_h

#include "tamandua_core.h"

#endif
EOF
```

#### 2. Create Swift Wrapper

```swift
// TamanduaAgent.swift
import Foundation

class TamanduaAgent {
    private var agentPtr: OpaquePointer?

    init() {
        agentPtr = tamandua_agent_new()
    }

    deinit {
        if let ptr = agentPtr {
            tamandua_agent_free(ptr)
        }
    }

    func start() -> Bool {
        guard let ptr = agentPtr else { return false }
        return tamandua_agent_start(ptr) == TamanduaResult_Ok
    }

    func stop() -> Bool {
        guard let ptr = agentPtr else { return false }
        return tamandua_agent_stop(ptr) == TamanduaResult_Ok
    }

    func status() -> String? {
        guard let ptr = agentPtr else { return nil }
        guard let cString = tamandua_agent_status(ptr) else { return nil }
        let status = String(cString: cString)
        tamandua_string_free(UnsafeMutablePointer(mutating: cString))
        return status
    }

    func configure(key: String, value: String) -> Bool {
        guard let ptr = agentPtr else { return false }
        return key.withCString { keyPtr in
            value.withCString { valuePtr in
                tamandua_agent_set_config(ptr, keyPtr, valuePtr) == TamanduaResult_Ok
            }
        }
    }
}
```

#### 3. Use in iOS App

```swift
// AppDelegate.swift
class AppDelegate: UIResponder, UIApplicationDelegate {
    var agent: TamanduaAgent?

    func application(_ application: UIApplication,
                     didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]?) -> Bool {
        agent = TamanduaAgent()
        agent?.configure(key: "agent_id", value: UIDevice.current.identifierForVendor?.uuidString ?? "unknown")
        agent?.configure(key: "server_url", value: "wss://your-backend.com/socket/agent")
        agent?.start()
        return true
    }

    func applicationWillTerminate(_ application: UIApplication) {
        agent?.stop()
    }

    func applicationDidEnterBackground(_ application: UIApplication) {
        // iOS will suspend the agent automatically
    }
}
```

### Android (Kotlin)

#### 1. Build Android Library

```bash
# Build for Android
cd libs/tamandua-core

# Install Android NDK toolchain
rustup target add aarch64-linux-android

# Build
cargo build --release --target aarch64-linux-android --features mobile

# Copy library to Android project
cp target/aarch64-linux-android/release/libtamandua_core.so \
   android-app/app/src/main/jniLibs/arm64-v8a/
```

#### 2. Create JNI Wrapper

```kotlin
// TamanduaAgent.kt
package com.tamandua.edr

class TamanduaAgent {
    private var nativePtr: Long = 0

    init {
        System.loadLibrary("tamandua_core")
        nativePtr = nativeNew()
    }

    fun start(): Boolean {
        return nativeStart(nativePtr)
    }

    fun stop(): Boolean {
        return nativeStop(nativePtr)
    }

    fun status(): String? {
        return nativeStatus(nativePtr)
    }

    fun configure(key: String, value: String): Boolean {
        return nativeSetConfig(nativePtr, key, value)
    }

    protected fun finalize() {
        if (nativePtr != 0L) {
            nativeFree(nativePtr)
            nativePtr = 0
        }
    }

    private external fun nativeNew(): Long
    private external fun nativeStart(ptr: Long): Boolean
    private external fun nativeStop(ptr: Long): Boolean
    private external fun nativeStatus(ptr: Long): String?
    private external fun nativeSetConfig(ptr: Long, key: String, value: String): Boolean
    private external fun nativeFree(ptr: Long)
}
```

#### 3. Create Android Service

```kotlin
// EDRService.kt
package com.tamandua.edr

import android.app.Service
import android.content.Intent
import android.os.IBinder

class EDRService : Service() {
    private lateinit var agent: TamanduaAgent

    override fun onCreate() {
        super.onCreate()

        agent = TamanduaAgent()
        agent.configure("agent_id", getDeviceId())
        agent.configure("server_url", "wss://your-backend.com/socket/agent")
        agent.start()

        // Show foreground notification
        startForeground(1, createNotification())
    }

    override fun onDestroy() {
        agent.stop()
        super.onDestroy()
    }

    override fun onBind(intent: Intent?): IBinder? = null

    private fun getDeviceId(): String {
        return android.provider.Settings.Secure.getString(
            contentResolver,
            android.provider.Settings.Secure.ANDROID_ID
        )
    }

    private fun createNotification(): Notification {
        // Create notification for foreground service
        // ...
    }
}
```

#### 4. Register in Manifest

```xml
<!-- AndroidManifest.xml -->
<manifest>
    <uses-permission android:name="android.permission.INTERNET" />
    <uses-permission android:name="android.permission.FOREGROUND_SERVICE" />

    <application>
        <service
            android:name=".EDRService"
            android:enabled="true"
            android:exported="false"
            android:foregroundServiceType="dataSync" />
    </application>
</manifest>
```

## Embedded Integration (Raspberry Pi)

### Cross-Compilation

```bash
# Install ARM toolchain
rustup target add armv7-unknown-linux-gnueabihf

# Build for Raspberry Pi
cd libs/tamandua-core
cargo build --release \
    --target armv7-unknown-linux-gnueabihf \
    --features embedded

# Binary at: target/armv7-unknown-linux-gnueabihf/release/libtamandua_core.a
```

### Minimal Agent

```rust
// embedded_agent.rs
use tamandua_core::{AgentConfig, TamanduaCore};

#[tokio::main(flavor = "current_thread")]  // Single-threaded runtime
async fn main() -> anyhow::Result<()> {
    // Minimal configuration
    let mut config = AgentConfig::default();
    config.telemetry.enabled = true;
    config.telemetry.batch_size = 20;  // Smaller batches
    config.detection.entropy_analysis = true;
    config.detection.yara_rules_dir = None;  // No YARA (too memory-heavy)
    config.detection.ml_enabled = false;  // No ML
    config.response.enabled = false;  // Read-only mode

    let mut agent = TamanduaCore::new(config).await?;
    agent.start().await?;

    // Run forever
    loop {
        tokio::time::sleep(tokio::time::Duration::from_secs(60)).await;
    }
}
```

## Configuration Reference

### Full Configuration File

```toml
# config.toml

# Agent identity
agent_id = "agent-001"
server_url = "wss://backend.example.com/socket/agent"
auth_token = "your-jwt-token-here"
data_dir = "/var/lib/tamandua"
log_level = "info"

[telemetry]
enabled = true
batch_size = 100
batch_timeout_secs = 30
compression = true
collection_interval_ms = 1000
max_queue_size = 10000

[telemetry.collectors]
process = true
file = true
network = true
dns = true
registry = true  # Windows only
auth = true

[detection]
enabled = true
yara_rules_dir = "/etc/tamandua/yara_rules"
entropy_analysis = true
entropy_threshold = 7.2
ml_enabled = false
ml_model_path = "/etc/tamandua/model.onnx"
ml_threshold = 0.8
heuristics_enabled = true

[response]
enabled = true
allow_kill = true
allow_quarantine = true
quarantine_dir = "/var/lib/tamandua/quarantine"
allow_isolate = false
require_confirmation = false

[transport]
enabled = true
max_reconnect_attempts = 10
reconnect_backoff_secs = 5
heartbeat_interval_secs = 30
connection_timeout_secs = 10
tls_enabled = true
tls_cert_path = "/etc/tamandua/cert.pem"
tls_key_path = "/etc/tamandua/key.pem"
```

### Environment Variables

```bash
# Override config file settings
export TAMANDUA_AGENT_ID="agent-001"
export TAMANDUA_SERVER_URL="wss://backend.example.com/socket/agent"
export TAMANDUA_AUTH_TOKEN="your-jwt-token"
export TAMANDUA_DATA_DIR="/var/lib/tamandua"
export TAMANDUA_LOG_LEVEL="debug"
```

## Migration Checklist

### From Existing Agent to Core Library

- [ ] Add `tamandua-core` dependency to `Cargo.toml`
- [ ] Update imports to use `tamandua_core::*`
- [ ] Replace local `TelemetryManager` with `tamandua_core::telemetry::TelemetryManager`
- [ ] Replace local `DetectionEngine` with `tamandua_core::detection::DetectionEngine`
- [ ] Replace local `ResponseExecutor` with `tamandua_core::response::ResponseExecutor`
- [ ] Remove duplicate code (telemetry, detection, response modules)
- [ ] Keep platform-specific collectors (ETW, auditd, FSEvents)
- [ ] Update configuration to use `tamandua_core::AgentConfig`
- [ ] Update tests to use core library types
- [ ] Build and verify functionality

### Desktop Agent Specific

- [ ] Keep Windows ETW collector (not in core yet)
- [ ] Keep Linux auditd integration (not in core yet)
- [ ] Keep macOS FSEvents collector (not in core yet)
- [ ] Keep YARA rule files in `priv/yara_rules/`
- [ ] Keep Sigma rule files in `priv/sigma_rules/`
- [ ] Update systemd/Windows service integration

## Testing

### Unit Tests

```bash
cd libs/tamandua-core

# Run all tests
cargo test --all-features

# Run specific module tests
cargo test --test integration_test
cargo test platform::tests
cargo test detection::tests

# Run with logging
RUST_LOG=debug cargo test
```

### Integration Tests

```bash
# Desktop agent
cd apps/tamandua_agent
cargo test --features yara,ml

# Mobile (iOS simulator)
cargo build --target x86_64-apple-ios --features mobile
cargo test --target x86_64-apple-ios --features mobile

# Embedded (Raspberry Pi)
cargo test --target armv7-unknown-linux-gnueabihf --features embedded
```

### Platform-Specific Tests

```bash
# Linux
cargo test --target x86_64-unknown-linux-gnu platform::linux

# macOS
cargo test --target x86_64-apple-darwin platform::macos

# Windows
cargo test --target x86_64-pc-windows-msvc platform::windows
```

## Troubleshooting

### Build Issues

**Problem**: YARA not found
```bash
# Solution: Install YARA development libraries
# Ubuntu/Debian
sudo apt-get install libyara-dev

# macOS
brew install yara

# Or disable YARA
cargo build --no-default-features --features telemetry,response,transport
```

**Problem**: Cross-compilation fails
```bash
# Solution: Install target toolchain
rustup target add aarch64-linux-android
rustup target add aarch64-apple-ios
rustup target add armv7-unknown-linux-gnueabihf
```

### Runtime Issues

**Problem**: Agent won't connect to backend
```bash
# Check WebSocket URL
export TAMANDUA_SERVER_URL="wss://your-backend.com/socket/agent"

# Check authentication token
export TAMANDUA_AUTH_TOKEN="your-valid-jwt-token"

# Enable debug logging
export RUST_LOG=tamandua_core::transport=debug
```

**Problem**: High memory usage
```bash
# Reduce queue sizes
export TAMANDUA_TELEMETRY_MAX_QUEUE_SIZE=1000
export TAMANDUA_TELEMETRY_BATCH_SIZE=50

# Disable ML
export TAMANDUA_DETECTION_ML_ENABLED=false
```

## Support

For issues or questions:
- GitHub Issues: https://github.com/treant-lab/tamandua-core/issues
- Documentation: https://docs.treantlab.org
- Community: https://community.treantlab.org

## Next Steps

1. Integrate with desktop agent: `apps/tamandua_agent`
2. Build mobile apps (iOS/Android)
3. Deploy to embedded devices
4. Contribute platform-specific improvements
