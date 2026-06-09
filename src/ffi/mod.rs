//! FFI (Foreign Function Interface) bindings
//!
//! Provides C-compatible API for mobile and embedded integrations.
//!
//! # iOS Swift Integration
//!
//! ```swift
//! import tamandua_core
//!
//! let config = tamandua_config_default()
//! let agent = tamandua_agent_new(config)
//! tamandua_agent_start(agent)
//! ```
//!
//! # Android Kotlin Integration
//!
//! ```kotlin
//! import com.tamandua.core.TamanduaAgent
//!
//! val agent = TamanduaAgent()
//! agent.start()
//! ```

use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_void};
use std::ptr;

#[cfg(target_os = "android")]
mod android;

#[cfg(target_os = "ios")]
mod ios;

/// FFI result code
#[repr(C)]
pub enum TamanduaResult {
    /// Success
    Ok = 0,
    /// Error
    Error = 1,
}

/// Opaque agent handle
#[repr(C)]
pub struct TamanduaAgent {
    _private: [u8; 0],
}

/// Create a new agent with default configuration
///
/// # Safety
///
/// The returned pointer must be freed with `tamandua_agent_free`.
#[no_mangle]
pub unsafe extern "C" fn tamandua_agent_new() -> *mut TamanduaAgent {
    // Simplified FFI implementation
    // In production, this would create actual TamanduaCore instance
    ptr::null_mut()
}

/// Start the agent
///
/// # Safety
///
/// `agent` must be a valid pointer from `tamandua_agent_new`.
#[no_mangle]
pub unsafe extern "C" fn tamandua_agent_start(agent: *mut TamanduaAgent) -> TamanduaResult {
    if agent.is_null() {
        return TamanduaResult::Error;
    }

    // In production, this would call agent.start()
    TamanduaResult::Ok
}

/// Stop the agent
///
/// # Safety
///
/// `agent` must be a valid pointer from `tamandua_agent_new`.
#[no_mangle]
pub unsafe extern "C" fn tamandua_agent_stop(agent: *mut TamanduaAgent) -> TamanduaResult {
    if agent.is_null() {
        return TamanduaResult::Error;
    }

    // In production, this would call agent.stop()
    TamanduaResult::Ok
}

/// Free the agent
///
/// # Safety
///
/// `agent` must be a valid pointer from `tamandua_agent_new`
/// and must not be used after this call.
#[no_mangle]
pub unsafe extern "C" fn tamandua_agent_free(agent: *mut TamanduaAgent) {
    if !agent.is_null() {
        // In production, this would properly drop the agent
        drop(Box::from_raw(agent as *mut u8));
    }
}

/// Set agent configuration value
///
/// # Safety
///
/// - `agent` must be a valid pointer
/// - `key` and `value` must be valid null-terminated C strings
#[no_mangle]
pub unsafe extern "C" fn tamandua_agent_set_config(
    agent: *mut TamanduaAgent,
    key: *const c_char,
    value: *const c_char,
) -> TamanduaResult {
    if agent.is_null() || key.is_null() || value.is_null() {
        return TamanduaResult::Error;
    }

    let _key = match CStr::from_ptr(key).to_str() {
        Ok(s) => s,
        Err(_) => return TamanduaResult::Error,
    };

    let _value = match CStr::from_ptr(value).to_str() {
        Ok(s) => s,
        Err(_) => return TamanduaResult::Error,
    };

    // In production, this would update agent config
    TamanduaResult::Ok
}

/// Get agent status as a JSON string
///
/// # Safety
///
/// - `agent` must be a valid pointer
/// - The returned string must be freed with `tamandua_string_free`
#[no_mangle]
pub unsafe extern "C" fn tamandua_agent_status(agent: *mut TamanduaAgent) -> *mut c_char {
    if agent.is_null() {
        return ptr::null_mut();
    }

    let status_json = r#"{"status":"running","uptime":0}"#;
    match CString::new(status_json) {
        Ok(s) => s.into_raw(),
        Err(_) => ptr::null_mut(),
    }
}

/// Free a string returned by Tamandua
///
/// # Safety
///
/// `s` must be a string returned by a Tamandua function
#[no_mangle]
pub unsafe extern "C" fn tamandua_string_free(s: *mut c_char) {
    if !s.is_null() {
        drop(CString::from_raw(s));
    }
}

/// Log a message from the mobile app
///
/// # Safety
///
/// `message` must be a valid null-terminated C string
#[no_mangle]
pub unsafe extern "C" fn tamandua_log(level: u32, message: *const c_char) {
    if message.is_null() {
        return;
    }

    if let Ok(msg) = CStr::from_ptr(message).to_str() {
        match level {
            0 => tracing::error!("{}", msg),
            1 => tracing::warn!("{}", msg),
            2 => tracing::info!("{}", msg),
            _ => tracing::debug!("{}", msg),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ffi_agent_lifecycle() {
        unsafe {
            let agent = tamandua_agent_new();
            assert!(!agent.is_null());

            let result = tamandua_agent_start(agent);
            assert!(matches!(result, TamanduaResult::Ok));

            let result = tamandua_agent_stop(agent);
            assert!(matches!(result, TamanduaResult::Ok));

            tamandua_agent_free(agent);
        }
    }
}
