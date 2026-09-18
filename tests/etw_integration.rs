#![cfg(windows)]

use std::thread;
use std::time::Duration;
use windows::core::GUID;
use windows_erg::error::{Error, EtwError};
use windows_erg::etw::{DecodedEvent, EventTrace, SystemProvider, TraceEvent};

fn build_trace(name: &str) -> windows_erg::Result<EventTrace> {
    EventTrace::builder(name)
        .system_provider(SystemProvider::Process)
        .buffer_size(128)
        .min_buffers(4)
        .max_buffers(16)
        .channel_capacity(4096)
        .start()
}

#[test]
#[ignore = "requires Administrator privileges and ETW kernel session access"]
fn etw_start_stop_lifecycle_raw_stream() -> windows_erg::Result<()> {
    let mut trace = build_trace("EtwIntegrationRaw")?;

    thread::sleep(Duration::from_millis(250));

    let mut events: Vec<TraceEvent> = Vec::with_capacity(128);
    let _count = trace.next_batch(&mut events)?;

    trace.stop()?;
    Ok(())
}

#[test]
#[ignore = "requires Administrator privileges and ETW kernel session access"]
fn etw_decoded_stream_batch_drain() -> windows_erg::Result<()> {
    let mut trace = EventTrace::builder("EtwIntegrationDecoded")
        .system_provider(SystemProvider::Process)
        .with_decoded_stream()
        .with_detailed_events()
        .start()?;

    thread::sleep(Duration::from_millis(250));

    let mut decoded: Vec<DecodedEvent> = Vec::with_capacity(128);
    let _count = trace.next_batch_decoded(&mut decoded)?;

    trace.stop()?;
    Ok(())
}

#[test]
#[ignore = "requires Administrator privileges and ETW kernel session access"]
fn etw_both_streams_can_drain_independently() -> windows_erg::Result<()> {
    let mut trace = EventTrace::builder("EtwIntegrationBoth")
        .system_provider(SystemProvider::Process)
        .with_both_streams()
        .start()?;

    thread::sleep(Duration::from_millis(250));

    let mut raw: Vec<TraceEvent> = Vec::with_capacity(128);
    let mut decoded: Vec<DecodedEvent> = Vec::with_capacity(128);

    let _raw_count = trace.next_batch(&mut raw)?;
    let _decoded_count = trace.next_batch_decoded(&mut decoded)?;

    trace.stop()?;
    Ok(())
}

#[test]
fn etw_rejects_mixed_kernel_and_user_mode_providers() {
    let result = EventTrace::builder("EtwIntegrationMixed")
        .system_provider(SystemProvider::Process)
        .user_provider(GUID::zeroed())
        .start();

    match result {
        Err(Error::Etw(EtwError::SessionStartFailed(e))) => {
            assert!(e.reason.contains("Cannot mix kernel system providers"));
        }
        _ => panic!("expected SessionStartFailed"),
    }
}

#[test]
#[ignore = "requires Administrator privileges and ETW kernel session access"]
fn etw_private_system_logger_sessions_can_run_concurrently() -> windows_erg::Result<()> {
    // Two named kernel sessions at once — impossible before `private_system_logger`,
    // since unadorned kernel providers are forced onto the single shared
    // "NT Kernel Logger" name and the second `StartTraceW` would collide with it.
    let guid_a = GUID::from_u128(0x1111_1111_1111_1111_1111_1111_1111_1111);
    let guid_b = GUID::from_u128(0x2222_2222_2222_2222_2222_2222_2222_2222);

    let mut trace_a = EventTrace::builder("EtwIntegrationPrivateA")
        .system_provider(SystemProvider::Process)
        .private_system_logger(guid_a)
        .start()?;
    assert_eq!(trace_a.name(), "EtwIntegrationPrivateA");
    assert!(trace_a.is_running());

    let mut trace_b = EventTrace::builder("EtwIntegrationPrivateB")
        .system_provider(SystemProvider::ImageLoad)
        .private_system_logger(guid_b)
        .start()?;
    assert_eq!(trace_b.name(), "EtwIntegrationPrivateB");
    assert!(trace_b.is_running());

    thread::sleep(Duration::from_millis(100));

    let mut events: Vec<TraceEvent> = Vec::with_capacity(16);
    let _ = trace_a.next_batch(&mut events)?;
    let _ = trace_b.next_batch(&mut events)?;

    trace_a.stop()?;
    trace_b.stop()?;
    Ok(())
}

#[test]
#[ignore = "requires a registered user-mode provider GUID and machine-specific provider ACLs"]
fn etw_user_mode_provider_startup_smoke() -> windows_erg::Result<()> {
    // Microsoft-Windows-DotNETRuntime
    let provider = GUID::from_u128(0xe13c0d23_ccbc_4e12_931b_d9cc2eee27e4);
    let result = EventTrace::builder("EtwIntegrationUserMode")
        .user_provider(provider)
        .with_cpu_samples()
        .start();

    match result {
        Ok(mut trace) => {
            thread::sleep(Duration::from_millis(250));
            let mut events: Vec<TraceEvent> = Vec::with_capacity(128);
            let _ = trace.next_batch(&mut events)?;
            trace.stop()?;
            Ok(())
        }
        Err(Error::Etw(EtwError::ProviderEnableFailed(_))) => Ok(()),
        Err(Error::Etw(EtwError::SessionStartFailed(_))) => Ok(()),
        Err(e) => Err(e),
    }
}
