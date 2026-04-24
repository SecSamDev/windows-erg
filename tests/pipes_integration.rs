#![cfg(windows)]

use std::io::{Read, Write};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use windows_erg::pipes::{
    AnonymousPipeBuilder, NamedPipeClientBuilder, NamedPipeOpenMode, NamedPipePoller,
    NamedPipeServerBuilder, NamedPipeType, PipeName, PipeSecurityOptions, Wait, list,
};
use windows_erg::security::{AccessMask, Ace, AceType, Dacl, SecurityDescriptor, Sid};
use windows_erg::{
    Error,
    error::{OtherError, PipeError},
};

fn io_to_error(context: &'static str, err: std::io::Error) -> Error {
    Error::Other(OtherError::new(format!("{}: {}", context, err)))
}

fn unique_pipe_name(prefix: &str) -> PipeName {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::from_secs(0))
        .as_nanos();
    PipeName::new(format!(r"\\.\pipe\windows-erg-{}-{}", prefix, nanos))
        .expect("valid unique pipe name")
}

fn pipe_relative_name(pipe_name: &PipeName) -> &str {
    pipe_name
        .as_str()
        .strip_prefix(PipeName::PREFIX)
        .expect("pipe name should use canonical prefix")
}

fn wait_for_pipe_presence(pipe_name: &PipeName, expected_present: bool) -> windows_erg::Result<()> {
    for _ in 0..20 {
        let present = list()?.iter().any(|pipe| pipe.pipe_name == *pipe_name);
        if present == expected_present {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(25));
    }

    panic!(
        "pipe presence for '{}' did not reach expected state {}",
        pipe_name, expected_present
    );
}

#[test]
fn named_pipe_server_client_roundtrip() -> windows_erg::Result<()> {
    let pipe_name = unique_pipe_name("roundtrip");

    let server_cfg = NamedPipeServerBuilder::new()
        .pipe_name(pipe_name.clone())
        .open_mode(NamedPipeOpenMode::Duplex)
        .pipe_type(NamedPipeType::Byte)
        .build()?;

    let client_cfg = NamedPipeClientBuilder::new()
        .pipe_name(pipe_name.clone())
        .open_mode(NamedPipeOpenMode::Duplex)
        .connect_timeout(Duration::from_secs(3))
        .build()?;

    let server_thread = thread::spawn(move || -> windows_erg::Result<Vec<u8>> {
        let mut server = server_cfg.create()?;
        server.connect()?;

        let mut recv = [0u8; 32];
        let read = server.read(&mut recv).expect("server read succeeds");
        server.write_all(b"pong").expect("server write succeeds");
        server.disconnect()?;

        Ok(recv[..read].to_vec())
    });

    thread::sleep(Duration::from_millis(30));

    let mut client = client_cfg.connect()?;
    client
        .write_all(b"ping")
        .map_err(|e| io_to_error("client write", e))?;

    let mut out = [0u8; 16];
    let count = client
        .read(&mut out)
        .map_err(|e| io_to_error("client read", e))?;

    let server_payload = server_thread
        .join()
        .expect("server thread should not panic")?;

    assert_eq!(server_payload, b"ping");
    assert_eq!(&out[..count], b"pong");
    Ok(())
}

#[test]
fn named_pipe_list_includes_created_pipe() -> windows_erg::Result<()> {
    let pipe_name = unique_pipe_name("list");

    let server_cfg = NamedPipeServerBuilder::new()
        .pipe_name(pipe_name.clone())
        .open_mode(NamedPipeOpenMode::Duplex)
        .pipe_type(NamedPipeType::Byte)
        .build()?;

    let _server = server_cfg.create()?;
    wait_for_pipe_presence(&pipe_name, true)?;

    let pipes = list()?;
    let pipe_info = pipes
        .iter()
        .find(|pipe| pipe.pipe_name == pipe_name)
        .expect("created named pipe should be discoverable");

    assert_eq!(pipe_info.relative_name, pipe_relative_name(&pipe_name));
    assert_eq!(pipe_info.pipe_name.as_str(), pipe_name.as_str());
    assert!(pipe_info.local_info.is_none());

    let local_info = windows_erg::pipes::query_local_info(&pipe_name)?;
    assert!(local_info.current_instances >= 1);

    Ok(())
}

#[test]
fn named_pipe_interval_poller_detects_changes() -> windows_erg::Result<()> {
    let pipe_name = unique_pipe_name("interval-poller");

    let server_cfg = NamedPipeServerBuilder::new()
        .pipe_name(pipe_name.clone())
        .open_mode(NamedPipeOpenMode::Duplex)
        .pipe_type(NamedPipeType::Byte)
        .build()?;

    let server_thread = thread::spawn(move || -> windows_erg::Result<()> {
        thread::sleep(Duration::from_millis(40));
        let server = server_cfg.create()?;
        thread::sleep(Duration::from_millis(120));
        drop(server);
        Ok(())
    });

    let rounds = windows_erg::pipes::poll_interval(12, Duration::from_millis(25))?;
    server_thread
        .join()
        .expect("server thread should not panic")?;

    let mut appeared = false;
    let mut removed = false;
    for changes in rounds {
        for change in changes {
            match change {
                windows_erg::pipes::NamedPipeChange::Appeared(info)
                    if info.pipe_name == pipe_name =>
                {
                    appeared = true;
                }
                windows_erg::pipes::NamedPipeChange::Removed(info)
                    if info.pipe_name == pipe_name =>
                {
                    removed = true;
                }
                _ => {}
            }
        }
    }

    assert!(appeared, "interval poller should report pipe appearance");
    assert!(removed, "interval poller should report pipe removal");

    Ok(())
}

#[test]
fn named_pipe_poller_detects_pipe_appearance_and_removal() -> windows_erg::Result<()> {
    let pipe_name = unique_pipe_name("poller");
    let mut poller = NamedPipePoller::new();
    poller.seed()?;

    let server_cfg = NamedPipeServerBuilder::new()
        .pipe_name(pipe_name.clone())
        .open_mode(NamedPipeOpenMode::Duplex)
        .pipe_type(NamedPipeType::Byte)
        .build()?;

    let server = server_cfg.create()?;
    wait_for_pipe_presence(&pipe_name, true)?;

    let mut appeared = false;
    for _ in 0..20 {
        let changes = poller.poll()?;
        if changes.iter().any(|change| {
            matches!(
                change,
                windows_erg::pipes::NamedPipeChange::Appeared(info) if info.pipe_name == pipe_name
            )
        }) {
            appeared = true;
            break;
        }
        thread::sleep(Duration::from_millis(25));
    }
    assert!(appeared, "poller should report pipe appearance");

    drop(server);
    wait_for_pipe_presence(&pipe_name, false)?;

    let mut removed = false;
    for _ in 0..20 {
        let changes = poller.poll()?;
        if changes.iter().any(|change| {
            matches!(
                change,
                windows_erg::pipes::NamedPipeChange::Removed(info) if info.pipe_name == pipe_name
            )
        }) {
            removed = true;
            break;
        }
        thread::sleep(Duration::from_millis(25));
    }
    assert!(removed, "poller should report pipe removal");

    Ok(())
}

#[test]
fn anonymous_pipe_roundtrip() -> windows_erg::Result<()> {
    let (mut reader, mut writer) = AnonymousPipeBuilder::new()
        .buffer_size(2048)
        .build()
        .create()?;

    writer
        .write_all(b"anonymous-test")
        .map_err(|e| io_to_error("anonymous writer write", e))?;

    let mut out = [0u8; 64];
    let count = reader
        .read(&mut out)
        .map_err(|e| io_to_error("anonymous reader read", e))?;
    assert_eq!(&out[..count], b"anonymous-test");
    Ok(())
}

#[test]
fn create_pipe_with_security_descriptor() -> windows_erg::Result<()> {
    let everyone = Sid::parse("S-1-1-0")?;
    let dacl = Dacl::from_entries(vec![Ace::new(
        everyone,
        AceType::Allow,
        AccessMask::from_bits(0x1F01FF),
    )]);
    let descriptor = SecurityDescriptor::new().with_dacl(dacl);

    let options = PipeSecurityOptions::new()
        .inherit_handle(true)
        .security_descriptor(descriptor);

    let pipe_name = unique_pipe_name("security");
    let cfg = NamedPipeServerBuilder::new()
        .pipe_name(pipe_name)
        .open_mode(NamedPipeOpenMode::Duplex)
        .pipe_type(NamedPipeType::Byte)
        .security(options)
        .build()?;

    let _server = cfg.create()?;
    Ok(())
}

#[test]
fn connect_missing_pipe_returns_connect_error() -> windows_erg::Result<()> {
    let pipe_name = unique_pipe_name("missing");
    let client_cfg = NamedPipeClientBuilder::new()
        .pipe_name(pipe_name)
        .open_mode(NamedPipeOpenMode::Duplex)
        .connect_timeout(Duration::from_millis(150))
        .build()?;

    let err = client_cfg
        .connect()
        .expect_err("connect should fail when no server exists");

    match err {
        Error::Pipe(PipeError::Connect(connect_err)) => {
            assert!(connect_err.error_code.is_some());
        }
        other => panic!("expected Pipe::Connect error, got {other:?}"),
    }

    Ok(())
}

#[test]
fn connect_when_all_instances_busy_returns_timeout_or_busy() -> windows_erg::Result<()> {
    let pipe_name = unique_pipe_name("busy-timeout");

    let server_cfg = NamedPipeServerBuilder::new()
        .pipe_name(pipe_name.clone())
        .open_mode(NamedPipeOpenMode::Duplex)
        .pipe_type(NamedPipeType::Byte)
        .max_instances(1)
        .build()?;

    let first_client_cfg = NamedPipeClientBuilder::new()
        .pipe_name(pipe_name.clone())
        .open_mode(NamedPipeOpenMode::Duplex)
        .connect_timeout(Duration::from_secs(2))
        .build()?;

    let second_client_cfg = NamedPipeClientBuilder::new()
        .pipe_name(pipe_name)
        .open_mode(NamedPipeOpenMode::Duplex)
        .connect_timeout(Duration::from_millis(150))
        .build()?;

    let server_thread = thread::spawn(move || -> windows_erg::Result<()> {
        let server = server_cfg.create()?;
        server.connect()?;
        thread::sleep(Duration::from_millis(500));
        server.disconnect()?;
        Ok(())
    });

    thread::sleep(Duration::from_millis(30));
    let first_client = first_client_cfg.connect()?;

    let err = second_client_cfg
        .connect()
        .expect_err("second client should fail while only instance is busy");

    match err {
        Error::Pipe(PipeError::Timeout(timeout_err)) => {
            assert_eq!(timeout_err.operation.as_ref(), "connect");
        }
        Error::Pipe(PipeError::Connect(connect_err)) => {
            assert_eq!(connect_err.error_code, Some(231));
        }
        other => panic!("expected Pipe::Timeout or Pipe::Connect(busy), got {other:?}"),
    }

    drop(first_client);
    server_thread
        .join()
        .expect("server thread should not panic")?;

    Ok(())
}

#[test]
fn server_connect_with_timeout_succeeds() -> windows_erg::Result<()> {
    let pipe_name = unique_pipe_name("connect-timeout-success");

    let server_cfg = NamedPipeServerBuilder::new()
        .pipe_name(pipe_name.clone())
        .open_mode(NamedPipeOpenMode::Duplex)
        .pipe_type(NamedPipeType::Byte)
        .build()?;

    let client_cfg = NamedPipeClientBuilder::new()
        .pipe_name(pipe_name)
        .open_mode(NamedPipeOpenMode::Duplex)
        .connect_timeout(Duration::from_secs(2))
        .build()?;

    let server_thread = thread::spawn(move || -> windows_erg::Result<()> {
        let server = server_cfg.create()?;
        server.connect_with_timeout(Duration::from_secs(2))?;
        server.disconnect()?;
        Ok(())
    });

    thread::sleep(Duration::from_millis(30));
    let _client = client_cfg.connect()?;

    server_thread
        .join()
        .expect("server thread should not panic")?;

    Ok(())
}

#[test]
fn server_connect_with_timeout_times_out() -> windows_erg::Result<()> {
    let pipe_name = unique_pipe_name("connect-timeout-fail");

    let server_cfg = NamedPipeServerBuilder::new()
        .pipe_name(pipe_name)
        .open_mode(NamedPipeOpenMode::Duplex)
        .pipe_type(NamedPipeType::Byte)
        .build()?;

    let server = server_cfg.create()?;
    let err = server
        .connect_with_timeout(Duration::from_millis(75))
        .expect_err("connect_with_timeout should time out without a client");

    match err {
        Error::Pipe(PipeError::Timeout(timeout_err)) => {
            assert_eq!(timeout_err.operation.as_ref(), "connect");
        }
        other => panic!("expected Pipe::Timeout error, got {other:?}"),
    }

    Ok(())
}

#[test]
fn server_connect_with_wait_interrupted() -> windows_erg::Result<()> {
    let pipe_name = unique_pipe_name("connect-wait-interrupted");

    let server_cfg = NamedPipeServerBuilder::new()
        .pipe_name(pipe_name)
        .open_mode(NamedPipeOpenMode::Duplex)
        .pipe_type(NamedPipeType::Byte)
        .build()?;

    let server = server_cfg.create()?;
    let wait = Wait::manual_reset(false)?;
    wait.set()?;
    let err = server
        .connect_with_wait_timeout(&wait, Duration::from_secs(3))
        .expect_err("connect_with_wait_timeout should be interrupted by wait signal");

    match err {
        Error::Pipe(PipeError::Connect(connect_err)) => {
            let context = connect_err
                .context
                .as_ref()
                .map(|c| c.as_ref())
                .unwrap_or_default();
            assert!(context.contains("interrupted"));
        }
        other => panic!("expected Pipe::Connect error, got {other:?}"),
    }

    Ok(())
}

#[test]
fn server_connect_with_wait_object_interrupted() -> windows_erg::Result<()> {
    let pipe_name = unique_pipe_name("connect-wait-object-interrupted");

    let server_cfg = NamedPipeServerBuilder::new()
        .pipe_name(pipe_name)
        .open_mode(NamedPipeOpenMode::Duplex)
        .pipe_type(NamedPipeType::Byte)
        .build()?;

    let server = server_cfg.create()?;
    let wait = Wait::manual_reset(false)?;
    wait.set()?;

    let err = server
        .connect_with_wait(&wait)
        .expect_err("connect_with_wait should be interrupted by wait signal");

    match err {
        Error::Pipe(PipeError::Connect(connect_err)) => {
            let context = connect_err
                .context
                .as_ref()
                .map(|c| c.as_ref())
                .unwrap_or_default();
            assert!(context.contains("interrupted"));
        }
        other => panic!("expected Pipe::Connect error, got {other:?}"),
    }

    Ok(())
}
