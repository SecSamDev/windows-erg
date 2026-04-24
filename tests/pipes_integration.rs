#![cfg(windows)]

use std::io::{Read, Write};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use windows_erg::pipes::{
    AnonymousPipeBuilder, NamedPipeClientBuilder, NamedPipeOpenMode, NamedPipeServerBuilder,
    NamedPipeType, PipeName, PipeSecurityOptions, Wait,
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
fn anonymous_pipe_roundtrip() -> windows_erg::Result<()> {
    let (mut reader, mut writer) = AnonymousPipeBuilder::new().buffer_size(2048).build().create()?;

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
