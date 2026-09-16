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
fn client_admin_check_matches_the_client_token() -> windows_erg::Result<()> {
    let pipe_name = unique_pipe_name("client-admin");
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

    let server_thread = thread::spawn(move || -> windows_erg::Result<bool> {
        let mut server = server_cfg.create()?;
        server.connect()?;
        let mut byte = [0u8; 1];
        // Impersonation needs data read from the pipe first.
        server.read_exact(&mut byte).expect("server read succeeds");
        let is_admin = server.client_is_elevated_admin();
        server.write_all(b"k").expect("server write succeeds");
        server.disconnect()?;
        is_admin
    });

    thread::sleep(Duration::from_millis(30));
    let mut client = client_cfg.connect()?;
    client
        .write_all(b"?")
        .map_err(|e| io_to_error("client write", e))?;
    let mut ack = [0u8; 1];
    client
        .read_exact(&mut ack)
        .map_err(|e| io_to_error("client read", e))?;

    let is_admin = server_thread.join().expect("server thread")?;
    // Same process on both ends: the client token is this process's token.
    assert_eq!(is_admin, windows_erg::is_elevated()?);
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

fn byte_pipe_pair(
    prefix: &str,
) -> windows_erg::Result<(
    windows_erg::pipes::NamedPipeServer,
    windows_erg::pipes::NamedPipeClient,
)> {
    let pipe_name = unique_pipe_name(prefix);
    let server = NamedPipeServerBuilder::new()
        .pipe_name(pipe_name.clone())
        .open_mode(NamedPipeOpenMode::Duplex)
        .pipe_type(NamedPipeType::Byte)
        .build()?
        .create()?;
    let client_cfg = NamedPipeClientBuilder::new()
        .pipe_name(pipe_name)
        .open_mode(NamedPipeOpenMode::Duplex)
        .connect_timeout(Duration::from_secs(3))
        .build()?;
    let client = thread::spawn(move || client_cfg.connect());
    server.connect()?;
    let client = client.join().expect("client thread should not panic")?;
    Ok((server, client))
}

#[test]
fn server_reads_payload_larger_than_pipe_buffer() -> windows_erg::Result<()> {
    let (mut server, mut client) = byte_pipe_pair("large-payload")?;
    let payload: Vec<u8> = (0..300_000u32).map(|i| (i % 251) as u8).collect();
    let expected = payload.clone();

    let writer = thread::spawn(move || client.write_all(&payload));
    let mut received = vec![0u8; expected.len()];
    server
        .read_exact(&mut received)
        .map_err(|e| io_to_error("server read_exact", e))?;
    writer
        .join()
        .expect("writer thread should not panic")
        .map_err(|e| io_to_error("client write", e))?;

    assert_eq!(received, expected);
    Ok(())
}

#[test]
fn flushed_reply_survives_disconnect() -> windows_erg::Result<()> {
    let (mut server, mut client) = byte_pipe_pair("flush-disconnect")?;
    let reader = thread::spawn(move || {
        let mut reply = Vec::new();
        client.read_to_end(&mut reply).map(|_| reply)
    });

    server
        .write_all(&[7u8; 50_000])
        .map_err(|e| io_to_error("server write", e))?;
    server.flush().map_err(|e| io_to_error("server flush", e))?;
    server.disconnect()?;

    let reply = reader
        .join()
        .expect("reader thread should not panic")
        .map_err(|e| io_to_error("client read_to_end", e))?;
    assert_eq!(reply.len(), 50_000);
    Ok(())
}

#[test]
fn server_read_times_out_and_connection_stays_usable() -> windows_erg::Result<()> {
    let (mut server, mut client) = byte_pipe_pair("read-timeout")?;
    server.set_io_timeout(Some(Duration::from_millis(100)));

    let mut buf = [0u8; 4];
    let err = server
        .read(&mut buf)
        .expect_err("read without data should time out");
    assert_eq!(err.kind(), std::io::ErrorKind::TimedOut);

    client
        .write_all(b"late")
        .map_err(|e| io_to_error("client write", e))?;
    server
        .read_exact(&mut buf)
        .map_err(|e| io_to_error("server read after timeout", e))?;
    assert_eq!(&buf, b"late");
    Ok(())
}

#[test]
fn read_after_peer_closes_returns_end_of_stream() -> windows_erg::Result<()> {
    let (mut server, client) = byte_pipe_pair("peer-closed")?;
    drop(client);

    let mut buf = [0u8; 8];
    let read = server
        .read(&mut buf)
        .map_err(|e| io_to_error("server read", e))?;
    assert_eq!(read, 0);

    let err = server
        .write_all(b"x")
        .expect_err("write to a closed pipe should fail");
    assert_eq!(err.kind(), std::io::ErrorKind::BrokenPipe);
    Ok(())
}

#[test]
fn first_instance_refuses_an_existing_pipe_name() -> windows_erg::Result<()> {
    let pipe_name = unique_pipe_name("first-instance");
    let builder = || {
        NamedPipeServerBuilder::new()
            .pipe_name(pipe_name.clone())
            .open_mode(NamedPipeOpenMode::Duplex)
            .pipe_type(NamedPipeType::Byte)
            .max_instances(4)
    };

    let _squatter = builder().build()?.create()?;
    assert!(builder().first_instance(true).build()?.create().is_err());
    // Without the flag the second instance joins the existing pipe.
    let _second = builder().build()?.create()?;
    Ok(())
}

#[test]
fn client_connects_with_data_only_access() -> windows_erg::Result<()> {
    // SYSTEM and Administrators: full access. Everyone: read/write data only,
    // without FILE_CREATE_PIPE_INSTANCE.
    let full = AccessMask::from_bits(0x001F_01FF);
    let dacl = Dacl::from_entries(vec![
        Ace::new(Sid::parse("S-1-5-18")?, AceType::Allow, full),
        Ace::new(Sid::parse("S-1-5-32-544")?, AceType::Allow, full),
        Ace::new(
            Sid::parse("S-1-1-0")?,
            AceType::Allow,
            AccessMask::from_bits(0x0012_018B),
        ),
    ]);
    let pipe_name = unique_pipe_name("data-only");
    let mut server = NamedPipeServerBuilder::new()
        .pipe_name(pipe_name.clone())
        .open_mode(NamedPipeOpenMode::Duplex)
        .pipe_type(NamedPipeType::Byte)
        .first_instance(true)
        .security(
            PipeSecurityOptions::new()
                .security_descriptor(SecurityDescriptor::new().with_dacl(dacl)),
        )
        .build()?
        .create()?;

    let client_cfg = NamedPipeClientBuilder::new()
        .pipe_name(pipe_name)
        .open_mode(NamedPipeOpenMode::Duplex)
        .connect_timeout(Duration::from_secs(3))
        .build()?;
    let client = thread::spawn(move || -> windows_erg::Result<Vec<u8>> {
        let mut client = client_cfg.connect()?;
        client
            .write_all(b"hi")
            .map_err(|e| io_to_error("client write", e))?;
        let mut reply = [0u8; 2];
        client
            .read_exact(&mut reply)
            .map_err(|e| io_to_error("client read", e))?;
        Ok(reply.to_vec())
    });

    // Bounded: a refused client must fail the test, not hang it.
    if let Err(e) = server.connect_with_timeout(Duration::from_secs(5)) {
        let client_error = client.join().expect("client thread should not panic").err();
        panic!("no client connected ({e}); client error: {client_error:?}");
    }
    let mut request = [0u8; 2];
    server
        .read_exact(&mut request)
        .map_err(|e| io_to_error("server read", e))?;
    server
        .write_all(b"ok")
        .map_err(|e| io_to_error("server write", e))?;
    server.flush().map_err(|e| io_to_error("server flush", e))?;

    assert_eq!(&request, b"hi");
    assert_eq!(
        client.join().expect("client thread should not panic")?,
        b"ok"
    );
    Ok(())
}
