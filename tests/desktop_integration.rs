//! Window, handler and message-loop round trips on a message-only window.

use std::cell::Cell;
use std::rc::Rc;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use windows_erg::desktop::{
    WindowBuilder, WindowClass, WindowHandle, WindowHandler, msg, post_quit, run_message_loop,
};

const WM_PING: u32 = msg::WM_APP + 1;

struct Recorder {
    seen: Rc<Cell<Option<(usize, isize)>>>,
    dropped: Arc<AtomicBool>,
}

impl WindowHandler for Recorder {
    fn handle(&self, _: WindowHandle, msg: u32, wparam: usize, lparam: isize) -> Option<isize> {
        if msg == WM_PING {
            self.seen.set(Some((wparam, lparam)));
            post_quit(7);
            return Some(0);
        }
        None
    }
}

impl Drop for Recorder {
    fn drop(&mut self) {
        self.dropped.store(true, Ordering::SeqCst);
    }
}

#[test]
fn a_message_posted_from_another_thread_reaches_the_handler() {
    let class = WindowClass::builder("windows_erg_test_ping")
        .register()
        .expect("register");
    let seen = Rc::new(Cell::new(None));
    let dropped = Arc::new(AtomicBool::new(false));
    let window = WindowBuilder::new(&class)
        .message_only()
        .create(Box::new(Recorder {
            seen: Rc::clone(&seen),
            dropped: Arc::clone(&dropped),
        }))
        .expect("create");

    let poster = window.handle().poster();
    std::thread::spawn(move || poster.post(WM_PING, 42, -3).expect("post"))
        .join()
        .expect("join");

    assert_eq!(run_message_loop(None), 7);
    assert_eq!(seen.get(), Some((42, -3)));

    assert!(!dropped.load(Ordering::SeqCst));
    drop(window);
    assert!(
        dropped.load(Ordering::SeqCst),
        "the handler is freed with the window"
    );
}

#[test]
fn posting_to_a_destroyed_window_fails() {
    let class = WindowClass::builder("windows_erg_test_gone")
        .register()
        .expect("register");
    let window = WindowBuilder::new(&class)
        .message_only()
        .create(Box::new(Recorder {
            seen: Rc::new(Cell::new(None)),
            dropped: Arc::new(AtomicBool::new(false)),
        }))
        .expect("create");
    let poster = window.handle().poster();
    drop(window);
    assert!(poster.post(WM_PING, 0, 0).is_err());
}
