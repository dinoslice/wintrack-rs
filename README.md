# Wintrack
A library for monitoring window related events on Windows.

> View API reference on [docs.rs](https://docs.rs/wintrack), and the crate page on [crates.io](https://crates.io/crates/wintrack).

## Features
- Listen for various window related events
    -  Foreground (active) window changed
    -  Window title or name changed
    -  Window became visible (unminimized / moved onscreen)
    -  Window became hidden (minimized / moved offscreen)
    -  New window was created
    -  Window was destroyed or closed
    -  Window was moved or resized
-  Define callback that will be called when event is received
-  Callback includes snapshot of window's state at time of event
-  snapshot has title, rect, executable, etc.
- Safe wrapper over Win32 API & robust error handling

## Demo
Using a channel to receive messages:
```rust
use std::sync::mpsc;
use wintrack::WindowEventKind;

wintrack::try_hook().expect("hook should not be set yet");

let (tx, rx) = mpsc::channel();

wintrack::set_callback(Box::new(move |event| {
    let snapshot_exe = event.snapshot.executable.file_name();
    let is_firefox = snapshot_exe == Some(OsStr::new("firefox.exe"));
    // only monitor name change events from Firefox
    // (this checks when the tab changes)
    if is_firefox && event.kind == WindowEventKind::WindowNameChanged {
        // send the event to the main thread
        let res = tx.send(event.snapshot);
        if let Err(err) = res {
            // ...
        }
    }
}));

while let Ok(browser_snapshot) = rx.recv() {
    println!("Your active Firefox tab changed to {}.", browser_snapshot.title);
}
```