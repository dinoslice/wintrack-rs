use std::panic;
use std::thread::JoinHandle;
use parking_lot::Mutex;
use windows::Win32::Foundation::{ERROR_INVALID_FUNCTION, ERROR_INVALID_PARAMETER, ERROR_INVALID_THREAD_ID, ERROR_INVALID_WINDOW_HANDLE, ERROR_MOD_NOT_FOUND, ERROR_PROC_NOT_FOUND, HWND, LPARAM, WPARAM};
use windows::core::{Error as WinErr, BOOL};
use windows::Win32::System::Threading::GetCurrentThreadId;
use windows::Win32::UI::Accessibility::{SetWinEventHook, HWINEVENTHOOK};
use windows::Win32::UI::WindowsAndMessaging::{GetMessageW, PostThreadMessageW, CHILDID_SELF, EVENT_OBJECT_CREATE, EVENT_OBJECT_DESTROY, EVENT_OBJECT_HIDE, EVENT_OBJECT_LOCATIONCHANGE, EVENT_OBJECT_NAMECHANGE, EVENT_OBJECT_SHOW, EVENT_SYSTEM_FOREGROUND, MSG, OBJECT_IDENTIFIER, OBJID_WINDOW, WINEVENT_OUTOFCONTEXT, WM_QUIT};
pub use window_info::WinThreadId;

mod window_info;
pub use window_info::*;

/// A window event.
/// 
/// Represents an event related to a window, like becoming foreground or title change,
/// along with a [snapshot](WindowSnapshot) of the window when the event occurred.
/// 
/// Most likely, you'll get a window event from the callback set by [`set_callback`](set_callback).
/// 
/// # Examples
/// ```no_run
/// # use window_events::{WindowEvent, WindowEventKind, WindowSnapshot};
/// window_events::set_callback(Box::new(|event: WindowEvent| {
///     // every event has a snapshot of the window's current state
///     let snapshot: WindowSnapshot = event.snapshot;
///     assert_eq!(snapshot.title, "Firefox");
///     assert_eq!(snapshot.class_name, "MozillaWindowClass");
/// 
///     // ... and the kind of event that caused it
///     if event.kind == WindowEventKind::ForegroundWindowChanged {
///         assert!(snapshot.is_foreground);
///     }
/// }));
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct WindowEvent {
    /// The specific type of event that occurred.
    pub kind: WindowEventKind,
    /// A snapshot of the window's properties when the event occurred. 
    pub snapshot: WindowSnapshot,
}

/// The kind of the event that occurred for a window.
/// 
/// Each corresponds to a [Windows event constant](https://learn.microsoft.com/en-us/windows/win32/winauto/event-constants). 
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub enum WindowEventKind {
    /// The foreground (active) window changed. ([`EVENT_SYSTEM_FOREGROUND`])
    ForegroundWindowChanged,
    /// The window title or name changed. ([`EVENT_OBJECT_NAMECHANGE`])
    WindowNameChanged,
    /// The window became visible (shown / unminimized / moved onscreen). ([`EVENT_OBJECT_SHOW`])
    WindowBecameVisible,
    /// The window became hidden (hidden / minimized / moved offscreen). ([`EVENT_OBJECT_HIDE`])
    WindowBecameHidden,
    /// A new window was created. ([`EVENT_OBJECT_CREATE`])
    WindowCreated,
    /// A window was destroyed or closed. ([`EVENT_OBJECT_DESTROY`])
    WindowDestroyed,
    /// A window was moved or resized. ([`EVENT_OBJECT_LOCATIONCHANGE`])
    WindowMovedOrResized,
}

impl WindowEventKind {
    pub(crate) const ALL: [Self; 7] = [
        Self::ForegroundWindowChanged,
        Self::WindowNameChanged,
        Self::WindowBecameVisible,
        Self::WindowBecameHidden,
        Self::WindowCreated,
        Self::WindowDestroyed,
        Self::WindowMovedOrResized,
    ];
    
    pub(crate) fn from_event_constant(event: u32) -> Option<Self> {
        let ret = match event {
            EVENT_SYSTEM_FOREGROUND => Some(Self::ForegroundWindowChanged),
            EVENT_OBJECT_NAMECHANGE => Some(Self::WindowNameChanged),
            EVENT_OBJECT_SHOW => Some(Self::WindowBecameVisible),
            EVENT_OBJECT_HIDE => Some(Self::WindowBecameHidden),
            EVENT_OBJECT_CREATE => Some(Self::WindowCreated),
            EVENT_OBJECT_DESTROY => Some(Self::WindowDestroyed),
            EVENT_OBJECT_LOCATIONCHANGE => Some(Self::WindowMovedOrResized),
            _ => None,
        };
        
        // FIXME: move this to a test
        if let Some(ret) = ret {
            debug_assert_eq!(ret.event_constant(), event);
        }
        
        ret
    }
    
    pub(crate) fn event_constant(self) -> u32 {
        match self {
            Self::ForegroundWindowChanged => EVENT_SYSTEM_FOREGROUND,
            Self::WindowNameChanged => EVENT_OBJECT_NAMECHANGE,
            Self::WindowBecameVisible => EVENT_OBJECT_SHOW,
            Self::WindowBecameHidden => EVENT_OBJECT_HIDE,
            Self::WindowCreated => EVENT_OBJECT_CREATE,
            Self::WindowDestroyed => EVENT_OBJECT_DESTROY,
            Self::WindowMovedOrResized => EVENT_OBJECT_LOCATIONCHANGE,
        }
    }
}

unsafe extern "system" fn win_event_proc(
    _h_win_event_hook: HWINEVENTHOOK,
    event: u32,
    hwnd: HWND,
    id_object: i32,
    id_child: i32,
    _dw_event_thread: u32,
    _dwms_event_time: u32,
) {
    if OBJECT_IDENTIFIER(id_object) == OBJID_WINDOW && id_child == CHILDID_SELF as _ {
        let Some(kind) = WindowEventKind::from_event_constant(event) else {
            return;
        };
        
        let snapshot = match WindowSnapshot::from_hwnd(hwnd) {
            Ok(snapshot) => snapshot,
            Err(_err) => {
                // eprintln!("{err}"); // TODO: log error!
                return;
            }
        };
        
        if let Some(callback) = &STATE.lock().callback {
            callback(WindowEvent { kind, snapshot });
        }
    }
}

/// A boxed closure/function pointer that provides [`WindowEvent`]s.
pub type WindowEventCallback = Box<dyn Fn(WindowEvent) + Send>;

struct WinHookState {
    pub callback: Option<WindowEventCallback>,
    pub thread: Option<(JoinHandle<Result<(), WinErr>>, WinThreadId)>,
}

static STATE: Mutex<WinHookState> = Mutex::new(WinHookState { callback: None, thread: None });

/// Error returned by [`try_hook`].
///
/// Most likely, this will be caused by attempting to hook when a hook is already set,
/// but in rare cases an error from the Win32 API may occur.
#[derive(Debug, thiserror::Error, Eq, PartialEq)]
pub enum TryHookError {
    /// A hook was already previously set by this process.
    /// To set another hook, first [unhook the previously set hook](unhook).
    #[error("Hook already set; no need to set it again.")]
    HookAlreadySet,
    /// Internal error from Win32 API.
    #[error("Failed to set hook: {0}")]
    FailedToSetHook(WinErr),
}

/// Attempts to install a hook for monitoring [window events](WindowEvent).
///
/// Near this call (either before or after), you probably want to call [`set_callback`] to do something whenever the hook receives an event.
/// Only one hook can be set at a time; attempting to set another hook will return [`TryHookError::HookAlreadySet`].
pub fn try_hook() -> Result<(), TryHookError> {
    let mut state = STATE.lock();

    if state.thread.is_some() {
        Err(TryHookError::HookAlreadySet)
    } else {
        match hook_inner() {
            Ok(thread_id) => {
                state.thread = Some(thread_id);

                Ok(())
            },
            Err(err) => Err(TryHookError::FailedToSetHook(err)),
        }
    }
}

fn hook_inner() -> Result<(JoinHandle<Result<(), WinErr>>, WinThreadId), WinErr> {
    let (tx, rx) = oneshot::channel();

    let handle = std::thread::spawn(move || {
        let event_const = WindowEventKind::ALL.map(WindowEventKind::event_constant);
        
        let min = *event_const.iter().min().expect("should be at least one event kind");
        let max = *event_const.iter().max().expect("should be at least one event kind");

        // SAFETY: callback signature is correct, callback cannot capture locals due to being a fn ptr,
        // event range is valid, thread will set up event loop
        let hook = unsafe {
            SetWinEventHook(min, max, None, Some(win_event_proc), 0, 0, WINEVENT_OUTOFCONTEXT)
        };

        let res = if hook.is_invalid() {
            match WinErr::from_win32() {
                err if err == WinErr::from(ERROR_INVALID_PARAMETER) => unreachable!("SetWinEventHook parameters should be correct"),
                err if err == WinErr::from(ERROR_MOD_NOT_FOUND) => unreachable!("hmodwineventproc is null, so never should trigger this error"),
                err if err == WinErr::from(ERROR_INVALID_THREAD_ID) => unreachable!("idthread is 0, so never should trigger this error"),
                err if err == WinErr::from(ERROR_INVALID_FUNCTION) => unreachable!("function should have right signature & calling abi"),
                err if err == WinErr::from(ERROR_PROC_NOT_FOUND) => unreachable!("not using a DLL"),
                err => Err(err)
            }
        } else {
            // SAFETY: always safe to call
            let thread_id = unsafe { GetCurrentThreadId() };
            
            Ok(WinThreadId::new(thread_id).expect("thread id should always be nonzero"))
        };

        tx.send(res).expect("rx should still exist");
        
        let mut msg = MSG::default();
        
        // SAFETY: msg is non-null & valid to write to (unique ptr due to &mut),
        // and thread has a message queue to read from
        match unsafe { GetMessageW(&mut msg, None, 0, 0) } {
            BOOL(0) => {
                assert_eq!(
                    msg.message, WM_QUIT,
                    // https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-getmessagew
                    "If the function retrieves a message other than WM_QUIT, the return value is nonzero."
                );
                
                Ok(())
            }
            BOOL(-1) => match WinErr::from_win32() {
                err if err == WinErr::from(ERROR_INVALID_WINDOW_HANDLE) => unreachable!("shouldn't trigger since hwnd is None"),
                err if err == WinErr::from(ERROR_INVALID_PARAMETER) => unreachable!("should be calling GetMessageW with correct params"),
                err => Err(err),
            },
            bool => unreachable!("message queue should not recv any other messages ({:?}, msg: {})", bool, msg.message),
        }
        
        // https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-unhookwinevent
        // "If the client's thread ends, the system automatically calls [UnhookWinEvent]"
    });

    rx.recv()
        .expect("should eventually recv a message")
        .map(|id| (handle, id))
}

/// Sets the callback called when a window event occurs.
///
/// This function is how you can define what should happen upon a window event.
/// Returns a previously set callback if it exists.
///
/// If you need to listen for the events in another location in your program,
/// or need to collect them, you might want to set up a [channel](std::sync::mpsc).
///
/// # Examples
/// Debug print all* events:
/// ```no_run
/// window_events::set_callback(Box::new(|evt| {
///     // ignore events from zero-sized windows or windows with no title
///     if evt.snapshot.rect.size() != (0, 0) && !evt.snapshot.title.is_empty() {
///         dbg!(evt.snapshot);
///     }
/// }));
/// ```
/// Using a channel:
/// ```no_run
/// # use std::ffi::OsStr;
/// # use window_events::WindowEventKind;
/// use std::sync::mpsc;
///
/// window_events::try_hook().expect("hook should not be set yet");
///
/// let (tx, rx) = mpsc::channel();
///
/// window_events::set_callback(Box::new(move |event| {
///     let snapshot_exe = event.snapshot.executable.file_name();
///     let is_firefox = snapshot_exe == Some(OsStr::new("firefox.exe"));
///
///     // only monitor name change events from Firefox
///     // (this checks when the tab changes)
///     if is_firefox && event.kind == WindowEventKind::WindowNameChanged {
///         // send the event to the main thread
///         let res = tx.send(event.snapshot);
///
///         if let Err(err) = res {
///             // ...
///  #          _ = err;
///         }
///     }
/// }));
///
/// while let Ok(browser_snapshot) = rx.recv() {
///     // ...
/// #   _ = browser_snapshot;
/// }
/// ```
/// # Panics
/// If the callback provided ever panics, the program will panic as expected.
pub fn set_callback(callback: WindowEventCallback) -> Option<WindowEventCallback> {
    STATE.lock().callback.replace(callback)
}

/// Removes & returns the currently set callback if it exists.
/// 
/// A callback can be set using [`set_callback`].
pub fn remove_callback() -> Option<WindowEventCallback> {
    STATE.lock().callback.take()
}

/// Error returned by [`unhook`].
///
/// Most likely, this will be caused by attempting to unhook when no hook is sent.
/// However, this can also error if there was a Win32 API error relating to the message queue.
#[derive(Debug, thiserror::Error, Eq, PartialEq)]
pub enum UnhookError {
    /// No hook was set yet. To set a hook, use [`try_hook`].
    #[error("No hook was set yet; call `try_hook()` to set a hook.")]
    HookNotSet,
    /// There was an error on the spawned hook thread (the thread that listens for events)
    /// relating to the setup or shutdown of the event queue.
    #[error("The hook thread failed: {0}")]
    HookThreadError(WinErr),
    /// There was an error with instructing the hook thread (thread that listens for events)
    /// to quit. The [`unhook`] function failed to send [`WM_QUIT`].
    #[error("Failed to quit to the hook thread (failed to send WM_QUIT): {0}")]
    QuitMessageQueueError(WinErr),
}

/// Removes window event monitoring hook.
/// 
/// This function stops the thread that listens for [window events](WindowEvent).
/// This *does not* call [`remove_callback`] to remove the set callback, but there's no harm in leaving it set.
/// If a hook isn't set yet, this will return [`UnhookError::HookNotSet`].
pub fn unhook() -> Result<(), UnhookError> {
    let mut state = STATE.lock();

    let Some((thread, thread_id)) = state.thread.take() else {
        return Err(UnhookError::HookNotSet);
    };

    // SAFETY: thread is live and has message queue
    match unsafe { PostThreadMessageW(thread_id.get(), WM_QUIT, WPARAM::default(), LPARAM::default()) } {
        Ok(()) => match thread.join() {
            Err(panic) => panic::resume_unwind(panic),
            Ok(res) => match res {
                Ok(()) => Ok(()),
                Err(err) => Err(UnhookError::HookThreadError(err)),
            }
        }
        Err(err) if err == WinErr::from(ERROR_INVALID_THREAD_ID) => panic!("WinHookState::thread should always point to a valid thread"),
        Err(err) if err == WinErr::from(ERROR_INVALID_PARAMETER) => panic!("WinHookState::thread should always point to a valid thread"),
        Err(err) => Err(UnhookError::QuitMessageQueueError(err)),
    }
}