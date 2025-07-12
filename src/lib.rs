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

#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub enum WindowEventKind {
    ForegroundWindowChanged,
    WindowNameChanged,
    WindowBecameVisible,
    WindowBecameHidden,
    WindowCreated,
    WindowDestroyed,
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
            Err(err) => {
                eprintln!("{err}"); // TODO: log error!
                return;
            }
        };
        
        if let Some(callback) = &STATE.lock().callback {
            callback(WindowEvent { kind, snapshot });
        }
    }
}

pub type WindowEventCallback = Box<dyn Fn(WindowEvent) + Send>;

#[derive(Default)]
pub struct WinHookState {
    pub callback: Option<WindowEventCallback>,
    pub thread: Option<(JoinHandle<Result<(), WinErr>>, WinThreadId)>,
}

static STATE: Mutex<WinHookState> = Mutex::new(WinHookState { callback: None, thread: None });

#[derive(Debug, thiserror::Error, Eq, PartialEq)]
pub enum TryHookError {
    #[error("Hook already set; no need to set it again.")]
    HookAlreadySet,
    #[error("Failed to set hook: {0}")]
    FailedToSetHook(WinErr),
}


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

pub fn set_callback(callback: WindowEventCallback) -> Option<WindowEventCallback> {
    STATE.lock().callback.replace(callback)
}

pub fn remove_callback() -> Option<WindowEventCallback> {
    STATE.lock().callback.take()
}

#[derive(Debug, thiserror::Error, Eq, PartialEq)]
pub enum UnhookError {
    #[error("No hook was set yet; call `try_hook()` to set a hook.")]
    HookNotSet,
    #[error("The hook thread failed: {0}")]
    HookThreadError(WinErr),
    #[error("Failed to quit to the hook thread (failed to send WM_QUIT): {0}")]
    QuitMessageQueueError(WinErr),
}

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