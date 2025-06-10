use std::ffi::OsString;
use std::os::windows::ffi::OsStringExt;
use std::ptr;
use parking_lot::Mutex;
use windows::Win32::Foundation::{ERROR_INVALID_THREAD_ID, ERROR_NOT_ENOUGH_QUOTA, HWND, LPARAM, WPARAM};
use windows::core::Error as WinErr;
use windows::Win32::System::Threading::GetCurrentThreadId;
use windows::Win32::UI::Accessibility::{SetWinEventHook, HWINEVENTHOOK};
use windows::Win32::UI::WindowsAndMessaging::{GetMessageW, GetWindowTextLengthW, GetWindowTextW, PostThreadMessageW, CHILDID_SELF, EVENT_OBJECT_NAMECHANGE, OBJID_WINDOW, WINEVENT_OUTOFCONTEXT, WM_QUIT};

type WinThreadId = u32;

unsafe extern "system" fn win_event_proc(
    _h_win_event_hook: HWINEVENTHOOK,
    event: u32,
    hwnd: HWND,
    id_object: i32,
    id_child: i32,
    _dw_event_thread: u32,
    _dwms_event_time: u32,
) {
    if event == EVENT_OBJECT_NAMECHANGE && id_object == OBJID_WINDOW.0 && id_child == CHILDID_SELF as _ {
        if let Some(title) = unsafe { get_window_title(hwnd) } {
            if !title.is_empty() {
                println!("Window title changed: \"{}\"", title);
            }
        }
    }
}

unsafe fn get_window_title(hwnd: HWND) -> Option<String> {
    let length = unsafe { GetWindowTextLengthW(hwnd) };
    if length == 0 {
        return None;
    }

    let mut buffer = vec![0; (length + 1) as usize];

    let copied = unsafe { GetWindowTextW(hwnd, &mut buffer) };
    if copied == 0 {
        return None;
    }

    let os_string = OsString::from_wide(&buffer[..copied as usize]);
    os_string.into_string().ok()
}

#[derive(Default)]
pub struct WinHookState {
    pub callback: Option<Box<dyn Fn() -> () + Send>>,
    pub thread_id: Option<WinThreadId>,
}

pub static STATE: Mutex<WinHookState> = Mutex::new(WinHookState { callback: None, thread_id: None });


pub fn try_hook() -> Result<(), ()> {
    let mut state = STATE.lock();

    if state.thread_id.is_some() {
        Err(()) // already hooked
    } else {
        match hook_inner() {
            Ok(thread_id) => {
                state.thread_id = Some(thread_id);

                Ok(())
            },
            Err(err) => {
                Err((/* err */))
            }
        }
    }
}

fn hook_inner() -> Result<WinThreadId, WinErr> {
    let (tx, rx) = oneshot::channel();

    std::thread::spawn(move || unsafe {
        let hook = SetWinEventHook(
            EVENT_OBJECT_NAMECHANGE,
            EVENT_OBJECT_NAMECHANGE,
            None,
            Some(win_event_proc),
            0,
            0,
            WINEVENT_OUTOFCONTEXT,
        );

        let res = if hook.is_invalid() {
            Err(WinErr::from_win32())
        } else {
            Ok(GetCurrentThreadId())
        };

        tx.send(res).expect("rx should still exist");

        let _ = GetMessageW(ptr::null_mut(), None, 0, 0);

        println!("closing message thread");
    });

    rx.recv().expect("should eventually recv a message")
}

pub fn unhook() -> Result<(), ()> {
    let mut state = STATE.lock();

    let Some(thread_id) = state.thread_id.take() else {
        return Err(());
    };

    match unsafe { PostThreadMessageW(thread_id, WM_QUIT, WPARAM::default(), LPARAM::default()) } {
        Ok(()) => Ok(()),
        Err(err) if err == WinErr::from(ERROR_INVALID_THREAD_ID) => panic!("WinHookState::thread_id should always point to a valid thread"),
        Err(err) if err == WinErr::from(ERROR_NOT_ENOUGH_QUOTA) => Err(()),
        Err(err) => Err(()),
    }
}