use std::ffi::OsString;
use std::os::windows::ffi::OsStringExt;
use parking_lot::Mutex;
use windows::Win32::Foundation::HWND;
use windows::Win32::UI::Accessibility::{HWINEVENTHOOK};
use windows::Win32::UI::WindowsAndMessaging::{GetWindowTextLengthW, GetWindowTextW, CHILDID_SELF, EVENT_OBJECT_NAMECHANGE, OBJID_WINDOW};

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