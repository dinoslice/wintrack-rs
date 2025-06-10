use std::num::NonZeroU32;
use windows::Win32::Foundation::{SetLastError, ERROR_SUCCESS, HWND, RECT};
use windows::core::Error as WinErr; 
use windows::Win32::UI::WindowsAndMessaging::{GetClassNameW, GetForegroundWindow, GetWindowRect, GetWindowTextLengthW, GetWindowTextW, GetWindowThreadProcessId, IsIconic, IsWindow, IsWindowVisible};

pub fn get_window_title(hwnd: HWND) -> Result<String, WinErr> {
    // clear last error to ensure GetWindowTextLengthW result can be used
    unsafe { SetLastError(ERROR_SUCCESS) };
    
    let len = unsafe { GetWindowTextLengthW(hwnd) } ;
    
    if len == 0 {
        let err = WinErr::from_win32();

        return if err != ERROR_SUCCESS.into() {
            Err(err)
        } else {
            Ok(String::new())
        }
    }

    let mut buffer = vec![0; (len + 1) as usize];

    match unsafe { GetWindowTextW(hwnd, &mut buffer) } {
        0 => Err(WinErr::from_win32()),
        copied => Ok(String::from_utf16_lossy(&buffer[..copied as usize]))
    }
}

fn get_window_class_name(hwnd: HWND) -> Result<String, WinErr> {
    // https://learn.microsoft.com/en-us/windows/win32/api/winuser/ns-winuser-wndclassa
    // "The maximum length for lpszClassName is 256 ..."
    const CLASS_NAME_MAX_LEN: usize = 256;
    
    let mut buffer = [0u16; CLASS_NAME_MAX_LEN];

    match unsafe { GetClassNameW(hwnd, &mut buffer) } {
        0 => Err(WinErr::from_win32()),
        copied => Ok(String::from_utf16_lossy(&buffer[..copied as usize]))
    }
}

#[derive(Copy, Clone, Debug, Hash, Eq, PartialEq)]
pub struct WindowRect {
    left: i32,
    top: i32,
    right: i32,
    bottom: i32,
}

impl WindowRect {
    pub fn new(left: i32, top: i32, right: i32, bottom: i32) -> Option<Self> {
        if left <= right && top <= bottom {
            Some(Self { left, top, right, bottom })
        } else {
            None
        }
    }
    
    pub fn left(self) -> i32 {
        self.left
    }

    pub fn top(self) -> i32 {
        self.top
    }

    pub fn right(self) -> i32 {
        self.right
    }

    pub fn bottom(self) -> i32 {
        self.bottom
    }
    
    pub fn top_left(self) -> (i32, i32) {
        (self.left, self.top)
    }
    
    pub fn size(self) -> (u32, u32) {
        let width = self.right - self.left;
        
        let height = self.bottom - self.top;
        
        (width as _, height as _)
    }
}

fn get_window_rect(hwnd: HWND) -> Result<WindowRect, WinErr> {
    let mut rect = RECT::default();

    unsafe { GetWindowRect(hwnd, &mut rect)? };
    
    let rect = WindowRect::new(rect.left, rect.top, rect.right, rect.bottom)
        .expect("window dimensions should be non-negative");
    
    Ok(rect)
}

pub type WinThreadId = NonZeroU32;
pub type WinProcessId = u32;

fn get_window_thread_process_id(hwnd: HWND) -> Result<(WinThreadId, WinProcessId), WinErr> {
    let mut process_id = 0;
    
    let thread_id = unsafe { GetWindowThreadProcessId(hwnd, Some(&mut process_id)) };
    
    match WinThreadId::new(thread_id) {
        Some(thread_id) => Ok((thread_id, process_id)),
        None => Err(WinErr::from_win32()),
    }
}

fn is_window_minimized(hwnd: HWND) -> Option<bool> {
    if unsafe { IsWindow(Some(hwnd)).as_bool() } {
        Some(
            unsafe { IsIconic(hwnd).as_bool() }
        )
    } else {
        None
    }
}

fn is_window_visible(hwnd: HWND) -> Option<bool> {
    if unsafe { IsWindow(Some(hwnd)).as_bool() } {
        Some(
            unsafe { IsWindowVisible(hwnd).as_bool() }
        )
    } else {
        None
    }
}

pub fn is_window_foreground(hwnd: HWND) -> Option<bool> {
    if unsafe { IsWindow(Some(hwnd)).as_bool() } {
        Some(
            hwnd == unsafe { GetForegroundWindow() }
        )
    } else {
        None
    }
}