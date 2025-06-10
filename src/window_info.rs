use std::ffi::OsString;
use std::os::windows::ffi::OsStringExt;
use windows::Win32::Foundation::{GetLastError, SetLastError, ERROR_SUCCESS, HWND};
use windows::core::Error as WinErr; 
use windows::Win32::UI::WindowsAndMessaging::{GetClassNameW, GetWindowTextLengthW, GetWindowTextW};

fn get_window_title(hwnd: HWND) -> Result<String, WinErr> {
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
    pub left: i32,
    pub top: i32,
    pub right: i32,
    pub bottom: i32,
}

impl WindowRect {
    pub fn top_left(self) -> (i32, i32) {
        (self.left, self.top)
    }
    
    pub fn size(self) -> (u32, u32) {
        let width = self.right - self.left;
        assert!(!width.is_negative(), "window width should be non-negative");

        let height = self.bottom - self.top;
        assert!(!height.is_negative(), "window height should be non-negative");

        (width as _, height as _)
    }
}