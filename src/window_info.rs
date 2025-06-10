use std::ffi::OsString;
use std::os::windows::ffi::OsStringExt;
use windows::Win32::Foundation::{GetLastError, SetLastError, ERROR_SUCCESS, HWND};
use windows::core::Error as WinErr; 
use windows::Win32::UI::WindowsAndMessaging::{GetWindowTextLengthW, GetWindowTextW};

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
        copied => Ok(
            OsString::from_wide(&buffer[..copied as usize])
                .to_string_lossy()
                .to_string()
        )
    }
}