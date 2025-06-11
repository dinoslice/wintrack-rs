use std::ffi::OsString;
use std::num::NonZeroU32;
use std::os::windows::ffi::OsStringExt;
use std::path::PathBuf;
use windows::Win32::Foundation::{CloseHandle, SetLastError, ERROR_INSUFFICIENT_BUFFER, ERROR_INVALID_WINDOW_HANDLE, ERROR_SUCCESS, HANDLE, HWND, MAX_PATH, RECT};
use windows::core::{Error as WinErr, PWSTR};
use windows::Win32::Security::{GetSidSubAuthority, GetSidSubAuthorityCount, GetTokenInformation, TokenIntegrityLevel, TOKEN_MANDATORY_LABEL, TOKEN_QUERY};
use windows::Win32::System::Threading::{OpenProcess, OpenProcessToken, QueryFullProcessImageNameW, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION};
use windows::Win32::UI::WindowsAndMessaging::{GetClassNameW, GetForegroundWindow, GetWindowRect, GetWindowTextLengthW, GetWindowTextW, GetWindowThreadProcessId, IsIconic, IsWindow, IsWindowVisible};

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct WindowSnapshot {
    pub title: String,
    pub class_name: String,
    pub rect: WindowRect,
    pub thread_id: WinThreadId,
    pub process_id: WinProcessId,
    pub is_minimized: bool,
    pub is_foreground: bool,
    pub executable: PathBuf,
    pub integrity_level: IntegrityLevel,
}

impl WindowSnapshot {
    pub fn from_hwnd(hwnd: HWND) -> Result<Self, WinErr> {
        let (thread_id, process_id) = get_window_thread_process_id(hwnd)?;
        
        let process_handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, process_id)? };
        
        let snapshot = Self {
            title: get_window_title(hwnd)?,
            class_name: get_window_class_name(hwnd)?,
            rect: get_window_rect(hwnd)?,
            thread_id,
            process_id,
            is_minimized: is_window_minimized(hwnd).ok_or(WinErr::from(ERROR_INVALID_WINDOW_HANDLE))?,
            is_foreground: is_window_foreground(hwnd).ok_or(WinErr::from(ERROR_INVALID_WINDOW_HANDLE))?,
            executable: get_process_executable_path(process_handle)?,
            integrity_level: get_process_integrity_level(process_handle)?,
        };

        unsafe { CloseHandle(process_handle)?; }
        
        Ok(snapshot)
    }
}

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

#[derive(Copy, Clone, Eq, PartialEq, Debug, Hash)]
pub enum IntegrityLevel {
    Low,
    Medium,
    MediumUiAccess,
    High,
    System,
    Protected,
    Other(u32),
}

impl IntegrityLevel {
    pub fn from_rid(rid: u32) -> Self {
        match rid {
            0x1000 => IntegrityLevel::Low,
            0x2000 => IntegrityLevel::Medium,
            0x2100 => IntegrityLevel::MediumUiAccess,
            0x3000 => IntegrityLevel::High,
            0x4000 => IntegrityLevel::System,
            0x5000 => IntegrityLevel::Protected,
            other => IntegrityLevel::Other(other),
        }
    }

    pub fn rid(&self) -> u32 {
        match *self {
            IntegrityLevel::Low => 0x1000,
            IntegrityLevel::Medium => 0x2000,
            IntegrityLevel::MediumUiAccess => 0x2100,
            IntegrityLevel::High => 0x3000,
            IntegrityLevel::System => 0x4000,
            IntegrityLevel::Protected => 0x5000,
            IntegrityLevel::Other(value) => value,
        }
    }
}

fn get_process_integrity_level(process_handle: HANDLE) -> Result<IntegrityLevel, WinErr> {
    let mut token_handle = HANDLE::default();
    
    unsafe { OpenProcessToken(process_handle, TOKEN_QUERY, &mut token_handle)? };
    
    let mut ret_len = 0;
    
    match unsafe { GetTokenInformation(token_handle, TokenIntegrityLevel, None, 0, &mut ret_len) } {
        Err(err) if err != ERROR_INSUFFICIENT_BUFFER.into() => {
            unsafe { CloseHandle(token_handle)?; }
            
            return Err(err);
        },
        _ => {},
    }
    
    let mut buffer = vec![0u8; ret_len as _];

    unsafe { GetTokenInformation(token_handle, TokenIntegrityLevel, Some(buffer.as_mut_ptr() as _), ret_len, &mut ret_len)? };
    
    let security_id = unsafe { *buffer.as_ptr().cast::<TOKEN_MANDATORY_LABEL>() }.Label.Sid;

    let count = unsafe { *GetSidSubAuthorityCount(security_id) } as u32;
    let rid = unsafe { *GetSidSubAuthority(security_id, count - 1) };

    unsafe { CloseHandle(token_handle)?; }
    
    Ok(IntegrityLevel::from_rid(rid))
}

fn get_process_executable_path(process_handle: HANDLE) -> Result<PathBuf, WinErr> {
    let mut buffer = [0u16; MAX_PATH as _];

    let mut chars = buffer.len() as _;

    unsafe { QueryFullProcessImageNameW(process_handle, PROCESS_NAME_WIN32, PWSTR(buffer.as_mut_ptr()), &mut chars)? };
    
    Ok(PathBuf::from(OsString::from_wide(&buffer[..chars as _])))
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