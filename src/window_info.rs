use std::ffi::OsString;
use std::fmt;
use std::num::NonZeroU32;
use std::os::windows::ffi::OsStringExt;
use std::path::PathBuf;
use std::ptr::NonNull;
use windows::Win32::Foundation::{CloseHandle, SetLastError, ERROR_INSUFFICIENT_BUFFER, ERROR_INVALID_HANDLE, ERROR_INVALID_PARAMETER, ERROR_INVALID_SID, ERROR_INVALID_WINDOW_HANDLE, ERROR_PARTIAL_COPY, ERROR_SUCCESS, HANDLE, HWND, MAX_PATH, RECT};
use windows::core::{Error as WinErr, PWSTR};
use windows::Win32::Security::{GetSidSubAuthority, GetSidSubAuthorityCount, GetTokenInformation, IsValidSid, TokenIntegrityLevel, TOKEN_MANDATORY_LABEL, TOKEN_QUERY};
use windows::Win32::System::Threading::{OpenProcess, OpenProcessToken, QueryFullProcessImageNameW, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION};
use windows::Win32::UI::WindowsAndMessaging::{GetClassNameW, GetForegroundWindow, GetWindowRect, GetWindowTextLengthW, GetWindowTextW, GetWindowThreadProcessId, IsIconic, IsWindow, IsWindowVisible};

/// Captures various properties of a window's current state.
///
/// Most likely, you'll get a snapshot from a [`WindowEvent`](crate::WindowEvent) from the callback set by [`set_callback`](crate::set_callback).
/// You can also create a snapshot from a [`HWND`](HWND) using [`Self::from_hwnd`](WindowSnapshot::from_hwnd).
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
///     if event.kind == WindowEventKind::ForegroundWindowChanged {
///         assert!(snapshot.is_foreground);
///     }
/// }));
/// ```
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct WindowSnapshot {
    /// The title of the window
    ///
    /// # Examples:
    /// ```no_run
    /// # use window_events::WindowSnapshot;
    /// let browser_snapshot: WindowSnapshot = todo!();
    /// assert_eq!(browser_snapshot.title, "Firefox");
    /// ```
    pub title: String,
    /// The [class name](https://learn.microsoft.com/en-us/windows/win32/winmsg/about-window-classes) of the window
    ///
    /// # Examples:
    /// ```no_run
    /// # use window_events::WindowSnapshot;
    /// let browser_snapshot: WindowSnapshot = todo!();
    /// assert_eq!(browser_snapshot.class_name, "MozillaWindowClass");
    /// ```
    pub class_name: String,
    /// Rectangle of the window's position on screen.
    pub rect: WindowRect,
    /// The id of the thread that created this window.
    pub thread_id: WinThreadId,
    /// The id of the process that created this window.
    pub process_id: WinProcessId,
    /// If the window was minimized (at time of snapshot)
    /// 
    /// # Examples:
    /// ```no_run
    /// # use window_events::{WindowEvent, WindowEventKind, WindowSnapshot};
    /// let WindowEvent { kind, snapshot } = todo!();
    /// assert_eq!(kind, WindowEventKind::WindowBecameVisible);
    /// assert!(!snapshot.is_minimized);
    /// ```
    pub is_minimized: bool,
    /// If the window was the foreground window (at time of snapshot)
    ///
    /// # Examples:
    /// ```no_run
    /// # use window_events::{WindowEvent, WindowEventKind, WindowSnapshot};
    /// let WindowEvent { kind, snapshot } = todo!();
    /// assert_eq!(kind, WindowEventKind::ForegroundWindowChanged);
    /// assert!(snapshot.is_foreground);
    /// ```
    pub is_foreground: bool,
    /// If the window is visible (at time of snapshot)
    ///
    /// # Examples:
    /// ```no_run
    /// # use window_events::{WindowEvent, WindowEventKind, WindowSnapshot};
    /// let WindowEvent { kind, snapshot } = todo!();
    /// assert_eq!(kind, WindowEventKind::WindowBecameHidden);
    /// assert!(!snapshot.is_visible);
    /// ```
    pub is_visible: bool,
    /// Path to the executable of the window.
    ///
    /// # Examples:
    /// ```no_run
    /// # use window_events::WindowSnapshot;
    /// # use std::path::PathBuf;
    /// let browser_snapshot: WindowSnapshot = todo!();
    /// assert_eq!(browser_snapshot.executable, PathBuf::from(r"C:\Program Files\Mozilla Firefox\firefox.exe"));
    /// ```
    pub executable: PathBuf,
    /// The [integrity level](https://learn.microsoft.com/en-us/windows/win32/secauthz/mandatory-integrity-control) of the window.
    pub integrity_level: IntegrityLevel,
}

/// Error returned by [`WindowSnapshot::from_hwnd`].
/// 
/// Most likely, this is caused by an invalid handle, but in rare cases an error from the Win32 API may occur.
#[derive(Debug, thiserror::Error, Eq, PartialEq)]
pub enum WindowSnapshotFromHandleError {
    /// The handle given was invalid.
    #[error("The handle passed in was invalid")]
    InvalidHandle,
    /// Internal error from Win32 API.
    #[error("Windows API error: {0}")]
    WinErr(#[from] WinErr),
}

impl WindowSnapshot {
    /// Create a snapshot of the window pointed to by `hwnd`.
    /// 
    /// # Example:
    /// ```no_run
    /// # use windows::Win32::UI::WindowsAndMessaging::GetForegroundWindow;
    /// # use window_events::WindowSnapshot;
    /// // SAFETY: this function (from Win32 API) is always safe to call
    /// let hwnd = unsafe { GetForegroundWindow() };
    ///
    /// let foreground = WindowSnapshot::from_hwnd(hwnd).expect("valid hwnd");
    /// ```
    /// # Errors:
    /// Returns [`WindowSnapshotFromHandleError::InvalidHandle`] is `hwnd` is invalid.
    /// If an internal error happens with the Win32 API, [`WindowSnapshotFromHandleError::WinErr`] is returned.
    pub fn from_hwnd(hwnd: HWND) -> Result<Self, WindowSnapshotFromHandleError> {
        if !is_valid_window(hwnd) {
            Err(WindowSnapshotFromHandleError::InvalidHandle)?
        }
        
        // SAFETY: hwnd is valid
        let (thread_id, process_id) = unsafe { get_window_thread_process_id(hwnd)? };

        // SAFETY: pid is valid
        let process_handle = unsafe { open_process_handle_limited_query(process_id)? };
        
        // SAFETY: checked that hwnd was valid, process_handle should be valid
        let snapshot = unsafe {
            Self {
                title: get_window_title(hwnd)?,
                class_name: get_window_class_name(hwnd)?,
                rect: get_window_rect(hwnd)?,
                thread_id,
                process_id,
                is_minimized: is_window_minimized(hwnd),
                is_foreground: is_window_foreground(hwnd),
                is_visible: is_window_visible(hwnd),
                executable: get_process_executable_path(process_handle)?,
                integrity_level: get_process_integrity_level(process_handle)?,
            }
        };

        // SAFETY: process handle should be valid
        unsafe { CloseHandle(process_handle).expect("process handle should be valid"); }
        
        Ok(snapshot)
    }
}

// SAFETY: pid should be valid
unsafe fn open_process_handle_limited_query(pid: WinProcessId) -> Result<HANDLE, WinErr> {
    // SAFETY: windows-rs checks for validity, caller is responsible for ensuring pid is valid
    match unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) } {
        Ok(handle) => Ok(handle),
        Err(err) if err == WinErr::from(ERROR_INVALID_PARAMETER) => panic!("PID from get_window_thread_process_id should be valid"),
        Err(err) if err == WinErr::from(ERROR_INVALID_HANDLE) => panic!("PID from get_window_thread_process_id should be valid"),
        Err(err) => Err(err),
    }
}

fn is_valid_window(hwnd: HWND) -> bool {
    unsafe { IsWindow(Some(hwnd)).as_bool() }
}

// SAFETY: hwnd should be a valid window
unsafe fn get_window_title(hwnd: HWND) -> Result<String, WinErr> {
    // clear last error to ensure GetWindowTextLengthW result can be used
    // SAFETY: always safe to call, thread local
    unsafe { SetLastError(ERROR_SUCCESS) };

    // SAFETY: caller ensures hwnd is valid => hwnd thread should be live
    let len = unsafe { GetWindowTextLengthW(hwnd) } ;
    
    if len == 0 {
        return match WinErr::from_win32() {
            err if err == ERROR_INVALID_HANDLE.into() => unreachable!("caller should ensure hwnd is valid"),
            err if err == ERROR_INVALID_WINDOW_HANDLE.into() => unreachable!("caller should ensure hwnd is valid"),
            err if err == ERROR_SUCCESS.into() => Ok(String::new()),
            err => Err(err),
        };
    }

    let mut buffer = vec![0; (len + 1) as usize];

    // SAFETY: caller ensures hwnd is valid, ptr is valid & unique (due to &mut),
    // buffer accounts for null terminator
    match unsafe { GetWindowTextW(hwnd, &mut buffer) } {
        0 => match WinErr::from_win32() {
            err if err == ERROR_INVALID_HANDLE.into() => unreachable!("caller should ensure hwnd is valid"),
            err if err == ERROR_INVALID_WINDOW_HANDLE.into() => unreachable!("caller should ensure hwnd is valid"),
            err => Err(err),
        },
        copied => Ok(String::from_utf16_lossy(&buffer[..copied as usize]))
    }
}

// SAFETY: hwnd should be a valid window
unsafe fn get_window_class_name(hwnd: HWND) -> Result<String, WinErr> {
    // https://learn.microsoft.com/en-us/windows/win32/api/winuser/ns-winuser-wndclassa
    // "The maximum length for lpszClassName is 256 ..."
    const CLASS_NAME_MAX_LEN: usize = 256;
    
    let mut buffer = [0u16; CLASS_NAME_MAX_LEN];

    // SAFETY: caller ensures hwnd is valid, buffer is writable and valid, unique (due to &mut)
    match unsafe { GetClassNameW(hwnd, &mut buffer) } {
        0 => match WinErr::from_win32() {
            err if err == ERROR_INVALID_HANDLE.into() => unreachable!("caller should ensure hwnd is valid"),
            err if err == ERROR_INVALID_WINDOW_HANDLE.into() => unreachable!("caller should ensure hwnd is valid"),
            err => Err(err),
        },
        copied => Ok(String::from_utf16_lossy(&buffer[..copied as usize]))
    }
}

/// Rectangle of the window's position on screen.
///
/// All four fields can be negative, usually for windows on monitors left or above of the main monitor.
/// Additionally, `left <= right && top <= bottom` is always guaranteed to be true.
#[derive(Copy, Clone, Debug, Hash, Eq, PartialEq)]
pub struct WindowRect {
    /// x-value of window's left edge
    left: i32,
    /// y-value of window's top edge
    top: i32,
    /// x-value of window's right edge
    right: i32,
    /// y-value of window's bottom edge
    bottom: i32,
}

impl WindowRect {
    /// Creates a `WindowRect`.
    /// `left <= right && top <= bottom` must be true, else [`None`] is returned.
    pub fn new(left: i32, top: i32, right: i32, bottom: i32) -> Option<Self> {
        if left <= right && top <= bottom {
            Some(Self { left, top, right, bottom })
        } else {
            None
        }
    }
    
    /// Get the x-value of window's left edge. Potentially negative.
    pub fn left(self) -> i32 {
        self.left
    }

    /// Get the y-value of window's top edge. Potentially negative.
    pub fn top(self) -> i32 {
        self.top
    }

    /// Get the x-value of window's right edge. Potentially negative.
    pub fn right(self) -> i32 {
        self.right
    }

    /// Get the y-value of window's bottom edge. Potentially negative.
    pub fn bottom(self) -> i32 {
        self.bottom
    }
    
    /// Get the top left corner of the window, `(x, y)`.
    pub fn top_left(self) -> (i32, i32) {
        (self.left, self.top)
    }
    
    /// Get the size of the window, `(x, y)`.
    pub fn size(self) -> (u32, u32) {
        let width = self.right - self.left;
        
        let height = self.bottom - self.top;
        
        (width as _, height as _)
    }
}

// SAFETY: hwnd should be a valid window
unsafe fn get_window_rect(hwnd: HWND) -> Result<WindowRect, WinErr> {
    let mut rect = RECT::default();

    // SAFETY: caller ensures hwnd is valid window, rect is valid ptr, unique (due to &mut)
    match unsafe { GetWindowRect(hwnd, &mut rect) } {
        Ok(()) => {},
        Err(err) if err == ERROR_INVALID_HANDLE.into() => unreachable!("caller should ensure hwnd is valid"),
        Err(err) if err == ERROR_INVALID_WINDOW_HANDLE.into() => unreachable!("caller should ensure hwnd is valid"),
        Err(err) => Err(err)?,
    }
    
    let rect = WindowRect::new(rect.left, rect.top, rect.right, rect.bottom)
        .expect("window dimensions should be non-negative");
    
    Ok(rect)
}

/// Windows thread id, notably *not* [`std::thread::ThreadId`].
///
/// # Examples:
/// ```no_run
/// # use window_events::{WindowSnapshot, WinThreadId};
/// let browser_snapshot: WindowSnapshot = todo!();
/// let thread_id = WinThreadId::new(335364).expect("nonzero!");
/// assert_eq!(browser_snapshot.thread_id, thread_id);
/// ```
pub type WinThreadId = NonZeroU32;

/// Windows process id.
///
/// # Examples:
/// ```no_run
/// # use window_events::WindowSnapshot;
/// let browser_snapshot: WindowSnapshot = todo!();
/// assert_eq!(browser_snapshot.process_id, 340304);
/// ```
pub type WinProcessId = u32;

// SAFETY: hwnd should be a valid window
unsafe fn get_window_thread_process_id(hwnd: HWND) -> Result<(WinThreadId, WinProcessId), WinErr> {
    let mut process_id = 0;

    // SAFETY: caller ensures hwnd is valid, process_id is valid, writable, unique (due to &mut)
    let thread_id = unsafe { GetWindowThreadProcessId(hwnd, Some(&mut process_id)) };
    
    match WinThreadId::new(thread_id) {
        Some(thread_id) => Ok((thread_id, process_id)),
        None => match WinErr::from_win32() {
            err if err == ERROR_INVALID_HANDLE.into() => unreachable!("caller should ensure hwnd is valid"),
            err if err == ERROR_INVALID_WINDOW_HANDLE.into() => unreachable!("caller should ensure hwnd is valid"),
            err => Err(err)?,
        },
    }
}

/// A process [integrity level](https://learn.microsoft.com/en-us/windows/win32/secauthz/mandatory-integrity-control).
///
/// # Examples:
/// ```no_run
/// # use window_events::{IntegrityLevel, WindowSnapshot};
/// let browser_snapshot: WindowSnapshot = todo!();
/// assert_eq!(browser_snapshot.integrity_level, IntegrityLevel::MEDIUM);
/// ```
#[derive(Copy, Clone, Eq, PartialEq, Hash)]
pub struct IntegrityLevel(pub u32);

impl IntegrityLevel {
    /// Untrusted integrity level, processes initiated by anonymous or guest users
    pub const UNTRUSTED: Self = Self(0);
    /// Low integrity level, used commonly by AppContainers
    pub const LOW: Self = Self(0x1000);
    /// Medium integrity level, for authenticated users
    pub const MEDIUM: Self = Self(0x2000);
    /// Medium-plus integrity level, possibly for UI access
    pub const MEDIUM_PLUS: Self = Self(0x2100);
    /// High integrity level, elevated processes, programs launched as administrator
    pub const HIGH: Self = Self(0x3000);
    /// System integrity level, admin level processes, core OS processes, Windows services
    pub const SYSTEM: Self = Self(0x4000);
    /// Protected integrity level, DRM-protected or anti-malware
    pub const PROTECTED: Self = Self(0x5000);
    /// Secure integrity level, internal kernel processes
    pub const SECURE: Self = Self(0x7000);
}

impl fmt::Debug for IntegrityLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let field = match *self {
            Self::UNTRUSTED => format!("Untrusted (0x{:04x})", self.0),
            Self::LOW => format!("Low (0x{:04x})", self.0),
            Self::MEDIUM => format!("Medium (0x{:04x})", self.0),
            Self::MEDIUM_PLUS => format!("Medium-plus (0x{:04x})", self.0),
            Self::HIGH => format!("High (0x{:04x})", self.0),
            Self::SYSTEM => format!("System (0x{:04x})", self.0),
            Self::PROTECTED => format!("Protected (0x{:04x})", self.0),
            Self::SECURE => format!("Secure (0x{:04x})", self.0),
            Self(rid) => format!("0x{:04x}", rid),
        };

        f.debug_tuple(&field).finish()
    }
}

// SAFETY: process_handle should be valid and should have limited query information
unsafe fn get_process_integrity_level(process_handle: HANDLE) -> Result<IntegrityLevel, WinErr> {
    let mut token_handle = HANDLE::default();
    
    // SAFETY: caller ensures process_handle is valid, access flags are valid,
    // handle is valid and initialized
    match unsafe { OpenProcessToken(process_handle, TOKEN_QUERY, &mut token_handle) } {
        Err(err) if err == ERROR_INVALID_HANDLE.into() => unreachable!("caller must ensure handle is valid"),
        Err(err) if err == ERROR_INVALID_PARAMETER.into() => unreachable!("access flags are valid, output ptr is valid & writable"),
        Err(err) => Err(err)?,
        Ok(()) => {}
    }
    
    let mut ret_len = 0;
    
    // SAFETY: token handle is valid & was opened with TOKEN_QUERY, no buffer is a valid argument when querying size.
    match unsafe { GetTokenInformation(token_handle, TokenIntegrityLevel, None, 0, &mut ret_len) } {
        Err(err) if err == ERROR_INVALID_PARAMETER.into() => unreachable!("parameters should be valid"),
        Err(err) if err == ERROR_INVALID_HANDLE.into() => unreachable!("token handle should be valid"),
        Err(err) if err != ERROR_INSUFFICIENT_BUFFER.into() => {
            // SAFETY: handle should be valid, and if not, would've errored already
            unsafe { CloseHandle(token_handle).expect("handle should be valid"); }
            
            return Err(err);
        },
        _ => {},
    }
    
    let mut buffer = vec![0u8; ret_len as _];

    // SAFETY: token handle is valid & was opened with TOKEN_QUERY, buffer is valid ptr and ret_len matches size
    match unsafe { GetTokenInformation(token_handle, TokenIntegrityLevel, Some(buffer.as_mut_ptr() as _), ret_len, &mut ret_len) } {
        Err(err) if err == ERROR_INVALID_PARAMETER.into() => unreachable!("parameters should be valid"),
        Err(err) if err == ERROR_INVALID_HANDLE.into() => unreachable!("token handle should be valid"),
        Err(err) if err == ERROR_INSUFFICIENT_BUFFER.into() => unreachable!("buffer should be correctly sized"),
        Err(err) => {
            // SAFETY: handle should be valid, and if not, would've errored already
            unsafe { CloseHandle(token_handle).expect("handle should be valid"); }

            return Err(err);
        },
        _ => {},
    }
    
    // buffer should be big enough to hold TOKEN_MANDATORY_LABEL & extra bytes should not have been written
    if buffer.len() < size_of::<TOKEN_MANDATORY_LABEL>() || buffer.len() < ret_len as _ {
        Err(ERROR_INSUFFICIENT_BUFFER)?
    }

    // SAFETY: buffer should be properly initialized by GetTokenInformation with TokenIntegrityLevel,
    // buffer was correctly sized and at least the size of the struct
    let security_id = unsafe { *buffer.as_ptr().cast::<TOKEN_MANDATORY_LABEL>() }.Label.Sid;
    
    // SAFETY: security_id is non-null due to short-circuiting
    if security_id.is_invalid() || unsafe { !IsValidSid(security_id).as_bool() } {
        Err(ERROR_INVALID_SID)?
    }
    
    // SAFETY: security_id is valid since GetTokenInformation should have
    // properly initialized TOKEN_MANDATORY_LABEL
    let count = unsafe { GetSidSubAuthorityCount(security_id) };
    
    // SAFETY: pointer is valid to read and should be allocated and non-dangling
    let count = unsafe { *NonNull::new(count).ok_or(ERROR_INVALID_SID)?.as_ptr() } as u32;
    
    // SAFETY: count was gotten from GetSidSubAuthorityCount, security_id is valid
    let rid = unsafe { GetSidSubAuthority(security_id, count - 1) };

    // SAFETY: pointer is valid to read and should be allocated and non-dangling
    let rid = unsafe { *NonNull::new(rid).ok_or(ERROR_INVALID_SID)?.as_ptr() };
    
    // SAFETY: handle should be valid, and if not, would've errored already
    unsafe { CloseHandle(token_handle).expect("handle should be valid"); }
    
    Ok(IntegrityLevel(rid))
}


// SAFETY: process_handle should be valid
unsafe fn get_process_executable_path(process_handle: HANDLE) -> Result<PathBuf, WinErr> {
    let mut buffer = [0u16; MAX_PATH as usize + 1];

    let mut chars = buffer.len() as _;

    // SAFETY: caller ensures process_handle is valid, buffer is valid and long enough
    match unsafe { QueryFullProcessImageNameW(process_handle, PROCESS_NAME_WIN32, PWSTR(buffer.as_mut_ptr()), &mut chars) } {
        Err(err) if err == ERROR_INSUFFICIENT_BUFFER.into() => unreachable!("paths should not be longer than MAX_PATH"),
        Err(err) if err == ERROR_PARTIAL_COPY.into() => unreachable!("paths should not be longer than MAX_PATH"),
        Err(err) if err == ERROR_INVALID_HANDLE.into() => unreachable!("caller should ensure process_handle is valid"),
        Err(err) if err == ERROR_INVALID_PARAMETER.into() => unreachable!("params should be valid"),
        Err(err) => Err(err)?,
        Ok(()) => {}
    }
    
    assert!(
        chars < (buffer.len() - 1) as u32,
        "QueryFullProcessImageNameW should not return more characters than the buffer can hold",
    );

    Ok(PathBuf::from(OsString::from_wide(&buffer[..chars as _])))
}

// SAFETY: hwnd should be a valid window
unsafe fn is_window_minimized(hwnd: HWND) -> bool {
    // SAFETY: caller ensures hwnd is a valid window
    unsafe { IsIconic(hwnd).as_bool() }
}

// SAFETY: hwnd should be a valid window
unsafe fn is_window_visible(hwnd: HWND) -> bool {
    // SAFETY: caller ensures hwnd is a valid window
    unsafe { IsWindowVisible(hwnd).as_bool() }
}

// SAFETY: hwnd should be a valid window
unsafe fn is_window_foreground(hwnd: HWND) -> bool {
    // SAFETY: caller ensures hwnd is a valid window
    hwnd == unsafe { GetForegroundWindow() }
}