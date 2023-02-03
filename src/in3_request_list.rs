use std::error::Error;
#[cfg(feature = "sdk")]
use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_void};

pub type ResolveHttpRequest = extern "C" fn(
    vade_req_ctx: *const c_void,
    url: *const c_char,
    method: *const c_char,
    path: *const c_char,
    payload: *const c_char,
    res: *mut *mut c_char,
) -> i32;

pub fn send_request(
    url: String,
    method: String,
    payload: Option<String>,
    request_pointer: *const c_void,
    resolve_http_request: ResolveHttpRequest,
) -> Result<String, Box<dyn Error>> {
    let url = CString::new(url.to_string())?;
    let url = url.as_ptr();

    let method = CString::new(method)?;
    let method = method.as_ptr();

    let path = CString::new("")?;
    let path = path.as_ptr();

    let payload = CString::new(payload.unwrap_or("")?)?;
    let payload = payload.as_ptr();

    let mut res: *mut c_char = std::ptr::null_mut();

    let error_code = (resolve_http_request)(
        request_pointer,
        url,
        method,
        path,
        payload,
        &mut res as *mut *mut c_char,
    );

    if error_code < 0 {
        return Err(Box::from(format!("{}", error_code)));
    }
    let res = unsafe { CStr::from_ptr(res).to_string_lossy().into_owned() };
    return Ok(res);
}
