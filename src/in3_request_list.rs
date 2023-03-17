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

/// Sends an HTTP request using the provided parameters
///
/// # Arguments
///
/// * `url`: A string representing the target URL for the HTTP request.
/// * `method`: A string representing the HTTP method to be used (e.g., "GET", "POST").
/// * `payload`: An optional string representing the request payload, if applicable.
/// * `request_pointer`: A raw pointer to a `c_void` representing the request context.
/// * `resolve_http_request`: A `ResolveHttpRequest` callback function to handle the actual HTTP request.
///
/// # Returns
///
/// * `Result<String, Box<dyn Error>>`: A `Result` containing either the response body as a `String`
///   if the request was successful, or a boxed error if the request failed.
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

    let payload = CString::new(payload.unwrap_or("".to_string()))?;
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
