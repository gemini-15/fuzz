use libc;
use std;
use json::*;
use super::fmtp::FMTPTransaction;

fn log_fmtp(tx: &FMTPTransaction) -> Option<Json>{
    let js = Json::object();
    if let Some(ref _request) = tx.srv {
        js.set_string("type", "server side");
    }
    if let Some(ref _response) = tx.cli {
        js.set_string("type", "client side");
    }
    return Some(js);
}

#[no_mangle]
pub extern "C" fn rs_fmtp_logger_log(tx: *mut libc::c_void) -> *mut JsonT {
    let tx= cast_pointer!(tx, FMTPTransaction);
    match log_fmtp(tx) {
        Some(js) => js.unwrap(),
        None => std::ptr::null_mut(),
    }
}
