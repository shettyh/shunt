#![no_main]

use http::{Method, Request, Uri, header};
use libfuzzer_sys::fuzz_target;
use shunt_engine::pipeline::strip_uri_prefix;
use shunt_engine::{PathMatch, RouteMatch, host_matches};

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else {
        return;
    };
    let mut parts = s.split('\0');
    let pattern = parts.next().unwrap_or("");
    let host = parts.next().unwrap_or("");
    let path_str = parts.next().unwrap_or("/");
    let prefix = parts.next().unwrap_or("/api");

    let _ = host_matches(pattern, host);
    let _ = PathMatch::Prefix(prefix.to_owned()).matches(path_str);
    let _ = PathMatch::Exact(prefix.to_owned()).matches(path_str);

    if let Ok(uri) = path_str.parse::<Uri>() {
        let stripped = strip_uri_prefix(&uri, prefix);
        if uri.path().starts_with('/') {
            assert!(stripped.path().starts_with('/'));
        }

        if let Ok(req) = Request::builder()
            .method(Method::GET)
            .uri(uri)
            .header(header::HOST, host)
            .body(())
        {
            let rm = RouteMatch::prefix(prefix).with_host(pattern);
            let _ = rm.matches(&req);
        }
    }
});
