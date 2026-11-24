#![no_main]

use http::{Method, Request, Uri, header};
use libfuzzer_sys::fuzz_target;
use shunt_engine::pipeline::strip_uri_prefix;
use shunt_engine::{
    CompiledPathRegex, CompiledPathTemplate, PathMatch, RouteIndex, RouteMatch, RouteSpec,
    RuntimeRegistry, SnapshotBuilder, UpstreamConfig, host_matches,
};

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

    if let Ok(tpl) = CompiledPathTemplate::parse(pattern) {
        let matched = tpl.matches(path_str);
        let params = tpl.extract_params(path_str);
        if !matched {
            assert!(params.is_empty());
        }
    }

    if let Ok(re) = CompiledPathRegex::compile(pattern) {
        let matched = re.matches(path_str);
        let params = re.extract_params(path_str);
        if !matched {
            assert!(params.is_empty());
        }
    }

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

            let reg = RuntimeRegistry::new();
            let mut builder = SnapshotBuilder::new(1)
                .upstream(UpstreamConfig::new(
                    "be",
                    vec!["http://127.0.0.1:8081".to_owned()],
                ))
                .route(RouteSpec::new("exact", RouteMatch::exact(prefix), "be"))
                .route(RouteSpec::new("prefix", rm, "be"));
            if let Ok(tpl_rm) = RouteMatch::template(pattern) {
                let tpl_rm = tpl_rm.with_host(host);
                let _ = tpl_rm.matches(&req);
                builder = builder.route(RouteSpec::new("tpl", tpl_rm, "be"));
            }
            if let Ok(re_rm) = RouteMatch::regex(pattern) {
                let re_rm = re_rm.with_host(host);
                let _ = re_rm.matches(&req);
                builder = builder.route(RouteSpec::new("re", re_rm, "be"));
            }
            builder = builder.route(RouteSpec::new("any", RouteMatch::any(), "be"));
            if let Ok(snap) = builder.build(&reg, false) {
                let index = RouteIndex::build(&snap.routes);
                assert_eq!(
                    index.match_route(&snap.routes, &req).map(|r| r.id.as_str()),
                    snap.match_route_linear(&req).map(|r| r.id.as_str()),
                );
            }
        }
    }
});
