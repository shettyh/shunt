//! Declarative TOML contract test engine (`shunt test`) with in-process fault-injecting
//! mock upstreams, deterministic [`shunt_plugin_sdk::ManualClock`] stepping, hot-reload
//! testing, and Prometheus metric / snapshot redaction assertions.

pub mod mock;
pub mod runner;
pub mod schema;

pub use mock::{CapturedRequest, MockHandle, spawn_mock};
pub use runner::{CaseReport, SpecError, SpecRunReport, run_spec_file, run_spec_str};
pub use schema::{
    CaseSpec, ExpectSpec, MockFault, MockResponseSpec, MockSpec, RequestSpec, SpecFile, SpecHeader,
    StepSpec, UpstreamCallExpect,
};
