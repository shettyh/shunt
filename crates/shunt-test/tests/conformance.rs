use std::path::PathBuf;

#[tokio::test]
async fn run_all_conformance_specs() {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let specs_dir = manifest_dir.join("../../specs/conformance");

    let mut entries: Vec<PathBuf> = std::fs::read_dir(&specs_dir)
        .expect("specs/conformance directory must exist")
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .map(|n| n.ends_with(".spec.toml"))
                .unwrap_or(false)
        })
        .collect();
    entries.sort();

    assert!(
        !entries.is_empty(),
        "expected at least one conformance spec in {}",
        specs_dir.display()
    );

    let mut all_failures = Vec::new();
    for spec_path in entries {
        let report = shunt_test::run_spec_file(&spec_path, None, None)
            .await
            .unwrap_or_else(|e| panic!("failed to run {}: {e}", spec_path.display()));
        for case in report.cases {
            if !case.passed {
                all_failures.push(format!(
                    "[{} :: {}]\n  {}",
                    spec_path.display(),
                    case.name,
                    case.failures.join("\n  ")
                ));
            }
        }
    }

    assert!(
        all_failures.is_empty(),
        "conformance spec failures:\n{}",
        all_failures.join("\n\n")
    );
}
