use std::path::Path;

fn main() {
    let dist_dir = Path::new("../../web/dist");
    if !dist_dir.exists() {
        let _ = std::fs::create_dir_all(dist_dir);
    }
    let index = dist_dir.join("index.html");
    if !index.exists() {
        let _ = std::fs::write(
            &index,
            "<!doctype html><html><head><meta charset=\"utf-8\"><title>shunt-console</title></head><body><p>Run <code>cd console/web &amp;&amp; npm ci &amp;&amp; npm run build</code> to bundle the Shunt Console UI.</p></body></html>\n",
        );
    }
    println!("cargo:rerun-if-changed=../../web/dist");
}
