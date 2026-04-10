#[cfg(target_os = "linux")]
fn main() {
    use std::path::PathBuf;
    use libbpf_cargo::SkeletonBuilder;

    let probes_dir = PathBuf::from("src/probes");
    let out_dir    = PathBuf::from(std::env::var("OUT_DIR").unwrap());

    for probe in &["execve", "memory", "persistence", "privesc", "rootkit"] {
        SkeletonBuilder::new()
            .source(probes_dir.join(format!("{probe}.bpf.c")))
            .clang_args(["-I/usr/include/bpf", "-I/usr/include"])
            .build_and_generate(out_dir.join(format!("{probe}.skel.rs")))
            .expect(&format!("failed to build {probe}.bpf.c"));
    }

    println!("cargo:rerun-if-changed=src/probes/");
}

#[cfg(not(target_os = "linux"))]
fn main() {}
