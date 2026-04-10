fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Use bundled protoc — no manual installation required.
    let protoc = protoc_bin_vendored::protoc_bin_path()?;
    std::env::set_var("PROTOC", protoc);

    tonic_build::configure()
        .build_server(false)
        .build_client(true)
        .compile_protos(
            &[
                "../../proto/common.proto",
                "../../proto/host_analyzer.proto",
            ],
            &["../../proto"],
        )?;
    Ok(())
}
