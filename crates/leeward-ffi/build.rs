//! Build script to generate C header using cbindgen

fn main() {
    let crate_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let output_dir = std::path::Path::new(&crate_dir).join("..").join("..").join("include");

    // Create include directory
    std::fs::create_dir_all(&output_dir).ok();

    let output_file = output_dir.join("leeward.h");

    // Generate header
    let config = cbindgen::Config::from_file("cbindgen.toml")
        .unwrap_or_default();

    cbindgen::Builder::new()
        .with_crate(&crate_dir)
        .with_config(config)
        .generate()
        .expect("Unable to generate C bindings")
        .write_to_file(&output_file);

    println!("cargo:rerun-if-changed=src/lib.rs");
    println!("cargo:rerun-if-changed=cbindgen.toml");
}
