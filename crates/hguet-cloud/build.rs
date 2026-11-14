//! Generates the Rust message types from the repository's own public schema `protocol/v1/hguet.proto`.
//! The schema is never copied or forked. A vendored `protoc` is used so no system protobuf compiler is required.

use std::{env, path::PathBuf};

fn main() {
    let root = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").expect("manifest dir"))
        .join("../../protocol/v1");
    let schema = root.join("hguet.proto");
    assert!(
        schema.is_file(),
        "public schema missing at {}",
        schema.display()
    );
    println!("cargo:rerun-if-changed={}", schema.display());
    let protoc = protoc_bin_vendored::protoc_bin_path().expect("vendored protoc for this platform");
    let mut config = prost_build::Config::new();
    config.protoc_executable(protoc);
    config
        .compile_protos(&[schema], &[root])
        .expect("compile the public HGUET Protobuf schema");
}
