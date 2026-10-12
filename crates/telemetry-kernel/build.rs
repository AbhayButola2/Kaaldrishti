// build.rs — protobuf code generation for telemetry-kernel
//
// Generates Rust types from proto/kaaladrishti/v1/platform.proto using prost-build.
// Output is placed in OUT_DIR (Cargo-managed) and included via the include! macro
// in generated/mod.rs.
//
// Why prost-build here instead of pre-generated files?
// prost-build runs at `cargo build` time, ensuring the generated Rust types are
// always in sync with the proto file without a manual codegen step for Rust.
// Go and Python use the scripts/gen_proto.sh script (separate step) because
// their build systems handle codegen differently.

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Tell Cargo to re-run this build script if the proto file changes.
    println!("cargo:rerun-if-changed=../../proto/kaaladrishti/v1/platform.proto");
    println!("cargo:rerun-if-changed=build.rs");

    prost_build::Config::new()
        // Generate serde Serialize/Deserialize on all messages for JSON test fixtures.
        // This is used exclusively in tests; the production path uses binary protobuf.
        .type_attribute(".", "#[derive(serde::Serialize, serde::Deserialize)]")
        .compile_protos(
            &["../../proto/kaaladrishti/v1/platform.proto"],
            &["../../proto"],
        )?;

    Ok(())
}
