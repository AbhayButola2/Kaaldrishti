// build.rs — Kaalform Protobuf code generation.
//
// Generates Rust types from the canonical kaaladrishti/v1/platform.proto so
// Kaalform can encode TelemetryEvent and GraphDelta messages that Kaaladrishti
// understands, without duplicating the schema.
//
// Usage: `cargo build` — prost-build compiles platform.proto into
// `$OUT_DIR/kaaladrishti.v1.rs` which `lib.rs` includes via the `proto` module.

fn main() {
    let proto_root = "../../proto";
    println!("cargo:rerun-if-changed={proto_root}/kaaladrishti/v1/platform.proto");

    prost_build::Config::new()
        .compile_protos(
            &[&format!("{proto_root}/kaaladrishti/v1/platform.proto")],
            &[proto_root],
        )
        .expect("kaalform: failed to compile platform.proto");
}
