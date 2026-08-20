use std::env;
use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR")?);
    // Proto is extracted to the monorepo root `proto/` (shared schema for
    // consensus-node + future mirror/sdk crates). From this crate:
    //   consensus-node/protocol/stream/ -> ../../.. -> repo root
    let proto_dir = manifest_dir.join("../../../proto");
    let proto_file = proto_dir.join("jkain_stream.proto");
    println!("cargo:rerun-if-changed={}", proto_file.display());
    prost_build::Config::new().compile_protos(&[proto_file], &[proto_dir])?;
    Ok(())
}
