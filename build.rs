// build.rs
use std::env;
use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Define the output directory for the generated Rust code
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());

    // Define the path for the file descriptor set
    let descriptor_path = out_dir.join("identity_descriptor.bin"); // You can name this file as you like

    println!("cargo:rerun-if-changed=proto/identity_service.proto");

    tonic_build::configure()
        .out_dir(&out_dir) // Ensure generated Rust code goes to OUT_DIR
        .file_descriptor_set_path(&descriptor_path) // Output the descriptor set here
        .compile_protos(
            &["proto/identity_service.proto"], // Your .proto files
            &["proto/identity", "proto"], // Include paths for imports
        )?;

    Ok(())
}