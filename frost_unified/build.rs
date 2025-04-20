use std::env;
use std::fs;
use std::path::Path;

fn main() {
    // Tell cargo to re-run this script if any of these files change
    println!("cargo:rerun-if-changed=../frost-ed25519/include");
    println!("cargo:rerun-if-changed=../frost-secp256k1/include");
    println!("cargo:rerun-if-changed=../frost-secp256k1-tr/include");
    
    // Create include directory if it doesn't exist
    let out_dir = env::var("OUT_DIR").unwrap();
    let include_dir = Path::new(&out_dir).join("include");
    fs::create_dir_all(&include_dir).unwrap();
    
    // Path to the combined header file
    let combined_header = include_dir.join("frost.h");
    
    // Start with header guards
    let mut combined_content = String::from(
        "#ifndef FROST_COMBINED_H\n#define FROST_COMBINED_H\n\n"
    );
    
    // Add extern "C" for C++ compatibility
    combined_content.push_str("#ifdef __cplusplus\nextern \"C\" {\n#endif\n\n");
    
    // Read and combine header files from each crate
    let header_files = [
        "../frost-ed25519/include/frost_ed25519.h",
        "../frost-secp256k1/include/frost_secp256k1.h",
        "../frost-secp256k1-tr/include/frost_secp256k1_tr.h",
    ];
    
    for header in &header_files {
        if let Ok(content) = fs::read_to_string(header) {
            // Strip any existing header guards or extern "C"
            let content = content
                .lines()
                .filter(|line| !line.contains("#ifndef") && 
                               !line.contains("#define") && 
                               !line.contains("#endif") &&
                               !line.contains("extern \"C\""))
                .collect::<Vec<&str>>()
                .join("\n");
            
            combined_content.push_str(&content);
            combined_content.push_str("\n\n");
        } else {
            println!("cargo:warning=Could not read header file: {}", header);
        }
    }
    
    // Close extern "C" and header guard
    combined_content.push_str("#ifdef __cplusplus\n}\n#endif\n\n");
    combined_content.push_str("#endif // FROST_COMBINED_H\n");
    
    // Write the combined header
    fs::write(&combined_header, combined_content).unwrap();
    
    // Copy the combined header to a more accessible location
    let dest_path = Path::new("include");
    fs::create_dir_all(dest_path).unwrap();
    fs::copy(&combined_header, dest_path.join("frost.h")).unwrap();
}
