use std::env;
use std::path::Path;

fn main() {
    let crate_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let output_file = Path::new(&crate_dir).join("target/header.h");

    // cbindgen::generate(crate_dir)
    //     .expect("Unable to generate bindings")
    //     .write_to_file(output_file);

    let header_content = r#"
        // C-compatible function declarations for frost-secp256k1-tr
        const char* get_id(const char* id);
        const char* num_to_id(unsigned long long num);
        const char* dkg_part1(const char* id, unsigned short max_signers, unsigned short min_signers);
        const char* verify_proof_of_knowledge(const char* id, const char* commitments_buff, const char* sign_buff);
        const char* dkg_part2(const char* r1_skrt_pkg_buff, const char* r1_pkg_buff);
        const char* dkg_verify_secret_share(const char* id, const char* share_buff, const char* commitment_buff);
        const char* dkg_part3(const char* r2_sec_pkg_buf, const char* r1_pkgs_buf, const char* r2_pkgs_buf);
        const char* keys_generate_with_dealer(unsigned short max_signers, unsigned short min_signers);
        const char* keys_split(const char* secret_buff, unsigned short max_signers, unsigned short min_signers);
        const char* keys_reconstruct(const char* secret_shares_buff, unsigned short min_signers);
        const char* get_pubkey(const char* secret_buff);
        const char* key_package_from(const char* secret_share);
        const char* round1_commit(const char* secret_buf);
        const char* signing_package_new(const char* signing_commitments_buf, const char* msg);
        const char* round2_sign(const char* signing_package_buf, const char* signer_nonces_buf, const char* key_package_buf);
        const char* verify_share(const char* identifier_buf, const char* verifying_share_buf, const char* signature_share_buf, const char* signing_package_buf, const char* verifying_key_buf);
        const char* aggregate(const char* signing_package_buf, const char* signature_shares_buf, const char* pubkey_package_buf);
        const char* pubkey_package_tweak(const char* pubkey_package_buf, const char* merkle_root_buf);
        const char* key_package_tweak(const char* key_package_buf, const char* merkle_root_buf);
        const char* verify_group_signature(const char* signature_buf, const char* msg_buf, const char* pubkey_package_buf);
        void mem_free(const char* ptr);
    "#;
    std::fs::write(output_file, header_content)
        .expect("Failed to write header.h");
}
