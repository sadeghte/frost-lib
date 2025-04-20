

#ifndef FROST_SECP256K1_TR_LIB_H
#define FROST_SECP256K1_TR_LIB_H

#include <cstdarg>
#include <cstdint>
#include <cstdlib>
#include <ostream>
#include <new>

extern "C" {

const uint8_t *get_id(const uint8_t *id);

const uint8_t *num_to_id(uint64_t num);

const uint8_t *dkg_part1(const uint8_t *id, uint16_t max_signers, uint16_t min_signers);

/// every proof of knowledge received from dkg_part1 must be validate with this method.
/// dkg_part2 validate this proofs it self, and throw an error if faild.
/// to find out which party behaves malicious, proof_of_knowledge of each partners must be check after dkg_part2 failure.
const uint8_t *verify_proof_of_knowledge(const uint8_t *id,
                                         const uint8_t *commitments_buff,
                                         const uint8_t *sign_buff);

const uint8_t *dkg_part2(const uint8_t *r1_skrt_pkg_buff, const uint8_t *r1_pkg_buff);

/// This method is called by the receiver of a secret share during the Distributed Key Generation (DKG) protocol.
///
/// Each secret share received from the `dkg_part2` process must be validated using this method before proceeding to `dkg_part3`.
///
/// If `dkg_part3` fails, it automatically validates the received shares and throws an error if validation fails.
/// To identify which party acted maliciously, all received shares from each partner should be re-validated after a `dkg_part3` failure.
///
/// ### Inputs:
/// - `id`: A pointer to the unique identifier of the participant receiving the share.
/// - `share_buff`: A buffer containing received secret share.
/// - `commitment_buff`: A buffer contains the received commitment associated with the share.
///
/// ### Output:
/// - Returns a pointer to buffer containing boolean json str
const uint8_t *dkg_verify_secret_share(const uint8_t *id,
                                       const uint8_t *share_buff,
                                       const uint8_t *commitment_buff);

const uint8_t *dkg_part3(const uint8_t *r2_sec_pkg_buf,
                         const uint8_t *r1_pkgs_buf,
                         const uint8_t *r2_pkgs_buf);

const uint8_t *keys_generate_with_dealer(uint16_t max_signers, uint16_t min_signers);

const uint8_t *keys_split(const uint8_t *secret_buff, uint16_t max_signers, uint16_t min_signers);

const uint8_t *keys_reconstruct(const uint8_t *secret_shares_buff, uint16_t min_signers);

const uint8_t *get_pubkey(const uint8_t *secret_buff);

const uint8_t *key_package_from(const uint8_t *secret_share);

const uint8_t *round1_commit(const uint8_t *secret_buf);

const uint8_t *signing_package_new(const uint8_t *signing_commitments_buf, const uint8_t *msg);

const uint8_t *round2_sign(const uint8_t *signing_package_buf,
                           const uint8_t *signer_nonces_buf,
                           const uint8_t *key_package_buf);

const uint8_t *round2_sign_with_tweak(const uint8_t *signing_package_buf,
                                      const uint8_t *signer_nonces_buf,
                                      const uint8_t *key_package_buf,
                                      const uint8_t *merkle_root_buf);

const uint8_t *verify_share(const uint8_t *identifier_buf,
                            const uint8_t *verifying_share_buf,
                            const uint8_t *signature_share_buf,
                            const uint8_t *signing_package_buf,
                            const uint8_t *verifying_key_buf);

const uint8_t *aggregate(const uint8_t *signing_package_buf,
                         const uint8_t *signature_shares_buf,
                         const uint8_t *pubkey_package_buf);

const uint8_t *aggregate_with_tweak(const uint8_t *signing_package_buf,
                                    const uint8_t *signature_shares_buf,
                                    const uint8_t *pubkey_package_buf,
                                    const uint8_t *merkle_root_buf);

const uint8_t *pubkey_package_tweak(const uint8_t *pubkey_package_buf,
                                    const uint8_t *merkle_root_buf);

const uint8_t *key_package_tweak(const uint8_t *key_package_buf, const uint8_t *merkle_root_buf);

const uint8_t *verify_group_signature(const uint8_t *signature_buf,
                                      const uint8_t *msg_buf,
                                      const uint8_t *pubkey_package_buf);

void mem_free(const uint8_t *ptr);

}  // extern "C"

#endif  // FROST_SECP256K1_TR_LIB_H
