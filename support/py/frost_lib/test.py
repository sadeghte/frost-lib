import solana
import base58
from nacl.signing import VerifyKey;
from solana.transaction import Pubkey

def verify_signature(public_key_bytes, message, signature_bytes):
    try:
        # Create a VerifyKey object from the public key bytes
        verify_key = VerifyKey(public_key_bytes)
        
        # Verify the signature for the message
        verify_key.verify(message, signature_bytes)
        return True  # Signature is valid
    except Exception:
        return False  # Signature verification failed

msg = b"message to sign"
signature_str = "0f5adaae08d48cde3869b972e0d50f79b2982e56c9489b3ef8c0859fa0a19e866c90437604727e308f8c04b65f0643cf85eee5f813997813e8c1bdf962834a0e"
pubkey_str = "18557b7e268264b32e017003e2bc85552c348956773aee5b80e71a6527282382"
# public_key = solana.transaction.Pubkey.from_string("")

public_key_bytes = bytes.fromhex(pubkey_str)
signature_bytes = bytes.fromhex(signature_str)

verify_key = VerifyKey(public_key_bytes)
    
# Verify the signature for the message
verified_correct = verify_signature(public_key_bytes, msg, signature_bytes);
verified_incorrect = verify_signature(public_key_bytes, b"wrong message", signature_bytes);

print("vorrect message verified: ", verified_correct)
print("  wrong message verified: ", verified_incorrect)

