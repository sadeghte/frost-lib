// frost_ed25519.cpp
#include <napi.h>
#include <iostream>
#include <cstring>
#include <cstdlib>
#include <iomanip> 
// #include "../../frost-ed25519/frost-ed25519-lib.h" // Include the header file

#ifdef FROST_LIB_HEADER
    #include FROST_LIB_HEADER
#endif


void printBuffer(const uint8_t *buffer) {
    if (buffer == nullptr) {
        std::cerr << "Buffer is null" << std::endl;
        return;
    }

    // Read the length from the first two bytes
    uint16_t length = (buffer[0] << 8) | buffer[1]; // Combine the bytes to get the length

    // Print the length for debugging
    std::cout << "Length of content: " << length << std::endl;

    // Convert the content to a string
    std::string content(reinterpret_cast<const char *>(buffer + 2), length);

    // Print the content as a string
    std::cout << "[" << length << "]:" << content << std::endl;
}

Napi::Value jsonParse(const Napi::CallbackInfo& info, std::string& json_string) {
	Napi::Env env = info.Env();
    // Get string that represents your json
    // Napi::String json_string = info[0].As<Napi::String>();
    Napi::Object json = env.Global().Get("JSON").As<Napi::Object>();
    Napi::Function parse = json.Get("parse").As<Napi::Function>();
    Napi::Value json_obj = parse.Call(json, { Napi::String::New(env, json_string) });
    // Now you can do whatever you want with the object I'm simply returning it back
    return json_obj;
}

// Napi::Value jsonStringify(const Napi::CallbackInfo& info) {
//     // Get string that represents your json
//     Napi::Object json_obj = info[0].As<Napi::Object>();
//     Object json = env.Global().Get("JSON").As<Object>();
//     Function stringify = json.Get("stringify").As<Function>();
//     Napi::String json_string = parse.Call(json, { json_obj });
//     // Now you can do whatever you want with the string I'm simply returning it back
//     return json_string;
// }

Napi::Object getJsonAndFreeMem(const Napi::CallbackInfo& info, const uint8_t* ptr) {
    // Extract the length from the first two bytes of the JSON data
    uint16_t json_len = (ptr[0] << 8) | ptr[1];
    std::string json_str(reinterpret_cast<const char*>(ptr+2), json_len);
    
    Napi::Value json_obj = jsonParse(info, json_str);

	// Check if the parsed JSON is an object and if it has an "error" key
    if (json_obj.IsObject()) {
        Napi::Object json_object = json_obj.As<Napi::Object>();
        if (json_object.Has("error")) {
            Napi::Value error_value = json_object.Get("error");
            if (error_value.IsString()) {
                // Throw an error with the "error" value as the message
                std::string error_message = error_value.As<Napi::String>().Utf8Value();
                mem_free(ptr); // Free the memory before throwing
                Napi::Error::New(info.Env(), error_message).ThrowAsJavaScriptException();
                return Napi::Object::New(info.Env()); // Return empty object (not reached after throw)
            }
        }
    }
    
    // Free the allocated memory
    mem_free(ptr); // Free the memory, adjusting for the length prefix
    return json_obj.As<Napi::Object>();
}

Napi::Object NumToId(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

	// Check the number of arguments
    if (info.Length() < 1) {
        Napi::TypeError::New(env, "num_to_id needs one argument").ThrowAsJavaScriptException();
        return env.Null().As<Napi::Object>();
    }

	u_int64_t num = info[0].As<Napi::Number>().Int64Value();

	const uint8_t *ptr = num_to_id(num);

    return getJsonAndFreeMem(info, ptr);
}

Napi::Object DkgPart1(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

	// Check the number of arguments
    if (info.Length() < 3) {
        Napi::TypeError::New(env, "dkg_part1 needs three arguments").ThrowAsJavaScriptException();
        return env.Null().As<Napi::Object>();
    }

	const uint8_t *identifier = info[0].As<Napi::Buffer<uint8_t>>().Data();
	u_int16_t maxSigners = info[1].As<Napi::Number>().Uint32Value();
	u_int16_t minSigners = info[2].As<Napi::Number>().Uint32Value();

	const uint8_t *ptr = dkg_part1(identifier, maxSigners, minSigners);

    return getJsonAndFreeMem(info, ptr);
}

Napi::Object VerifyProofOfKnowledge(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

	// Check the number of arguments
    if (info.Length() < 3) {
        Napi::TypeError::New(env, "verify_proof_of_knowledge needs three arguments").ThrowAsJavaScriptException();
        return env.Null().As<Napi::Object>();
    }

	const uint8_t *identifier = info[0].As<Napi::Buffer<uint8_t>>().Data();
	const uint8_t *commitments = info[1].As<Napi::Buffer<uint8_t>>().Data();
	const uint8_t *signature = info[2].As<Napi::Buffer<uint8_t>>().Data();

	const uint8_t *ptr = verify_proof_of_knowledge(identifier, commitments, signature);

    return getJsonAndFreeMem(info, ptr);
}

Napi::Object DkgPart2(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

	// Check the number of arguments
    if (info.Length() < 2) {
        Napi::TypeError::New(env, "dkg_part2 needs two arguments").ThrowAsJavaScriptException();
        return env.Null().As<Napi::Object>();
    }

	const uint8_t *round1SecretPackage = info[0].As<Napi::Buffer<uint8_t>>().Data();
	const uint8_t *round1Packages = info[1].As<Napi::Buffer<uint8_t>>().Data();

	const uint8_t *ptr = dkg_part2(round1SecretPackage, round1Packages);

    return getJsonAndFreeMem(info, ptr);
}

Napi::Object DkgVerifySecretShare(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

	// Check the number of arguments
    if (info.Length() < 3) {
        Napi::TypeError::New(env, "dkg_verify_secret_share needs three arguments").ThrowAsJavaScriptException();
        return env.Null().As<Napi::Object>();
    }

	const uint8_t *identifier = info[0].As<Napi::Buffer<uint8_t>>().Data();
	const uint8_t *secret_share = info[1].As<Napi::Buffer<uint8_t>>().Data();
	const uint8_t *commitment = info[2].As<Napi::Buffer<uint8_t>>().Data();

	const uint8_t *ptr = dkg_verify_secret_share(identifier, secret_share, commitment);

    return getJsonAndFreeMem(info, ptr);
}

Napi::Object DkgPart3(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

	// Check the number of arguments
    if (info.Length() < 3) {
        Napi::TypeError::New(env, "dkg_part3 needs three arguments").ThrowAsJavaScriptException();
        return env.Null().As<Napi::Object>();
    }

	const uint8_t *round2SecretPackage = info[0].As<Napi::Buffer<uint8_t>>().Data();
	const uint8_t *round1Packages = info[1].As<Napi::Buffer<uint8_t>>().Data();
	const uint8_t *round2Packages = info[2].As<Napi::Buffer<uint8_t>>().Data();

	const uint8_t *ptr = dkg_part3(round2SecretPackage, round1Packages, round2Packages);

    return getJsonAndFreeMem(info, ptr);
}

Napi::Object KeysGenerateWithDealer(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

	// Check the number of arguments
    if (info.Length() < 2) {
        Napi::TypeError::New(env, "keys_generate_with_dealer needs two arguments").ThrowAsJavaScriptException();
        return env.Null().As<Napi::Object>();
    }

	u_int16_t max_signers = info[0].As<Napi::Number>().Uint32Value();
	u_int16_t min_signers = info[1].As<Napi::Number>().Uint32Value();

	// Call the keys_generate_with_dealer function from the shared library
    const uint8_t* ptr = keys_generate_with_dealer(max_signers, min_signers);
    if (ptr == nullptr) {
        Napi::TypeError::New(env, "Failed to generate keys").ThrowAsJavaScriptException();
        return env.Null().As<Napi::Object>();
    }

    return getJsonAndFreeMem(info, ptr);
}

Napi::Object KeysSplit(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

	// Check the number of arguments
    if (info.Length() < 3) {
        Napi::TypeError::New(env, "keys_split needs tree arguments").ThrowAsJavaScriptException();
        return env.Null().As<Napi::Object>();
    }

	const uint8_t *secret = info[0].As<Napi::Buffer<uint8_t>>().Data();
	u_int16_t max_signers = info[1].As<Napi::Number>().Uint32Value();
	u_int16_t min_signers = info[2].As<Napi::Number>().Uint32Value();

	// Call the keys_generate_with_dealer function from the shared library
    const uint8_t* ptr = keys_split(secret, max_signers, min_signers);
    if (ptr == nullptr) {
        Napi::TypeError::New(env, "Failed to split keys").ThrowAsJavaScriptException();
        return env.Null().As<Napi::Object>();
    }

    return getJsonAndFreeMem(info, ptr);
}

Napi::Object KeyPackageFrom(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

	// Check the number of arguments
    if (info.Length() < 1) {
        Napi::TypeError::New(env, "key_package_from needs one argument").ThrowAsJavaScriptException();
        return env.Null().As<Napi::Object>();
    }

	const uint8_t *secretShare = info[0].As<Napi::Buffer<uint8_t>>().Data();

	// Call the keys_generate_with_dealer function from the shared library
    const uint8_t* ptr = key_package_from(secretShare);
    if (ptr == nullptr) {
        Napi::TypeError::New(env, "Failed to call key_package_from").ThrowAsJavaScriptException();
        return env.Null().As<Napi::Object>();
    }

    return getJsonAndFreeMem(info, ptr);
}

Napi::Object Round1Commit(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

	// Check the number of arguments
    if (info.Length() < 1) {
        Napi::TypeError::New(env, "round1_commit needs one argument").ThrowAsJavaScriptException();
        return env.Null().As<Napi::Object>();
    }

	const uint8_t *signingShare = info[0].As<Napi::Buffer<uint8_t>>().Data();

	// Call the keys_generate_with_dealer function from the shared library
    const uint8_t* ptr = round1_commit(signingShare);
    if (ptr == nullptr) {
        Napi::TypeError::New(env, "Failed to call round1_commit").ThrowAsJavaScriptException();
        return env.Null().As<Napi::Object>();
    }

    return getJsonAndFreeMem(info, ptr);
}

Napi::Object SigningPackageNew(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

	// Check the number of arguments
    if (info.Length() < 2) {
        Napi::TypeError::New(env, "signing_package_new needs two argument").ThrowAsJavaScriptException();
        return env.Null().As<Napi::Object>();
    }

	const uint8_t *commitmentsMap = info[0].As<Napi::Buffer<uint8_t>>().Data();
	const uint8_t *message = info[1].As<Napi::Buffer<uint8_t>>().Data();

	// Call the keys_generate_with_dealer function from the shared library
    const uint8_t* ptr = signing_package_new(commitmentsMap, message);
    if (ptr == nullptr) {
        Napi::TypeError::New(env, "Failed to call signing_package_new").ThrowAsJavaScriptException();
        return env.Null().As<Napi::Object>();
    }

    return getJsonAndFreeMem(info, ptr);
}

Napi::Object Round2Sign(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

	// Check the number of arguments
    if (info.Length() < 3) {
        Napi::TypeError::New(env, "round2_sign needs three arguments").ThrowAsJavaScriptException();
        return env.Null().As<Napi::Object>();
    }
	
	const uint8_t *signingPackage = info[0].As<Napi::Buffer<uint8_t>>().Data();
	const uint8_t *nonces = info[1].As<Napi::Buffer<uint8_t>>().Data();
	const uint8_t *keyPackage = info[2].As<Napi::Buffer<uint8_t>>().Data();

	const uint8_t *ptr = round2_sign(signingPackage, nonces, keyPackage);

    return getJsonAndFreeMem(info, ptr);
}

Napi::Object Aggregate(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

	// Check the number of arguments
    if (info.Length() < 3) {
        Napi::TypeError::New(env, "aggregate needs three arguments").ThrowAsJavaScriptException();
        return env.Null().As<Napi::Object>();
    }
	
	const uint8_t *signingPackage = info[0].As<Napi::Buffer<uint8_t>>().Data();
	const uint8_t *signatureShares = info[1].As<Napi::Buffer<uint8_t>>().Data();
	const uint8_t *pubkeyPackage = info[2].As<Napi::Buffer<uint8_t>>().Data();

	const uint8_t *ptr = aggregate(signingPackage, signatureShares, pubkeyPackage);

    return getJsonAndFreeMem(info, ptr);
}

Napi::Object VerifyGroupSignature(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

	// Check the number of arguments
    if (info.Length() < 3) {
        Napi::TypeError::New(env, "verify_group_signature needs three arguments").ThrowAsJavaScriptException();
        return env.Null().As<Napi::Object>();
    }
	
	const uint8_t *groupSignature = info[0].As<Napi::Buffer<uint8_t>>().Data();
	const uint8_t *message = info[1].As<Napi::Buffer<uint8_t>>().Data();
	const uint8_t *pubkeyPackage = info[2].As<Napi::Buffer<uint8_t>>().Data();

	const uint8_t *ptr = verify_group_signature(groupSignature, message, pubkeyPackage);

    return getJsonAndFreeMem(info, ptr);
}

#ifdef FROST_SECP256K1_TR_LIB_H
Napi::Object Round2SignWithTweak(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

	// Check the number of arguments
    if (info.Length() < 4) {
        Napi::TypeError::New(env, "round2_sign_with_tweak needs four arguments").ThrowAsJavaScriptException();
        return env.Null().As<Napi::Object>();
    }
	
	const uint8_t *signingPackage = info[0].As<Napi::Buffer<uint8_t>>().Data();
	const uint8_t *nonces = info[1].As<Napi::Buffer<uint8_t>>().Data();
	const uint8_t *keyPackage = info[2].As<Napi::Buffer<uint8_t>>().Data();
	const uint8_t *merkleRoot = info[3].As<Napi::Buffer<uint8_t>>().Data();

	const uint8_t *ptr = round2_sign_with_tweak(signingPackage, nonces, keyPackage, merkleRoot);

    return getJsonAndFreeMem(info, ptr);
}

Napi::Object AggregateWithTweak(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

	// Check the number of arguments
    if (info.Length() < 4) {
        Napi::TypeError::New(env, "aggregate_with_tweak needs four arguments").ThrowAsJavaScriptException();
        return env.Null().As<Napi::Object>();
    }
	
	const uint8_t *signingPackage = info[0].As<Napi::Buffer<uint8_t>>().Data();
	const uint8_t *signatureShares = info[1].As<Napi::Buffer<uint8_t>>().Data();
	const uint8_t *pubkeyPackage = info[2].As<Napi::Buffer<uint8_t>>().Data();
	const uint8_t *merkleRoot = info[3].As<Napi::Buffer<uint8_t>>().Data();

	const uint8_t *ptr = aggregate_with_tweak(signingPackage, signatureShares, pubkeyPackage, merkleRoot);

    return getJsonAndFreeMem(info, ptr);
}

Napi::Object PubkeyPackageTweak(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

	// Check the number of arguments
    if (info.Length() < 2) {
        Napi::TypeError::New(env, "pubkey_package_tweak needs two arguments").ThrowAsJavaScriptException();
        return env.Null().As<Napi::Object>();
    }
	
	const uint8_t *pubkeyPackage = info[0].As<Napi::Buffer<uint8_t>>().Data();
	const uint8_t *merkleRoot = info[1].As<Napi::Buffer<uint8_t>>().Data();

	const uint8_t *ptr = pubkey_package_tweak(pubkeyPackage, merkleRoot);

    return getJsonAndFreeMem(info, ptr);
}
#endif

Napi::Object Init(Napi::Env env, Napi::Object exports) {
    exports.Set(Napi::String::New(env, "num_to_id"), Napi::Function::New(env, NumToId));
    exports.Set(Napi::String::New(env, "dkg_part1"), Napi::Function::New(env, DkgPart1));
    exports.Set(Napi::String::New(env, "verify_proof_of_knowledge"), Napi::Function::New(env, VerifyProofOfKnowledge));
    exports.Set(Napi::String::New(env, "dkg_part2"), Napi::Function::New(env, DkgPart2));
    exports.Set(Napi::String::New(env, "dkg_verify_secret_share"), Napi::Function::New(env, DkgVerifySecretShare));
    exports.Set(Napi::String::New(env, "dkg_part3"), Napi::Function::New(env, DkgPart3));
    exports.Set(Napi::String::New(env, "keys_generate_with_dealer"), Napi::Function::New(env, KeysGenerateWithDealer));
    exports.Set(Napi::String::New(env, "keys_split"), Napi::Function::New(env, KeysSplit));
    exports.Set(Napi::String::New(env, "key_package_from"), Napi::Function::New(env, KeyPackageFrom));
    exports.Set(Napi::String::New(env, "round1_commit"), Napi::Function::New(env, Round1Commit));
    exports.Set(Napi::String::New(env, "signing_package_new"), Napi::Function::New(env, SigningPackageNew));
    exports.Set(Napi::String::New(env, "round2_sign"), Napi::Function::New(env, Round2Sign));
    exports.Set(Napi::String::New(env, "aggregate"), Napi::Function::New(env, Aggregate));
    exports.Set(Napi::String::New(env, "verify_group_signature"), Napi::Function::New(env, VerifyGroupSignature));

#ifdef FROST_SECP256K1_TR_LIB_H
    exports.Set(Napi::String::New(env, "round2_sign_with_tweak"), Napi::Function::New(env, Round2SignWithTweak));
    exports.Set(Napi::String::New(env, "aggregate_with_tweak"), Napi::Function::New(env, AggregateWithTweak));
    exports.Set(Napi::String::New(env, "pubkey_package_tweak"), Napi::Function::New(env, PubkeyPackageTweak));
#endif

	return exports;
}

// NODE_API_MODULE(NODE_GYP_MODULE_NAME, Init)
NODE_API_MODULE(node_addon, Init)
