// frost_ed25519.cpp
#include <napi.h>
#include <iostream>
#include <cstring>
#include <cstdlib>
#include <iomanip> 
#include "frost-ed25519-lib.h" // Include the header file


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
    
    // Free the allocated memory
    mem_free(ptr, json_len + 2); // Free the memory, adjusting for the length prefix
    return json_obj.As<Napi::Object>();
}

Napi::Object KeysGenerateWithDealer(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

	// Check the number of arguments
    if (info.Length() < 2) {
        Napi::TypeError::New(env, "keys_generate_with_dealer needs two arguments").ThrowAsJavaScriptException();
        return env.Null().As<Napi::Object>();
    }

	u_int16_t min_signers = info[0].As<Napi::Number>().Uint32Value();
	u_int16_t max_signers = info[1].As<Napi::Number>().Uint32Value();

	// Call the keys_generate_with_dealer function from the shared library
    const uint8_t* ptr = keys_generate_with_dealer(min_signers, max_signers);
    if (ptr == nullptr) {
        Napi::TypeError::New(env, "Failed to generate keys").ThrowAsJavaScriptException();
        return env.Null().As<Napi::Object>();
    }

    return getJsonAndFreeMem(info, ptr);
}

Napi::Object Init(Napi::Env env, Napi::Object exports) {
    exports.Set(Napi::String::New(env, "keys_generate_with_dealer"), Napi::Function::New(env, KeysGenerateWithDealer));
	return exports;
}

// NODE_API_MODULE(NODE_GYP_MODULE_NAME, Init)
NODE_API_MODULE(node_addon, Init)
