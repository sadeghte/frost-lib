{
    "targets": [
        {
            "target_name": "addon",
            "sources": ["addon.cpp"],
      		"libraries": [ "<(module_root_dir)/../../lib/target/release/libfrost_ed25519.so" ],
            "include_dirs": [
                "<!@(node -p \"require('node-addon-api').include\")",
            ],
            "cflags!": ["-fno-exceptions"],
            "cflags_cc!": ["-fno-exceptions"],
      		"defines": [ "NAPI_DISABLE_CPP_EXCEPTIONS" ],
			"dependencies": [
				"<!(node -p \"require('node-addon-api').gyp\")"
			]
        }
    ]
}
