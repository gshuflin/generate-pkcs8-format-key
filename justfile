_list:
    just --list

attempt-openssl-decrypt:
    nix run nixpkgs#openssl -- pkey -in output-zebra.der -inform der

attempt-openssl-decrypt-pkcs8:
    nix run nixpkgs#openssl -- pkcs8 -in output-zebra.der -inform der -topk8
