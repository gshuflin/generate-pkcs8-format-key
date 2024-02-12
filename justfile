_list:
    just --list

attempt-openssl-decrypt filename:
    openssl pkcs8 -topk8 -in {{filename}}
