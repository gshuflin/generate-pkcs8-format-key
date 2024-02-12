Run `cargo run` to execute the program. It should generate four keypair files, all
encrypted using the password "test".

Run `just attempt-openssl-decrypt {{filename}}` to run the openssl command that should
prompt for the password and print out a representation of the key. Instead of succeeding,
openssl unexpectedly throws an error with all four files.
