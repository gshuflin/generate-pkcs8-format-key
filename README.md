Run `cargo run` to execute the program. It should generate two keypair files, both
encrypted using the password "test".

Run `openssl -- pkey -in $FILENAME.der -inform der` on either of the keypair files
to demonstrate `openssl` being unable to read the key from these files.
