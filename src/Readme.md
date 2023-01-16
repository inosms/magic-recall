### Memo

#### Upon Creation

1. Generate local libp2p id (ed25519)
2. Generate local age key pair
3. Generate recovery age key pair and save to yubikey 
4. Create json containing (1) and (2) and encrypt with (3) and sign with (1)
    * require correct sign on modification
5. Put (4) in DHT with key = hash of public key of (3) 
6. Put peer configuration in json and encrypt with local key pair
7. Put (5) in DHT with key = random cryptographic hash (store in (4))

#### Add New Recovery Key
1. Generate age key pair and save to yubikey
2. Continue with steps from `Upon Creation`

#### Upon Recovery
1. Recall encrypted json with hash of public age key
2. Decrypt file with private key
3. Recreate libp2p id
4. Recall configuration tied to local node containing connected peer ids


??