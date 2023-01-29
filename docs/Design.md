# Design

## Keys

### Creation

1. Create local ed25519 libp2p identity (`lipp2plocal`)
1. Create local age keypair (`agelocal`)

For every external keypair (at least one! e.g. yubikey, paperkey)
1. Create recovery ed25519 keypair for recovery (`signrecovery{n}`)
1. Create recovery age keypair for recovery (`agerecovery{n}`)

Save the hash of the public id of `signrecovery` (A) and the public key of `signrecovery` (B) locally and distribute it to peers so they can announce the backups with (A) and identify the peer with (B).


### Recovery

1. Load age id of `agerecovery` from recovery device (or paperkey) and search the network with hash as key
1. When a peer is found request backups from the peer and sign the request with `signrecovery`
1. The contacted peer should check the sign and if correct send the encrypted backup index file (and some metadata) to the peer. 


### Adding New Recovery Keys

Adding new recovery keys requires the backups to be encrypted again.