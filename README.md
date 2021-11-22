# MWixnet
This is an implementation of @tromp's [CoinSwap Proposal](https://forum.grin.mw/t/mimblewimble-coinswap-proposal/8322) with some slight modifications.

A set of n CoinSwap servers (node<sub>i</sub> with i=1...n) are agreed upon in advance. They each have a known public key.

### SWAP API
The first CoinSwap server (n<sub>1</sub>) provides the `swap` API, publicly available for use by GRIN wallets.

**jsonrpc:** `2.0`
**method:** `swap`
**params:**
```
[{
    "comsig": "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f",
    "msg": "00010203",
    "onion": {
        "commit": "0967593792bc958cd73848c0b948ecab2c6e996ab3c550d462fe41359e447b651f",
        "data": ["3719e5fba260c71a5a4bcf9d9caa58cd5dc49531388782fae7699c6fa6b30b09fe42"],
        "pubkey": "020dd38a220280f14515f6901a3a366cb7b87630814e4b68b3189a32df964961e5"
    }
}]
```

### Data Provisioning
#### Inputs
* C<sub>in</sub>: UTXO commitment to swap
* x<sub>in</sub>: Blinding factor of C<sub>in</sub>
* K<sub>1...n</sub>: The public keys of all n servers

#### Procedure
<ol>
    <li>Choose random x<sub>i</sub> for each node n<sub>i</sub> and create a Payload (P<sub>i</sub>) for each containing x<sub>i</sub></li>
    <li>Build a rangeproof for C<sub>n</sub>=C<sub>in</sub>+(Σx<sub>1...n</sub>)*G and include it in payload P<sub>n</sub></li>
    <li>Choose random initial ephemeral keypair (r<sub>1</sub>, R<sub>1</sub>)</li>
    <li>Derive remaining ephemeral keypairs such that r<sub>i+1</sub>=r<sub>i</sub>*Sha256(R<sub>i</sub>||s<sub>i</sub>) where s<sub>i</sub>=ECDH(R<sub>i</sub>, K<sub>i</sub>)</li>
    <li>For each node n<sub>i</sub>, use ChaCha20 stream cipher with key=HmacSha256("MWIXNET"||s<sub>i</sub>) and nonce "NONCE1234567" to encrypt payloads P<sub>i...n</sub></li>
</ol>

### Input Validation

* Node n<sub>1</sub> verifies that C<sub>in</sub> is in the current UTXO set
* Node n<sub>1</sub> verifies the commitment signature is valid for C<sub>in</sub>, proving ownership of the input

----

`Output derivation`, `Output validation`, `Kernel derivation`, and `Aggregation` steps remain unchanged from the [original design](https://forum.grin.mw/t/mimblewimble-coinswap-proposal/8322)