# MWixnet
This is an implementation of @tromp's [CoinSwap Proposal](https://forum.grin.mw/t/mimblewimble-coinswap-proposal/8322) with some slight modifications.

A set of n CoinSwap servers (N<sub>i</sub> with i=1...n) are agreed upon in advance. They each have a known public key.

We refer to the first server (N<sub>1</sub>) as the "Swap Server." This is the server that wallets can submit their coinswaps too.

We refer to the remaining servers (N<sub>2</sub>...N<sub>n</sub>) as "Mixers." 

### Setup
#### init-config
To setup a new server, run `mwixnet init-config`. Then enter a password for the server key when prompted.

This will generate a key for the server and then create a new config file named `mwixnet-config.toml` in the current working directory.
The configuration file will contain the private key of the server encrypted with the server password you provided.

**Back this config file up! It's the only copy of the server's private key!**

#### Wallet
A grin-wallet account must be created for receiving extra mwixnet fees. The wallet's owner API should be available (run `grin-wallet owner_api`).

### Usage
With your wallet and fully synced node both online and listening at the addresses configured, the mwixnet server can be started by running `mwixnet` and providing the server key password and wallet password when prompted.

### SWAP API
The Swap Server (N<sub>1</sub>) provides the `swap` API, which is publicly available for use by GRIN wallets.

**jsonrpc:** `2.0`
**method:** `swap`
**params:**
```
[{
    "comsig": "0835f4b8b9cd286c9e35475f575c3e4ae71ceb4ff36598504662627afd628a17d6ba7dedb1aa4c47f0fabad026b76fc86d06f3bef8d0621b8ac4601d4b1b98401586ca3374a401508f32049212478ae91cfa474dfaa5ef2c3dd559d5a292e02334",
    "onion": {
        "commit": "099a8922343f242dd3da29935ba5bbc7e38bf68eccfb8c96aec87aec0535199139",
        "data":[
            "758bc7339edfe8a1f117ef2ef02de58b33d99e820ffd2c21a3d108f4cbdadfbcbc061b705fc351ae2fb34a855bb64180fe8b4913ea13b3bf826773e4b293166cdad1fdf59cadd7d33f73a8f3fc0f339a849f9c505c573d8cc2f006082d8f5bf2c2c84c18d5873a821d9f60bcdd44cf0566d04d761a1eda005cd19ab0b1c593da4656dd2a09322fe1d725f61e8855c927844ec9e80b9260a58012f7c519c5ca3d9b192ab1104d30ac09fb844bd7f692214e5cf0f6cdf1477c20708c2f3ecb098dce6be661907593918840b0fe8eb5043996dace45f2fb66e8f1e2a732035b4e6447b8904f313badebcba99f75c003e297d8dd815915f534dfa7ed416af0c415b60d2a0186752af6af33b781f31fdd3016aeee3bd2e47743fe2ce391b3354b9036b56ec38ed7539adafbc96bef1dbaf354a805b03ac0df7a0d32cff91716926bce68c8ccebb607340f2ffe09c08a9c9fd282ea19b33c69107ed5c54d4872eb0ed83c38d7e07606722069d7709fb914e1e02ea23323f3ae9252902dbfa6f15bd83a3f64587c9ae23aaf96b2a95e1341da12a6e423cf95375184752e10c1dd1a599db74ac0c3d74ec270c589f6a3bdd0877eb986d9a58a8548b917e22bfb93a4a06c36d7cad8d4a8791a8d1e1dc683429b440b136c43ad2f664dafc5156b808050a3c4d28771877d3f1d3a9daa2585eae259aaa64745c6cd260f577e538e27be3c985db41b7c456b63c5b18d7d17420a277d4abc04ae892ceb26940b09fb322445846c14898f5f59305490b1338c56384cd0c7bf5950a0a403aec4d2c2f5e2378b5eb7b1e7fcdbd8d6cc547f3b5a372b22e50e37d858bb197392a10fb9e6e292d6ed6bd8eab1fef7f2d069b6250a0e3e597ccf9a062e04b68821f5c57328ddab775d141147b71c1764c911bad03d8b88e2e62034bc899395514ecab4dec8ab341ba114f0a4e5d1dcfa182396c0e4826ddee187b07bb524dfeaa5297f7a5465f99eaaaa37f082c787b94811feb15b57d68369e6a7e3761d"
        ],
        "pubkey": "033946e6a495e7278027b38be3d500cfc23d3e0836f1b7e24513841437f316ccb0"
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