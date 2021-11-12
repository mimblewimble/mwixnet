# MWixnet
MW CoinSwap Server

## APIs
### swap
The server configured to be the entry server (node 1) exposes a JSON-RPC `swap` API for use by GRIN wallets.

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