# Onion Routing

## Overview

The Onion Routing scheme in this context is a method of encrypting and routing transactions in a privacy-preserving manner. At each step, a server peels off a layer of encryption, revealing information intended for it, and passes on the rest of the data to the next server.

The main component in this encryption scheme is an `Onion`, which contains encrypted payloads, an ephemeral public key and an output commitment.

## Data Structures

### `Hop` structure

Each `Hop` represents a step in the routing process, which has its own unique encryption parameters. A `Hop` consists of:

- `server_pubkey`: The public key of the server for this hop.
- `excess`: An additional blinding factor to add to the commitment.
- `fee`: The transaction fee for this hop.
- `rangeproof`: An optional rangeproof, included only for the final hop.

### `Onion` structure

An `Onion` represents a complete route at a particular stage. It contains:

- `ephemeral_pubkey`: The ephemeral public key for the server that is next in line to peel off a layer of the onion.
- `commit`: The modified commitment at this stage in the routing process, which will be the original commitment for the first server in the chain, and then will be a recalculated commitment at each following stage.
- `enc_payloads`: The list of encrypted payloads for each remaining hop in the route.

The `commit` in an `Onion` will be the original unspent output's commitment for the very first `Onion` object sent to the swap server, but then for each peeled layer (i.e., after each hop), a new `Onion` object will be created with a recalculated commitment. This new commitment reflects the additional blinding factor and subtracted fee at each stage. The `Onion` passed from one server to the next then contains this adjusted commitment, not the original one.

### `Payload` structure

Each encrypted payload contains the information needed by a server to process the hop. This includes:

- `next_ephemeral_pk`: The ephemeral public key for the next hop.
- `excess`: The additional blinding factor for the commitment at this hop.
- `fee`: The transaction fee for this hop.
- `rangeproof`: A rangeproof if the payload is for the final hop.
  Absolutely, let's go into more detail on the cryptographic methods utilized during the creation and peeling of the Onion.

### Creating an Onion

The creation of the Onion involves both symmetric and asymmetric encryption techniques:

1. **Ephemeral keys:** For each hop (server) in the network, an ephemeral secret key is randomly generated. These ephemeral keys are used to create shared secrets with the server's public key through the Diffie-Hellman key exchange. The first ephemeral public key is included in the Onion, and each subsequent ephemeral public key is encrypted and included in the payload for the previous server.

2. **Shared secrets:** A shared secret is generated between the sender (the client) and each server (hop) in the path. This is done using the Elliptic Curve Diffie-Hellman (ECDH) method. The shared secret for each server is calculated from the server's public key and the client's ephemeral secret key.

3. **Payload encryption:** Detailed in the next section.

### Payload Encryption with ChaCha20 Cipher

After the shared secrets are created, they are used to derive keys for symmetric encryption with the ChaCha20 cipher. Here is the process:

1. **Key derivation:** An HMAC-SHA-256 is used as a key derivation function (KDF). The shared secret is fed into this HMAC function with a constant key of "MWIXNET". The HMAC is used here as a pseudo-random function (PRF) to derive a 256-bit key from the shared secret. The purpose of using HMAC in this manner is to ensure that the output key is indistinguishable from random data, assuming the shared secret is also indistinguishable from random data. The output of the HMAC function is a 256-bit key.

2. **Nonce:** A nonce is a random or pseudo-random value that is meant to prevent replay attacks. For the ChaCha20 cipher, a 12-byte nonce is used. In this case, a static nonce of "NONCE1234567" is used. This means that the security of the cipher relies solely on the never-reusing any key more than once, since the nonce is not being used as an input of randomness.

3. **ChaCha20 Initialization**: The derived key and static nonce are used to initialize the ChaCha20 cipher.

4. **Payload Encryption**  Each server's payload is encrypted with all the shared secrets of that server and all previous servers, in reverse order. This means the payload for the first server is encrypted once, the second server's payload is encrypted twice, and so on, creating the layered "onion" encryption.

```rust
fn new_stream_cipher(shared_secret: &SharedSecret) -> Result<ChaCha20, OnionError> {
    let mut mu_hmac = HmacSha256::new_from_slice(b"MWIXNET")?;
    mu_hmac.update(shared_secret.as_bytes());
    let mukey = mu_hmac.finalize().into_bytes();

    let key = Key::from_slice(&mukey[0..32]);
    let nonce = Nonce::from_slice(b"NONCE1234567");

    Ok(ChaCha20::new(&key, &nonce))
}
```

### Peeling an Onion

The peeling of the Onion is basically the decryption process that happens at each server:

1. **Shared secret:** The server creates a shared secret using its own private key and the client's ephemeral public key.

2. **Decryption:** The server uses the shared secret to derive a key for the ChaCha20 cipher. It then uses this to decrypt the payloads. Because of the layered encryption, each server can only decrypt the first remaining payload in the Onion, which reveals the payload intended for that server, while leaving the other payloads still encrypted.

3. **Payload extraction:** After decryption, the server extracts its fee, excess, and the next server's ephemeral public key from its payload. If the server is the last one in the chain, it also receives a rangeproof.

4. **Commitment recalculation:** Using the excess and fee from the decrypted payload, the server recalculates the commitment. The new commitment is `C' = (C - fee*H + excess*G)`, where `C` is the previous commitment, `H` is the hash of a known value and `G` is the generator of the elliptic curve group.

5. **New Onion creation:** The server creates a new Onion with the recalculated commitment, the next server's ephemeral public key, and the remaining still-encrypted payloads (minus the server's own decrypted payload).

This process repeats until the Onion reaches the final server in the path. The final server, after peeling its layer, should find the commitment matches the provided rangeproof, thus ensuring the integrity of the transaction and the anonymity of the involved parties.

### 2-Hop Example

Initial output:

```json
{
  "value": 1000,
  "blind": "c2df4d2331659e8e9c780d27309dba453e34ef48f6e38aab1be50545a0431f95",
  "commit": "0899dadc2b75d66d738b7dbfcba4a37460622dcedaf222e688a2a84826eaa1cff1"
}

```

Server keys:

```json
[
  {
    "sk": "a129111d283b13bf93957c06bf6605c3417b4b89db4b5cb2e7dab2c15e36e0a4",
    "pk": "96ced236bdf1aca722ef68b818445755e6ed4bacf23e19d7b71c43efc5f0077b"
  },
  {
    "sk": "2231414c56488b3596bb56b555ce1b4f8f6ed6b128914760ff89cd42c3d38ad6",
    "pk": "a2fa3c7043e5080429bdcfb48fb6a8502bca77139d88c6603c9a75234fd6c718"
  }
]
```

For the first hop, the user provides:
```json
{
  "server_pubkey": "96ced236bdf1aca722ef68b818445755e6ed4bacf23e19d7b71c43efc5f0077b",
  "excess": "a9f15dc4760a1a280f68c6fc16d8aeada415fd66d5da805ff05cac6857a09db4",
  "fee": 5,
  "rangeproof": "None"
}
```
The ephemeral key is randomly generated as
```json
{
  "sk": "e8debf70567d3240f5d8e7743e3d986962de4efdd8e638e9989a3afbbafaa85f",
  "pk": "808ed260a56fe8910444dce931e2d67be0d2c6518134643450d2b9db9dfe7c26"
}
```

For the second hop, the user provides:
```json
{
  "server_pubkey": "a2fa3c7043e5080429bdcfb48fb6a8502bca77139d88c6603c9a75234fd6c718",
  "excess": "d777cf064daf8929e66d2dfc6898fd0cf0774d8546bccb40699c8c47da215663",
  "fee": 5,
  "rangeproof": "b58e8833cf94a470423b3787193f6f3bd4e9c769eec7fb0030e6ec9747b1a796c6e84f21d88714c2d2e790c6f08d4599ecc766666be95b65c46b1c22ca98ba8206a92fe720ed2e7548e794cc41d2b38d409e19625936902e8a3d64905c08927abade0ed923158abd74b52ae0c302c4a53b58e42ccedc49f6a37133edd43a3fa544a704bf7fff2bd5bcd931e4176e30349b5e687486c8cefdc0418ba5e6d389934b78d619301a0a2ba911e57c88c26002da471c8a4827b0a80330fcc28b550f987329c534189d41869dd12ca5d04e7d283bf2d37bb5fe180cfd8f8fc76fd81a9c929f6c9688e8acc7ec7fb8d0633b362e2e080643b384f1fcad09894bc523bbe4539d76aae858a6dc822187f7e2cae3c41fe26ce4441f2a29b2d874689247c6b08e5c25b512bced45467592a092811b3dafb83b49857ddfddeced32d62dfa807f85a9c9262445e985a1e5f6c5cb723de7e4d8ffe1d9e546b27a7d3e0a30604f0cbce500d0122e5312cf46c09621c60b75a0ca33ad1f193cfb2289784a0ec65d22eaf0721faf556536723e6bc0c4127b86562db4921cadb384bd6f2a9262f3125ed7c90f4c7339cdeaf07d4b8f515306428142d81c27a7440a7dfaf7c79cdd9f2a75a3dfad995ec403dbf7a1cf0011cf1acf97c5f3b550dc2582633bf22cb743bb05565eb67c1d9229a644362f46f3b6fcc5283e765f34273770c0123ebc0463b123df7afa547257d9bbe2fce7d44bac396f8872dfbcb6eea357359a2f618b2a3e0e1cdf27316b5130bd9e36e2eb9c28f6b878f2f9802e4ab4950b3e0d158f596120144a76c4db95ee951146ffb15b3e0104897082c8bf4831d7b7a35a77c1729376ce0c46183ccd2957c9c0869b75dd4d90395ea3da024e0d5f490920ad1b18c68d9ac6cc874e782b7406ceffa48b218abe00ca9aa0c517b0c2dc49f1dc2bdfb4592dfa"
}
```

The generated onion becomes:
```json
{
    "commit": "0899dadc2b75d66d738b7dbfcba4a37460622dcedaf222e688a2a84826eaa1cff1",
    "data": [
		"d19f914e7a7b5ba1c0ab36d982bd0bc59aa651458a6ee86c2015b57d96424da4a41559069be5ba59e0d2b688f95f1dfb20648e21f9b01ac400cb4879f2ba434c8eb0337d3f58e9e643aa",
		"a5663659b17f48fba8a335e774f9968e7039db4ce67f3a9d11419e3cf24d96b1c1338d574ba8c6ac36e74b08aef0e61f0dacb5bb769aa76227f894cc49e5ac0f55800130f2a49509123963734ddf21db0fa4f662a3d37c7a0850f8c0c0dd31b26be9cce1e264d60b2240e52f465c7c2b14b11b77fbe3b2fa9bbe78e71df4083d554aa80bcfb1266bd2132ea5c5b356d54a166c16e38c66a58c19c85bb72d11e2097ab2cb13efb4f1de62b3fdf5ee90093de04e8e31e5ef036e155c3db4d7912240abd8807d26f6e9e116bfe90958a8f4347377ed774b1408adb217847efc9dc1bd0067d283a180757f5d23bcdb9e2a87dba903191ecf13ec9ff2e9bed2e774f68fa06f6f51b8f90895058ad3c699d44b9917d2b4b56096bd7885ca8d44d4b635bd975db07780006000faa40b59280aef2bf99088677f0d24efdddd670b7d0b713a9bec34f3c47cc74f594675174508061c7957fcbcf4a5f27ae9fc92f1e9d56f64a3cbcb1492c6845fd08ea04990234ea3cebf62c17f79d3a93fc6ab076fb02563579c903673759b89cfaffef68bf86daf7cb42939ee7fbc8a92e832fb0d7f8071d46323c95676d7e7821c40595d2db8dd7e29bf988eaca8f4ef6ed71a4084a01beea45497d0a5e06476c7092d7774fb4c6f9c52a0ab8bd4cc0d1569696f58deb521c2a11b774f4934fb171f3c2cf0cbfadb02c32a93a70895c5388f04824c486b5075cadf143594f46cb792145932d6a67845b5b744451517728df77f194fd5cbfda7dab160c329d7d340a2cbe3cd2accdecbd32494f75aed1892d65248124aaf9c82951edf49e46de1d80fa465ee70552d76b4f5e5f68d8bbac534f98454adc396050c9eaa7a782c3a27d6f2116a831e75cd1726b8b543738a084d7c1ee592aad80798461eb7a88ba5ea3ecf1a3329ffb7bdc882644efea1d97ceb10206356678e05aa555dd090a695da43e193ecaa239116ba1df350a86a508feb4e57696ec66f17864c394c06de614fe35c7417d51be837dfd2a1eabe135bb985be8d11847990dff17ba3f7b74a68cdfad6d83fec0700fc5fd5"
	],
    "pubkey": "808ed260a56fe8910444dce931e2d67be0d2c6518134643450d2b9db9dfe7c26"
}
```

This is provided to the swap (first) server, which uses its server secret key to peel one layer, resulting in:
```json
{
	"payload": {
		"next_ephemeral_pk": "5353ed848b8b2514aa08c8d9a5109ca4ddafe575c07a2a7cb2f19defa58d8442",
		"excess": "a9f15dc4760a1a280f68c6fc16d8aeada415fd66d5da805ff05cac6857a09db4",
		"fee": 5,
		"proof": "None"
	},
	"onion": {
		"commit":"08b045d9f160fd2528feb50e134a0873ae91a5ab7c44eb2a73ae246eee426bdbde",
		"data":[
			"1df9a17573e657575b3fe17a458adc83907a9c643f1121fc5e93ca06467adc1c26fab89974d4b906683625e78ea8b778d6f48628220515699e921e8ec8059f09f4bc81cf84ace0e01fe542b9181e3cb79e4242845cf2b8c0d9a23654bede0cd149e92a6be92fa039602f5e81be2bdaaf7580e1102dd7dfec3df9dbfd4cd6977321bb7212b60810c337c1f83cce1fe9d8a1d8780cbc650dd77082b427e21cae914745f3563557f21315ed16332d09bdeee1cd5b1981433449533e515bfa223202fe8343989f57b9dc783e99b03750be23fa3ba87d973b907b173fb8d8c0790e3db3689f560eaf95c7073e9b71c453261c2e5598cdfed2503200b527724cb1a7dec033bf48e220f1a46b8cf3dc6c961d0173d10b487154fefd850c4e04923ce924a743a8ff403699ca319756e09106d5af5005e214bb02d23d9df99d6ee01fc578ecd82334d3bfdb18eeb3592d98d66a232bc1eecee972cbdf7e2f9dbc60b8fed1767afbb94220efed6a7f7ad51bfd10bc81089e650ca175c0ff0c4b0f5d592fa3166a2689871a89665c17d94a2ce9a4d25f4d174befc0a4b66e72ae6b559ae5250c23806d002a51713800190c25e310aae57167803de7413783f607b8d6cfbb3071dcb6fec6a2bfacd7b0656e8e24060c1a20c9b201ab5d5875455098770d0c4d48ceac73c9d5d6d357fb8fe24d9de27f9bd461e7076c7a28dd1e961d1e373e6890b8d4cf697a8bc11c5b252370ce2be403306390c1bf0d2aaeb6ef5f62064fb87e7fccca5e8a503c8d35651a4fbcfce89e44bd8595dac54e45d11861ca075af49cfdd1dd0bc56085548c8605c6b1706cdbcdfca0d37a77732039cfb9f28b4e216d3cc996d0e69b184d33c54d162d63efa0d7d2738dbcd09690d99277be25ce758d3a90880565d3a03e7c6308a8eb0fbbb450259bf916e1802c72f1226ccd1444503a8ce95a4e296eec4ffbba47e6a41d94b5672499b98f77e72cbed7660e2a0d66598ccc81de1055130393158d4a04805797444b0d8cc713184120a554a130ed4179e51f98db094fab5b1e27accd4b3d2351ebad62"
		],
		"pubkey":"5353ed848b8b2514aa08c8d9a5109ca4ddafe575c07a2a7cb2f19defa58d8442"
	}
}
```

This is passed to the second server, which uses its server secret key to peel the last layer, resulting in:
```json
{
  "payload": {
    "next_ephemeral_pk": "0000000000000000000000000000000000000000000000000000000000000000",
    "excess": "d777cf064daf8929e66d2dfc6898fd0cf0774d8546bccb40699c8c47da215663",
    "fee": 5,
    "proof": "b58e8833cf94a470423b3787193f6f3bd4e9c769eec7fb0030e6ec9747b1a796c6e84f21d88714c2d2e790c6f08d4599ecc766666be95b65c46b1c22ca98ba8206a92fe720ed2e7548e794cc41d2b38d409e19625936902e8a3d64905c08927abade0ed923158abd74b52ae0c302c4a53b58e42ccedc49f6a37133edd43a3fa544a704bf7fff2bd5bcd931e4176e30349b5e687486c8cefdc0418ba5e6d389934b78d619301a0a2ba911e57c88c26002da471c8a4827b0a80330fcc28b550f987329c534189d41869dd12ca5d04e7d283bf2d37bb5fe180cfd8f8fc76fd81a9c929f6c9688e8acc7ec7fb8d0633b362e2e080643b384f1fcad09894bc523bbe4539d76aae858a6dc822187f7e2cae3c41fe26ce4441f2a29b2d874689247c6b08e5c25b512bced45467592a092811b3dafb83b49857ddfddeced32d62dfa807f85a9c9262445e985a1e5f6c5cb723de7e4d8ffe1d9e546b27a7d3e0a30604f0cbce500d0122e5312cf46c09621c60b75a0ca33ad1f193cfb2289784a0ec65d22eaf0721faf556536723e6bc0c4127b86562db4921cadb384bd6f2a9262f3125ed7c90f4c7339cdeaf07d4b8f515306428142d81c27a7440a7dfaf7c79cdd9f2a75a3dfad995ec403dbf7a1cf0011cf1acf97c5f3b550dc2582633bf22cb743bb05565eb67c1d9229a644362f46f3b6fcc5283e765f34273770c0123ebc0463b123df7afa547257d9bbe2fce7d44bac396f8872dfbcb6eea357359a2f618b2a3e0e1cdf27316b5130bd9e36e2eb9c28f6b878f2f9802e4ab4950b3e0d158f596120144a76c4db95ee951146ffb15b3e0104897082c8bf4831d7b7a35a77c1729376ce0c46183ccd2957c9c0869b75dd4d90395ea3da024e0d5f490920ad1b18c68d9ac6cc874e782b7406ceffa48b218abe00ca9aa0c517b0c2dc49f1dc2bdfb4592dfa"
  },
  "onion": {
    "commit": "0996a01db5f4d43b7c185491db087fa0c01dd8e3517a0751787f244ef6c0a0a7f0",
    "data": [],
    "pubkey": "0000000000000000000000000000000000000000000000000000000000000000"
  }
}
```

The final commitment is returned as part of the last onion packet: `0996a01db5f4d43b7c185491db087fa0c01dd8e3517a0751787f244ef6c0a0a7f0`

The final payload contains a valid rangeproof for it: `b58e8833cf94a470423b3787193f6f3bd4e9c769eec7fb0030e6ec9747b1a796c6e84f21d88714c2d2e790c6f08d4599ecc766666be95b65c46b1c22ca98ba8206a92fe720ed2e7548e794cc41d2b38d409e19625936902e8a3d64905c08927abade0ed923158abd74b52ae0c302c4a53b58e42ccedc49f6a37133edd43a3fa544a704bf7fff2bd5bcd931e4176e30349b5e687486c8cefdc0418ba5e6d389934b78d619301a0a2ba911e57c88c26002da471c8a4827b0a80330fcc28b550f987329c534189d41869dd12ca5d04e7d283bf2d37bb5fe180cfd8f8fc76fd81a9c929f6c9688e8acc7ec7fb8d0633b362e2e080643b384f1fcad09894bc523bbe4539d76aae858a6dc822187f7e2cae3c41fe26ce4441f2a29b2d874689247c6b08e5c25b512bced45467592a092811b3dafb83b49857ddfddeced32d62dfa807f85a9c9262445e985a1e5f6c5cb723de7e4d8ffe1d9e546b27a7d3e0a30604f0cbce500d0122e5312cf46c09621c60b75a0ca33ad1f193cfb2289784a0ec65d22eaf0721faf556536723e6bc0c4127b86562db4921cadb384bd6f2a9262f3125ed7c90f4c7339cdeaf07d4b8f515306428142d81c27a7440a7dfaf7c79cdd9f2a75a3dfad995ec403dbf7a1cf0011cf1acf97c5f3b550dc2582633bf22cb743bb05565eb67c1d9229a644362f46f3b6fcc5283e765f34273770c0123ebc0463b123df7afa547257d9bbe2fce7d44bac396f8872dfbcb6eea357359a2f618b2a3e0e1cdf27316b5130bd9e36e2eb9c28f6b878f2f9802e4ab4950b3e0d158f596120144a76c4db95ee951146ffb15b3e0104897082c8bf4831d7b7a35a77c1729376ce0c46183ccd2957c9c0869b75dd4d90395ea3da024e0d5f490920ad1b18c68d9ac6cc874e782b7406ceffa48b218abe00ca9aa0c517b0c2dc49f1dc2bdfb4592dfa`

## Security Considerations

The security of this scheme comes from the use of ephemeral keys and the double encryption of payloads. Each server only has the keys to decrypt its own layer, and cannot derive the keys for any other layers.

This means that a server can only see the data intended for it, and has no information about the rest of the route or the details of any previous hops. This provides strong privacy guarantees for the sender of the transaction.