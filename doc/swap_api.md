# Swap Server API

## Overview

The Swap Server provides a single JSON-RPC API with the method `swap`. This API is used by clients to initiate the mixing process for their outputs, obscuring their coin history in a transaction with other users.

## SWAP

### Request
The `swap` method accepts a single JSON object containing the following fields:

- `onion`: an `Onion` data structure, which is the encrypted onion packet containing the key information necessary to transform the user's output.
- `comsig`: a Commitment Signature that proves the client knows the secret key and value of the output's commitment.

#### `Onion` data structure

The `Onion` data structure consists of the following fields:

- `pubkey`: an ephemeral pubkey to as the onion originator's portion of the shared secret, represented as an `x25519_dalek::PublicKey`.
- `commit`: the Pedersen commitment before adjusting the excess and subtracting the fee, represented as a 33-byte `secp256k1` Pedersen commitment.
- `data`: a vector of encrypted payloads, each representing a layer of the onion. When completely decrypted, these are serialized `Payload` objects.

Each entry in the `enc_payloads` vector corresponds to a server in the system, in order, with the first entry containing the payload for the swap server, and the last entry containing the payload for the final mix server.

#### `Payload` data structure

A `Payload` represents a single, decrypted/peeled layer of an Onion. It consists of the following fields:

- `next_ephemeral_pk`: an `xPublicKey` representing the public key for the next layer.
- `excess`: a `SecretKey` representing the excess value.
- `fee`: a `FeeFields` value representing the transaction fee.
- `rangeproof`: an optional `RangeProof` value.

### Response

A successful call to the 'swap' API will result in an empty JSON-RPC response with no error.

In case of errors, the API will return a `SwapError` type with one of the following variants:

- `InvalidPayloadLength`: The provided number of payloads is invalid.
- `InvalidComSignature`: The Commitment Signature is invalid.
- `InvalidRangeproof`: The provided rangeproof is invalid.
- `MissingRangeproof`: A rangeproof is required but was not supplied.
- `CoinNotFound`: The output does not exist, or it is already spent.
- `AlreadySwapped`: The output is already in the swap list.
- `PeelOnionFailure`: Failed to peel onion layer due to an `OnionError`.
- `FeeTooLow`: The provided fee is too low.
- `StoreError`: An error occurred when saving swap to the data store.
- `ClientError`: An error occurred during client communication.
- `UnknownError`: An unknown error occurred.

### Example

Here is an example of how to call the 'swap' API:
```json
{
  "jsonrpc": "2.0",
  "method": "swap",
  "params": {
    "comsig": "09ca34db2ac772a9a0e954b4ae2180ba936d8f96219824fe7ec1f5439bef3a0afe7e18867db3d391f37260285feea38ff740b0b49196a4b0a7910c1a72ceca1c5a3e4a53d6e06ffb0536f0dad78812a72ef14e6ff83df8d0dd2aa71615fb00fbe2",
    "onion": {
      "commit": "0962da257e8c663d1a35128cf87363657ae6ec4a3c78fda4742a77e9c4f17e1a20",
      "data": [
        "fd06dd3e506b1c1e76fd6546beec1e88bb13e7e13be7c02a7e525cd22c43d5dc7a906c77e5c07b08d7a5eeb7e7983b87376b02a33f7582ffc1bf2adac498fefbc2dba840d76d4c8e945f",
        "ecead273b9b707d101aae71c2c7cb8ce3e7c95347aa730015af206baaf37302df48e5e635ecc94ddf3eee12b314e276f23e29e7dde9f30f712b14ea227801719ecdd1a53999f854a7f4878b905c94905d5f1bfbb4ad9bcf01afeb55070ebcc665d29b0a85093b4d134a52adc76293ad9e963a9f7156dcfc95c1c600a31b919495bf6d3b7ec75eeffcc70aef15b98c43c41468f34b1a96c49b9e20328849a3b12c84d97893145a65d820c37dae51eba62121d681543d060d600167ede3a8c6e807a5765c5ebb2d568366c89bba2b08590a4615822ca64fb848e54267b18fc35fb0f9f6834f1524d7e0da89163e5385de65613e09fed6fec8d9cc60354baa86131b80aa1c8cd5be916a3d757cd8e8253c17158555539a2f8e4d9d1a4b996b218b1af3e7b28bdf9e0f3db2ea9f4d5e11d798d9b7698d037e69df3ca89c2165760963a4d80207917a70a4986d7df83b463547f4d704d28b1eec2e5a93aa70b5b7c73559120e23cd4cfbf76e4d2b21ef215d4c0210001c17318eba633a3c177c18ef88b6c1718e11c552cc77b297dab5c1020557915853434b8ca5698685b3a66bba73164e83d2440473ebb0591df593e0264b605dc3b35055a7de0d40c5c7cc7542dcbe5ade436098dd41e1ac395d2d0baf5c82fdd5932b2e182f8f11a67bccc90e6e63ec8928bd7f0306c6949122fadf12493a7de17f7bfad72501f4f792fca388b3614d6eb3165d948d7c9efe168b5273b132fa27ea6e8df63d70d8b099a9220903b02898b5cc925010ebfab78ccceb19a9f2f6d6e0392c4837977bf0e3e014913e154913c0204913514684f64d7166b3a7203cbab9dddd96ed7db35b4a17fec50abd752348cdf53181ddd6954bc1fb907ed86206dcf05c04efb432cb6ba6db25082b4ce0bf520e3c508163b44c82efaa44b2ec904ddd938a0b99044666941bc72be58e22122027c2fcbc4299e52bc29916eb51206c41e618bce1a5c0d859d116807217282d0883fdabe6f9250cda63082f71fbf921b65ab17cd9bfb0561c4cabe1369c7d6a85c51c0e4f43f51622e70ab4eb0e3fab5"
      ],
      "pubkey": "500b161d3bbd9249161d9760ba038d9805be86c0e5273782303a67cda50edb5a"
    }
  },
  "id": "1"
}
```