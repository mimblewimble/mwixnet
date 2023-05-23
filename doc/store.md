# SwapStore

## Overview

The `SwapStore` is an lmdb database, responsible for storing unprocessed and in-process `SwapData` entries.

The `SwapStore` is used to hold onto new `SwapData` entries until the next swap round, when the mixing process actually occurs. At that time, they will be marked as `InProcess` until the swap is in a confirmed transaction, at which time they will be marked `Completed` and eventually erased.

## Data Model

`SwapData`  entries are keyed with prefix 'S' followed by the commitment of the output being swapped. Entries are all unique by key.

### `SwapData`

The `SwapData` structure contains information needed to swap a single output. It has the following fields:

- `excess`: The total excess for the output commitment.
- `output_commit`: The derived output commitment after applying excess and fee.
- `rangeproof`: The rangeproof, included only for the final hop (node N).
- `input`: The transaction input being spent.
- `fee`: The transaction fee.
- `onion`: The remaining onion after peeling off our layer.
- `status`: The status of the swap, represented by the `SwapStatus` enum, which can be one of the following:
  - `Unprocessed`: The swap has been received but not yet processed.
  - `InProcess { kernel_hash: Hash }`: The swap is currently being processed, and is expected to be a transaction with the kernel matching the given `kernel_hash`.
  - `Completed { kernel_hash: Hash, block_hash: Hash }`: The swap has been successfully processed and included in the block matching the given `block_hash`.
  - `Failed`: The swap has failed, potentially due to expiration or because the output is no longer in the UTXO set.