# SwapStore

## Overview

The `SwapStore` is an LMDB database for swap entries and generated swap transactions.

New entries remain `Unprocessed` until a round uses them. A successful round marks them `InProcess`; entries rejected by a downstream mixer become `Failed`. Reorg checks can rebroadcast or rebuild the transaction. Automatic transition to `Completed` and deletion are not currently implemented.

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
  - `InProcess { kernel_commit: Commitment }`: The swap was included in a generated transaction identified by its kernel commitment.
  - `Completed { kernel_commit: Commitment, block_hash: Hash }`: Reserved for a swap confirmed in the given block; the current server does not set this status.
  - `Failed`: The swap has failed, potentially due to expiration or because the output is no longer in the UTXO set.
