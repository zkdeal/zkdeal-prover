//! Real non-empty v4 batch: seven signed EVM transactions regrouped into
//! two contiguous blocks (3 + 4). This is execution evidence, not a proof
//! performance claim; the CUDA proof is exercised by GPU CI.

mod batches;
mod fixture;
mod preset;

mod execution;
mod refusals;
