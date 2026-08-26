//! The two room-state commitments: the canonical secure-trie MPT root shared
//! with the ethereumjs engine, and the flat sparse v5 candidate.

use alloy_primitives::{keccak256, B256};
use alloy_trie::TrieAccount;

use super::StateMap;

impl StateMap {
    /// Secure-trie MPT state root: keccak(address) keys, account RLP
    /// [nonce, balance, storageRoot, codeHash]. Fully empty accounts are
    /// excluded. A storage-bearing record is committed defensively; the v4
    /// witness boundary rejects this non-canonical EIP-161 shape before it can
    /// reach execution.
    pub fn state_root(&self) -> B256 {
        alloy_trie::root::state_root_unhashed(
            self.accounts
                .iter()
                .filter(|(_, a)| !a.is_empty())
                .map(|(address, a)| {
                    (
                        *address,
                        TrieAccount {
                            nonce: a.nonce,
                            balance: a.balance,
                            storage_root: a.storage_root(),
                            // The address binding is installed only after the
                            // artifact hash was checked against these bytes,
                            // and DatabaseCommit removes it on code changes.
                            code_hash: self
                                .validated_prepared_code(address, a)
                                .map(|(hash, _)| hash)
                                .unwrap_or_else(|| a.code_hash()),
                        },
                    )
                }),
        )
    }

    /// Flat sparse room commitment candidate for v5. The EVM-visible account
    /// and storage values are identical to the MPT path; only the
    /// proof-internal commitment layout changes.
    pub fn sparse_state_root_v5(&self) -> B256 {
        fn tree_root(tag: &[u8], mut leaves: Vec<B256>) -> B256 {
            let count = leaves.len() as u64;
            if leaves.is_empty() {
                leaves.push(B256::ZERO);
            } else {
                leaves.resize(leaves.len().next_power_of_two(), B256::ZERO);
            }
            while leaves.len() > 1 {
                leaves = leaves
                    .chunks_exact(2)
                    .map(|pair| {
                        let mut encoded = Vec::with_capacity(32 * 3);
                        encoded.extend_from_slice(keccak256(tag).as_slice());
                        encoded.extend_from_slice(pair[0].as_slice());
                        encoded.extend_from_slice(pair[1].as_slice());
                        keccak256(encoded)
                    })
                    .collect();
            }
            let mut committed = Vec::with_capacity(tag.len() + 8 + 32);
            committed.extend_from_slice(tag);
            committed.extend_from_slice(&count.to_be_bytes());
            committed.extend_from_slice(leaves[0].as_slice());
            keccak256(committed)
        }

        let leaves = self
            .accounts
            .iter()
            .filter(|(_, account)| !account.is_empty())
            .map(|(address, account)| {
                let storage = account
                    .storage
                    .iter()
                    .filter(|(_, value)| !value.is_zero())
                    .map(|(slot, value)| {
                        let mut encoded = Vec::with_capacity(32 * 3);
                        encoded.extend_from_slice(
                            keccak256(b"zkdeal/sparse-storage-leaf/v5").as_slice(),
                        );
                        encoded.extend_from_slice(&slot.to_be_bytes::<32>());
                        encoded.extend_from_slice(&value.to_be_bytes::<32>());
                        keccak256(encoded)
                    })
                    .collect::<Vec<_>>();
                let storage_root = tree_root(b"zkdeal/sparse-storage-tree/v5", storage);
                let mut encoded = Vec::with_capacity(32 * 6);
                encoded.extend_from_slice(keccak256(b"zkdeal/sparse-account-leaf/v5").as_slice());
                let mut address_word = [0u8; 32];
                address_word[12..].copy_from_slice(address.as_slice());
                encoded.extend_from_slice(&address_word);
                let mut nonce_word = [0u8; 32];
                nonce_word[24..].copy_from_slice(&account.nonce.to_be_bytes());
                encoded.extend_from_slice(&nonce_word);
                encoded.extend_from_slice(&account.balance.to_be_bytes::<32>());
                encoded.extend_from_slice(account.code_hash().as_slice());
                encoded.extend_from_slice(storage_root.as_slice());
                keccak256(encoded)
            })
            .collect::<Vec<_>>();
        tree_root(b"zkdeal/sparse-account-tree/v5", leaves)
    }
}
