// Import from `core` instead of from `std` since we are in no-std mode
use core::result::Result;

// Import heap related library from `alloc`
// https://doc.rust-lang.org/alloc/index.html
use alloc::vec::Vec;

// Import CKB syscalls and structures
// https://nervosnetwork.github.io/ckb-std/riscv64imac-unknown-none-elf/doc/ckb_std/index.html
use ckb_std::{
    ckb_constants::Source,
    ckb_types::{
        bytes::Bytes,
        packed::{Uint128, Uint64},
        prelude::*,
    },
    debug,
    high_level::{load_cell_data, load_script, load_witness_args},
};

use sparse_merkle_tree::{traits::Value, CompiledMerkleProof, H256};
use sst_mol::{AccountValue, AccountValueBuilder, SSTData, SmtUpdateAction};

use crate::{
    error::Error,
    hash::{new_blake2b, CKBBlake2bHasher},
};

#[derive(Debug, Default, Clone)]
pub struct AccountVal {
    amount: u128,
    nonce: u64,
    timestamp: u64,
}

impl From<&AccountVal> for AccountValue {
    fn from(val: &AccountVal) -> AccountValue {
        let builder = AccountValueBuilder::default();
        builder
            .amount(Uint128::from_slice(&val.amount.to_le_bytes()).unwrap())
            .nonce(Uint64::from_slice(&val.nonce.to_le_bytes()).unwrap())
            .timestamp(Uint64::from_slice(&val.timestamp.to_le_bytes()).unwrap())
            .build()
    }
}

impl From<AccountValue> for AccountVal {
    fn from(val: AccountValue) -> AccountVal {
        let mut amount_bytes = [0u8; 16];
        for i in 0..amount_bytes.len() {
            amount_bytes[i] = val.amount().as_slice()[i];
        }
        let amount = u128::from_le_bytes(amount_bytes);

        let mut nonce_bytes = [0u8; 8];
        for i in 0..nonce_bytes.len() {
            nonce_bytes[i] = val.nonce().as_slice()[i];
        }
        let nonce = u64::from_le_bytes(nonce_bytes);
        let mut timestamp_bytes = [0u8; 8];
        for i in 0..nonce_bytes.len() {
            timestamp_bytes[i] = val.timestamp().as_slice()[i];
        }
        let timestamp = u64::from_le_bytes(timestamp_bytes);

        return AccountVal {
            amount,
            nonce,
            timestamp,
        };
    }
}

impl AccountVal {
    fn is_zero(&self) -> bool {
        return self.amount == 0;
    }
}

impl Value for AccountVal {
    fn to_h256(&self) -> H256 {
        if self.is_zero() {
            return H256::zero();
        }
        let mut buf = [0u8; 32];
        let mut hasher = new_blake2b();
        hasher.update(&self.amount.to_le_bytes());
        hasher.update(&self.nonce.to_le_bytes());
        hasher.update(&self.timestamp.to_le_bytes());
        hasher.finalize(&mut buf);
        buf.into()
    }

    fn zero() -> Self {
        Default::default()
    }
}

pub fn main() -> Result<(), Error> {
    // remove below examples and write your code here
    let script = load_script()?;
    let args: Bytes = script.args().unpack();

    debug!("script args is {:?}", args);

    // return an error if args is invalid
    if args.is_empty() {
        return Err(Error::MyError);
    }

    let in_cell_data = load_cell_data(0, Source::GroupInput).unwrap();
    let out_cell_data = load_cell_data(0, Source::GroupOutput).unwrap();

    let in_data = SSTData::from_slice(&in_cell_data).unwrap();
    let out_data = SSTData::from_slice(&out_cell_data).unwrap();

    let mut root_byte = [0u8; 32];
    for i in 0..root_byte.len() {
        root_byte[i] = in_data.smt_root().as_slice()[i];
    }
    let old_root = H256::from(root_byte);

    // debug!("old root:{:?}", old_root);
    for i in 0..root_byte.len() {
        root_byte[i] = out_data.smt_root().as_slice()[i];
    }
    let new_root = H256::from(root_byte);

    // debug!("new root:{:?}", new_root);
    let in_type = load_witness_args(0, Source::GroupInput)
        .unwrap()
        .input_type();

    let update_action = if let Some(in_type) = in_type.to_opt() {
        let b: Vec<u8> = in_type.unpack();
        SmtUpdateAction::from_compatible_slice(&b).unwrap()
    } else {
        return Err(Error::ItemMissing);
    };

    let merkle_proof_compiled = {
        let proof = Vec::from(update_action.proof().raw_data());
        //debug!("proof len:{:?}", proof.len());
        CompiledMerkleProof(proof)
    };
    // debug!(
    //     "proof 100 101 {:?},{:?}",
    //     merkle_proof_compiled.0[100], merkle_proof_compiled.0[101]
    // );

    let item_vec = update_action.updates();

    let mut old_keys = Vec::new();
    let mut new_keys = Vec::new();
    let mut buf = [0u8; 32];
    for item in item_vec.into_iter() {
        for i in 0..buf.len() {
            buf[i] = item.key().as_slice()[i];
        }
        let key = H256::from(buf);
        
        let old_value: AccountVal = item.old_value().into();
        old_keys.push((key.clone(), old_value.to_h256()));

        let new_value: AccountVal = item.new_value().into();
        new_keys.push((key.clone(), new_value.to_h256()));
    }

    // debug!(
    //     "mod_keys 0:{:?}, {:?}, {:?}\n",
    //     old_keys[0].0, old_keys[0].1, new_keys[0].1
    // );

    let ok = merkle_proof_compiled
        .verify::<CKBBlake2bHasher>(&old_root, old_keys)
        .unwrap();
    if !ok {
        return Err(Error::MyError);
    }

    let ok = merkle_proof_compiled
        .verify::<CKBBlake2bHasher>(&new_root, new_keys)
        .unwrap();
    if !ok {
        return Err(Error::MyError);
    }

    Ok(())
}
