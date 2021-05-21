// Import from `core` instead of from `std` since we are in no-std mode
use core::{result::Result, u128};

// Import heap related library from `alloc`
// https://doc.rust-lang.org/alloc/index.html
use alloc::{collections::BTreeMap, vec::Vec};

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
        amount_bytes.copy_from_slice(val.amount().as_slice());
        let amount = u128::from_le_bytes(amount_bytes);

        let mut nonce_bytes = [0u8; 8];
        nonce_bytes.copy_from_slice(val.nonce().as_slice());
        let nonce = u64::from_le_bytes(nonce_bytes);

        let mut timestamp_bytes = [0u8; 8];
        timestamp_bytes.copy_from_slice(val.timestamp().as_slice());
        let timestamp = u64::from_le_bytes(timestamp_bytes);

        return AccountVal {
            amount,
            nonce,
            timestamp,
        };
    }
}

#[derive(Debug, Default, Clone)]
pub struct AccountChange {
    amount: i128,
    nonce: u64,
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
        return Err(Error::ItemMissing);
    }

    //首先，获得cell的数据
    let in_cell_data = load_cell_data(0, Source::GroupInput).unwrap();
    let out_cell_data = load_cell_data(0, Source::GroupOutput).unwrap();

    //将其转换成我们想要的格式
    let in_data = SSTData::from_slice(&in_cell_data).unwrap();
    let out_data = SSTData::from_slice(&out_cell_data).unwrap();

    let mut root_byte = [0u8; 32];

    //获得旧状态根
    root_byte.copy_from_slice(in_data.smt_root().as_slice());
    let old_root = H256::from(root_byte);

    // debug!("old root:{:?}", old_root);

    //获得新状态根
    root_byte.copy_from_slice(out_data.smt_root().as_slice());
    let new_root = H256::from(root_byte);

    // debug!("new root:{:?}", new_root);

    let in_type = load_witness_args(0, Source::GroupInput)
        .unwrap()
        .input_type();

    //获得本次的更新操作，里面有交易，更新的key，以及merkle_proof
    let update_action = if let Some(in_type) = in_type.to_opt() {
        let b: Vec<u8> = in_type.unpack();
        SmtUpdateAction::from_compatible_slice(&b).unwrap()
    } else {
        return Err(Error::ItemMissing);
    };

    //获得merkle_proof
    let merkle_proof_compiled = {
        let proof = Vec::from(update_action.proof().raw_data());
        //debug!("proof len:{:?}", proof.len());
        CompiledMerkleProof(proof)
    };
    // debug!(
    //     "proof 100 101 {:?},{:?}",
    //     merkle_proof_compiled.0[100], merkle_proof_compiled.0[101]
    // );

    //得到交易引起的状态变换
    let txs = update_action.txs();
    let mut state_change: BTreeMap<H256, AccountChange> = BTreeMap::new();

    let mut buf = [0u8; 32];
    let mut u128_buf = [0u8; 16];
    let mut u64_buf = [0u8; 8];
    for tx in txs.into_iter() {
        //首先得到原始交易
        let raw = tx.raw();

        //然后得到发送方的账户地址
        buf.copy_from_slice(raw.from().as_slice());
        let key = H256::from(buf);

        //然后得到这次转账的转账总额
        u128_buf.copy_from_slice(raw.total_amount().as_slice());

        //发送方的余额是减少
        let total_amount = u128::from_le_bytes(u128_buf) as i128;

        //然后得到本次转账的nonce
        u64_buf.copy_from_slice(raw.nonce().as_slice());
        let nonce = u64::from_le_bytes(u64_buf);

        //更改发送方的状态
        {
            //u64::MAX代表map里没出现过这个项
            let val = state_change.entry(key).or_insert(AccountChange {
                amount: 0,
                nonce: u64::MAX,
            });
            //下一个交易的nonce必须比上一个高1
            if val.nonce != u64::MAX && nonce != val.nonce + 1 {
                return Err(Error::ResultUnmatch);
            }
            val.amount -= total_amount;
            val.nonce = nonce;

        }

        let mut sum = 0;
        let targets = raw.to();
        for to in targets.into_iter() {
            //然后得到接收方的账户地址
            buf.copy_from_slice(to.to().as_slice());
            let key = H256::from(buf);
            u128_buf.copy_from_slice(to.amount().as_slice());
            let amount = u128::from_le_bytes(u128_buf) as i128;
            sum += amount;
            let val = state_change.entry(key).or_insert(AccountChange {
                amount: 0,
                nonce: u64::MAX,
            });
            val.amount += amount;
        }

        //发送给所有人的总额应该等于设定值，或者可以改成>=？可以让用户自己销毁一些币
        if sum != total_amount {
            return Err(Error::ResultUnmatch);
        }
    }

    //得到更新的key
    let item_vec = update_action.updates();

    let mut old_keys = Vec::new();
    let mut new_keys = Vec::new();
    for item in item_vec.into_iter() {
        buf.copy_from_slice(item.key().as_slice());

        let key = H256::from(buf);

        let old_value: AccountVal = item.old_value().into();
        old_keys.push((key.clone(), old_value.to_h256()));

        let new_value: AccountVal = item.new_value().into();
        new_keys.push((key.clone(), new_value.to_h256()));

        if let Some(change) = state_change.get(&key) {
            //要么这个地址在本次交易中nonce无变化，要么新nonce等于最终用到的nonce+1
            if change.nonce == u64::MAX {
                if new_value.nonce != old_value.nonce {
                    return Err(Error::ResultUnmatch);
                }
            } else if new_value.nonce != change.nonce + 1 {
                return Err(Error::ResultUnmatch);
            }

            //余额的变化匹配
            if new_value.amount as i128 - old_value.amount as i128 != change.amount {
                return Err(Error::ResultUnmatch);
            }
        } else {
            return Err(Error::ResultUnmatch);
        }
    }

    //验证旧状态的正确性
    let ok = merkle_proof_compiled
        .verify::<CKBBlake2bHasher>(&old_root, old_keys)
        .unwrap();
    if !ok {
        return Err(Error::ProofInvalid);
    }

    //验证新状态的正确性
    let ok = merkle_proof_compiled
        .verify::<CKBBlake2bHasher>(&new_root, new_keys)
        .unwrap();
    if !ok {
        return Err(Error::ProofInvalid);
    }

    Ok(())
}
