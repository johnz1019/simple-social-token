// Import from `core` instead of from `std` since we are in no-std mode
use core::{i128, result::Result, u128};

// Import heap related library from `alloc`
// https://doc.rust-lang.org/alloc/index.html
use alloc::{collections::BTreeMap, vec::Vec};

// Import CKB syscalls and structures
// https://nervosnetwork.github.io/ckb-std/riscv64imac-unknown-none-elf/doc/ckb_std/index.html
use ckb_std::{ckb_constants::Source, ckb_types::{
        bytes::Bytes,
        packed::{BytesOpt, Uint128, Uint64},
        prelude::*,
    }, debug, high_level::{load_cell_data, load_script, load_witness_args}, syscalls::{SysError, load_cell}};

use sparse_merkle_tree::{traits::Value, CompiledMerkleProof, H256};
use sst_mol::{
    AccountValue, AccountValueBuilder, LegerTransactionWithFlag, SSTData, SmtUpdateAction,
};

use crate::{
    error::Error,
    hash::{new_blake2b, CKBBlake2bHasher},
    type_id::{check_type_id, TYPE_ID_SIZE},
};

#[derive(Debug, Default, Clone)]
pub struct AccountVal {
    amount: u128,
    nonce: u64,
    clock_id: u64,
}

impl From<&AccountVal> for AccountValue {
    fn from(val: &AccountVal) -> AccountValue {
        let builder = AccountValueBuilder::default();
        builder
            .amount(Uint128::from_slice(&val.amount.to_le_bytes()).unwrap())
            .nonce(Uint64::from_slice(&val.nonce.to_le_bytes()).unwrap())
            .clock_id(Uint64::from_slice(&val.clock_id.to_le_bytes()).unwrap())
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

        let mut clock_id_bytes = [0u8; 8];
        clock_id_bytes.copy_from_slice(val.clock_id().as_slice());
        let clock_id = u64::from_le_bytes(clock_id_bytes);

        return AccountVal {
            amount,
            nonce,
            clock_id,
        };
    }
}

#[derive(Debug, Default, Clone)]
pub struct AccountChange {
    amount: i128,
    nonce: u64,
    tx_count: u64,
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
        hasher.update(&self.clock_id.to_le_bytes());
        hasher.finalize(&mut buf);
        buf.into()
    }

    fn zero() -> Self {
        Default::default()
    }
}

//验证转账逻辑
fn verify_transfer(in_type: Vec<u8>, lock_type: BytesOpt) -> Result<(), Error> {
    //得到这次更新的信息
    let update_action = SmtUpdateAction::from_compatible_slice(&in_type).unwrap();

    //首先，获得cell的数据
    let in_cell_data = load_cell_data(0, Source::GroupInput)?;
    let out_cell_data = load_cell_data(0, Source::GroupOutput)?;

    //将其转换成我们想要的格式
    let in_data = SSTData::from_slice(&in_cell_data).unwrap();
    let out_data = SSTData::from_slice(&out_cell_data).unwrap();

    //转账不允许改基础信息
    if in_data.amount().as_slice() != out_data.amount().as_slice()
        || in_data.info().as_slice() != out_data.info().as_slice()
    {
        return Err(Error::ResultUnmatch);
    }

    let mut root_byte = [0u8; 32];

    //获得旧状态根
    root_byte.copy_from_slice(in_data.smt_root().as_slice());
    let old_root = H256::from(root_byte);

    // debug!("old root:{:?}", old_root);

    //获得新状态根
    root_byte.copy_from_slice(out_data.smt_root().as_slice());
    let new_root = H256::from(root_byte);

    // debug!("new root:{:?}", new_root);

    //获得merkle_proof
    let merkle_proof_compiled = {
        let proof = Vec::from(update_action.proof().raw_data());
        CompiledMerkleProof(proof)
    };

    //得到交易
    let tx_with_flag = if let Some(lock_type) = lock_type.to_opt() {
        let lock_type: Vec<u8> = lock_type.unpack();
        LegerTransactionWithFlag::from_compatible_slice(&lock_type).unwrap()
    } else {
        return Err(Error::ItemMissing);
    };

    let txs = tx_with_flag.txs();

    //转账模式下，不允许打包无交易的Layer2区块
    if txs.len() <= 0 {
        return Err(Error::LengthNotEnough);
    }

    //将所有交易导致的状态变更记录在BTreeMap里，包括amount的增减，nonce的增加
    let mut state_change: BTreeMap<H256, AccountChange> = BTreeMap::new();

    //得到committer的信息
    let mut buf = [0u8; 32];
    buf.copy_from_slice(update_action.committer().as_slice());
    let committer = H256::from(buf);

    //用于统计所有的手续费
    let mut fee_sum: i128 = 0;

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

        //发送方的余额减少数额
        let total_amount = u128::from_le_bytes(u128_buf) as i128;

        //防止溢出
        if total_amount < 0 {
            return Err(Error::OverFlow);
        }

        //然后得到本次转账的nonce
        u64_buf.copy_from_slice(raw.nonce().as_slice());
        let nonce = u64::from_le_bytes(u64_buf);

        //更改发送方的状态
        {
            //u64::MAX代表nonce不需要改变
            let val = state_change.entry(key).or_insert(AccountChange {
                amount: 0,
                nonce: u64::MAX,
                tx_count: 0,
            });
            //下一个交易的nonce必须比上一个高1
            if val.nonce != u64::MAX && nonce != val.nonce + 1 {
                return Err(Error::ResultUnmatch);
            }

            val.tx_count += 1;
            //转出了这么多钱
            val.amount = val.amount.checked_sub(total_amount).unwrap();
            //nonce更新成新的
            val.nonce = nonce;
        }

        //更改所有接收方的值
        let mut sum: i128 = 0;
        let targets = raw.targets();
        for target in targets.into_iter() {
            //然后得到接收方的账户地址
            buf.copy_from_slice(target.to().as_slice());
            let key = H256::from(buf);
            u128_buf.copy_from_slice(target.amount().as_slice());
            let amount = u128::from_le_bytes(u128_buf) as i128;
            if amount < 0 {
                return Err(Error::OverFlow);
            }
            sum = sum.checked_add(amount).unwrap();

            let val = state_change.entry(key).or_insert(AccountChange {
                amount: 0,
                nonce: u64::MAX,
                tx_count: 0,
            });
            val.amount = val.amount.checked_add(amount).unwrap();
        }

        //统计手续费
        {
            u128_buf.copy_from_slice(raw.fee().as_slice());
            let fee: i128 = u128::from_le_bytes(u128_buf) as i128;
            if fee < 0 {
                return Err(Error::OverFlow);
            }
            fee_sum = fee_sum.checked_add(fee).unwrap();
        }

        //发送给所有人的总额应该等于设定值，或者可以改成>=？等于可以让用户自己销毁一些币
        if sum != total_amount {
            return Err(Error::ResultUnmatch);
        }
    }

    //只有手续费大于零的时候，committer的状态才会改变，否则可能不需要这一项
    if fee_sum > 0 {
        //将committer的初始信息加入btree_map
        let val = state_change.entry(committer).or_insert(AccountChange {
            amount: 0,
            nonce: u64::MAX,
            tx_count: 0,
        });
        val.amount = val.amount.checked_add(fee_sum).unwrap();
    }
    //得到更新的key
    let item_vec = update_action.updates();

    //更新项的数量应该与通过交易计算出来的一样
    if item_vec.len() != state_change.len() {
        return Err(Error::ResultUnmatch);
    }

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
            //u64::MAX，代表nonce无变化
            if change.nonce == u64::MAX {
                if new_value.nonce != old_value.nonce {
                    return Err(Error::ResultUnmatch);
                }
            } else if new_value.nonce != change.nonce + 1
                && old_value.nonce + change.tx_count - 1 != change.nonce
            {
                return Err(Error::ResultUnmatch);
            }

            //防止变化的数值超过i128表达的上限
            let actual_change = if new_value.amount > old_value.amount {
                let change = (new_value.amount - old_value.amount) as i128;
                if change < 0 {
                    return Err(Error::OverFlow);
                }
                change
            } else {
                let change = (old_value.amount - new_value.amount) as i128;
                if change < 0 {
                    return Err(Error::OverFlow);
                }
                -change
            };

            //余额的变化应该和计算得到的相匹配
            if actual_change != change.amount {
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

//验证增发逻辑
fn verify_issue(out_type: Vec<u8>) -> Result<(), Error> {
    //获取本次更新信息
    let update_action = SmtUpdateAction::from_compatible_slice(&out_type).unwrap();

    let mut buf = [0u8; 32];

    //有输入，是Owner主动增发或者缩减
    if let Ok(in_cell_data) = load_cell_data(0, Source::GroupInput) {
        let out_cell_data = load_cell_data(0, Source::GroupOutput)?;

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

        //获得merkle_proof
        let merkle_proof_compiled = {
            let proof = Vec::from(update_action.proof().raw_data());
            //debug!("proof len:{:?}", proof.len());
            CompiledMerkleProof(proof)
        };

        //得到更新的key
        let item_vec = update_action.updates();

        let mut amount_change: i128 = 0;
        let mut old_keys = Vec::new();
        let mut new_keys = Vec::new();
        for item in item_vec.into_iter() {
            buf.copy_from_slice(item.key().as_slice());

            let key = H256::from(buf);

            let old_value: AccountVal = item.old_value().into();
            let new_value: AccountVal = item.new_value().into();

            let actual_change = if new_value.amount > old_value.amount {
                let change = (new_value.amount - old_value.amount) as i128;
                if change < 0 {
                    return Err(Error::OverFlow);
                }
                change
            } else {
                let change = (old_value.amount - new_value.amount) as i128;
                if change < 0 {
                    return Err(Error::OverFlow);
                }
                -change
            };

            amount_change = amount_change.checked_add(actual_change).unwrap();

            //要保证每个账户的Token数只增不减，同时其他的保持不变
            if new_value.nonce != old_value.nonce || new_value.clock_id != old_value.clock_id {
                return Err(Error::ResultUnmatch);
            }

            old_keys.push((key.clone(), old_value.to_h256()));
            new_keys.push((key.clone(), new_value.to_h256()));
        }

        //验证amount数额的变化
        let mut u128_buf = [0u8; 16];
        u128_buf.copy_from_slice(in_data.amount().as_slice());
        let old_amount = u128::from_le_bytes(u128_buf);
        u128_buf.copy_from_slice(out_data.amount().as_slice());
        let new_amount = u128::from_le_bytes(u128_buf);

        let actual_change = if new_amount > old_amount {
            let change = (new_amount - old_amount) as i128;
            if change < 0 {
                return Err(Error::OverFlow);
            }
            change
        } else {
            let change = (old_amount - new_amount) as i128;
            if change < 0 {
                return Err(Error::OverFlow);
            }
            -change
        };

        if actual_change != amount_change {
            return Err(Error::ResultUnmatch);
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

    //无输入，是创世
    } else {
        let out_cell_data = load_cell_data(0, Source::GroupOutput)?;

        //将其转换成我们想要的格式
        let out_data = SSTData::from_slice(&out_cell_data).unwrap();

        let mut root_byte = [0u8; 32];

        //获得新状态根
        root_byte.copy_from_slice(out_data.smt_root().as_slice());
        let new_root = H256::from(root_byte);

        // debug!("new root:{:?}", new_root);

        //获得merkle_proof
        let merkle_proof_compiled = {
            let proof = Vec::from(update_action.proof().raw_data());
            //debug!("proof len:{:?}", proof.len());
            CompiledMerkleProof(proof)
        };

        //得到更新的key
        let item_vec = update_action.updates();

        let mut amount_sum: u128 = 0;
        let mut new_keys = Vec::new();
        for item in item_vec.into_iter() {
            buf.copy_from_slice(item.key().as_slice());

            let key = H256::from(buf);

            let new_value: AccountVal = item.new_value().into();

            if new_value.nonce != 0 || new_value.clock_id != 0 {
                return Err(Error::ResultUnmatch);
            }
            amount_sum = amount_sum.checked_add(new_value.amount).unwrap();
            new_keys.push((key.clone(), new_value.to_h256()));
        }

        let mut u128_buf = [0u8; 16];
        u128_buf.copy_from_slice(out_data.amount().as_slice());
        let new_amount = u128::from_le_bytes(u128_buf);

        if new_amount != amount_sum {
            return Err(Error::ResultUnmatch);
        }

        //验证新状态的正确性
        let ok = merkle_proof_compiled
            .verify::<CKBBlake2bHasher>(&new_root, new_keys)
            .unwrap();
        if !ok {
            return Err(Error::ProofInvalid);
        }
    }

    Ok(())
}

pub fn main() -> Result<(), Error> {
    // check type_id
    {
        let script = load_script()?;
        let args: Bytes = Unpack::unpack(&script.args());

        debug!("script args is {:?}", args);
        if args.len() < TYPE_ID_SIZE {
            return Err(Error::InvalidTypeID);
        }
        let mut type_id = [0u8; TYPE_ID_SIZE];
        type_id.copy_from_slice(&args[..TYPE_ID_SIZE]);
        check_type_id(type_id)?;
    }

    //要么从同type_script的第一个取，要么从交易第一个取
    let witness_args = if let Ok(args) = load_witness_args(0, Source::GroupInput) {
        args
    } else {
        //只有无输入同type_script的时候，才可以从第一个Input里读取
        if load_cell_data(0, Source::GroupInput).is_ok() {
            return Err(Error::ResultUnmatch);
        };
        load_witness_args(0, Source::Input)?
    };
    let in_type = witness_args.input_type();
    let out_type = witness_args.output_type();
    let lock_type = witness_args.lock();

    //如果in_type不为空，则为正常转账逻辑
    if let Some(in_type) = in_type.to_opt() {
        let in_type: Vec<u8> = in_type.unpack();
        verify_transfer(in_type, lock_type)?
    //否则为增发逻辑
    } else if let Some(out_type) = out_type.to_opt() {
        let out_type: Vec<u8> = out_type.unpack();
        verify_issue(out_type)?

    //否则，可能是owner换锁脚本，或者往Cell充值CKB，或者Owner销毁这个币
    } else {
        //首先，获得cell的数据
        let in_cell_data = load_cell_data(0, Source::GroupInput)?;

        //有同类型的输出Cell，确保输入输出相等
        if let Ok(out_cell_data) = load_cell_data(0, Source::GroupOutput) {
            //将其转换成我们想要的格式
            let in_data = SSTData::from_slice(&in_cell_data).unwrap();
            let out_data = SSTData::from_slice(&out_cell_data).unwrap();

            //cell的data不能变，但允许修改info
            if in_data.amount().as_slice() != out_data.amount().as_slice()
                || in_data.smt_root().as_slice() != out_data.smt_root().as_slice()
            {
                return Err(Error::ResultUnmatch);
            }

        //没有同类型的输出Cell了，相当于销毁，不做任何判定，逻辑在锁脚本那边
        } else {
        }
    };

    Ok(())
}
