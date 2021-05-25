use std::u128;

use crate::{
    tests::misc::{AccountVal, CKBBlake2bHasher, SMT},
    Loader,
};

use sst_mol::{
    LegerTransactionBuilder, LegerTransactionVecBuilder, LegerTransactionWithFlagBuilder,
    RawLedgerTransactionBuilder, SSTDataBuilder, SmtProofBuilder, SmtUpdateActionBuilder,
    SmtUpdateItemBuilder, SmtUpdateItemVecBuilder, TargetBuilder, TargetsBuilder,
};

use rand::{thread_rng, Rng};
use sparse_merkle_tree::{traits::Value, H256};

use super::*;
use ckb_testtool::ckb_types::{bytes::Bytes, core::TransactionBuilder, packed::*, prelude::*};
use ckb_testtool::{builtin::ALWAYS_SUCCESS, context::Context};

#[test]
fn test_transaction() {
    //设定状态树的参数
    let account_count = 10000;
    let update_count = 50;

    // deploy contract
    let mut context = Context::default();
    let sst_bin: Bytes = Loader::default().load_binary("simple-social-token");
    let sst_out_point = context.deploy_cell(sst_bin);
    let always_success_bin = ALWAYS_SUCCESS.clone();
    let always_success_out_point = context.deploy_cell(always_success_bin);

    // prepare scripts
    let lock_script = context
        .build_script(&always_success_out_point, Bytes::from(vec![42]))
        .expect("script");
    let lock_script_dep = CellDep::new_builder()
        .out_point(always_success_out_point)
        .build();

    let sst_script = context.build_script(&sst_out_point, random_32bytes());
    let sst_script_dep = CellDep::new_builder().out_point(sst_out_point).build();

    let mut smt = SMT::default();
    let mut rng = thread_rng();

    //往状态树里添加随机值
    for _ in 0..account_count {
        let key: H256 = rng.gen::<[u8; 32]>().into();
        let value = AccountVal::random(&mut rng);
        smt.update(key, value).unwrap();
    }

    //设定本次交易的提交者
    let committer: H256 = rng.gen::<[u8; 32]>().into();
    let committer_value = AccountVal {
        amount: 10000,
        nonce: 0,
        clock_id: 0,
    };
    smt.update(committer, committer_value).unwrap();

    //往状态树里添加待测试的值
    let mut keys = Vec::with_capacity(update_count);
    for _ in 0..update_count {
        let key: H256 = rng.gen::<[u8; 32]>().into();
        //每个账户初始10000个币的余额
        let value = AccountVal {
            amount: 10000,
            nonce: 0,
            clock_id: 0,
        };
        keys.push((key, value.clone()));
        smt.update(key, value).unwrap();
    }

    //获得旧的状态树根
    let old_root: H256 = smt.root().clone();
    print!("old root: {:?}\n", old_root);

    //生成旧的Cell data
    let sst_data_old = SSTDataBuilder::default()
        .amount(Uint128::from_slice(&(10000000 as u128).to_le_bytes()).unwrap())
        .info(Byte32::from_slice(&[1u8; 32]).unwrap())
        .smt_root(Byte32::from_slice(old_root.as_slice()).unwrap())
        .build();

    // prepare cells
    let input_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(1000u64.pack())
            .lock(lock_script.clone())
            .type_(sst_script.clone().pack())
            .build(),
        sst_data_old.as_bytes(),
    );
    let input = CellInput::new_builder()
        .previous_output(input_out_point)
        .build();

    let mut txs_builder = LegerTransactionVecBuilder::default();
    let mut mod_keys = Vec::with_capacity(update_count);
    let mut fee: u128 = 0;
    //开始构建交易转账
    for two_key in keys.chunks(2).into_iter() {
        //第一个key转给第二个key，1000个币
        if two_key.len() >= 2 {
            let key_0 = two_key[0].0;
            let key_1 = two_key[1].0;

            let old_value_0 = two_key[0].1;
            let old_value_1 = two_key[1].1;

            let mut new_value_0 = two_key[0].1;
            new_value_0.amount -= 1000;

            //发送方需要修改nonce
            new_value_0.nonce += 1;
            let mut new_value_1 = two_key[1].1;
            new_value_1.amount += 1000;

            mod_keys.push((key_0, old_value_0, new_value_0));
            mod_keys.push((key_1, old_value_1, new_value_1));

            smt.update(key_0, new_value_0).unwrap();
            smt.update(key_1, new_value_1).unwrap();

            //接收方
            let targets = TargetsBuilder::default()
                .push(
                    TargetBuilder::default()
                        .to(Byte32::from_slice(two_key[1].0.as_slice()).unwrap())
                        .amount(Uint128::from_slice(&(1000 as u128).to_le_bytes()).unwrap())
                        .build(),
                )
                .build();

            //发送方
            let raw = RawLedgerTransactionBuilder::default()
                .from(Byte32::from_slice(two_key[0].0.as_slice()).unwrap())
                .targets(targets)
                .nonce(Uint64::from_slice(&(0 as u64).to_le_bytes()).unwrap())
                .total_amount(Uint128::from_slice(&(1000 as u128).to_le_bytes()).unwrap())
                .fee(Uint128::from_slice(&(1 as u128).to_le_bytes()).unwrap())
                .build();

            //收取了一个token作为手续费
            fee += 1;
            let tx = LegerTransactionBuilder::default().raw(raw).build();
            txs_builder = txs_builder.push(tx);
        }
    }

    //把手续费部分加进去
    let mut committer_value_new = AccountVal::clone(&committer_value);
    committer_value_new.amount += fee;

    print!("fee:{},new_value:{:?}\n", fee, committer_value_new);
    mod_keys.push((committer, committer_value, committer_value_new));

    smt.update(committer, committer_value_new).unwrap();

    let txs = txs_builder.build();

    //生成更新后的状态根
    let new_root = smt.root().clone();
    print!("new root:{:?}\n", new_root);
    //生成Merkle proof
    let merkle_proof = smt
        .merkle_proof(mod_keys.clone().into_iter().map(|(k, _, _)| k).collect())
        .unwrap();

    let old_keys: Vec<(H256, H256)> = mod_keys
        .clone()
        .into_iter()
        .map(|(k, old, _)| (k, old.to_h256()))
        .collect();
    let merkle_proof_compiled = merkle_proof.clone().compile(old_keys.clone()).unwrap();

    //验证旧状态
    let res = merkle_proof_compiled
        .verify::<CKBBlake2bHasher>(&old_root, old_keys)
        .unwrap();
    assert!(res);

    // 验证新状态
    let new_keys: Vec<(H256, H256)> = mod_keys
        .clone()
        .into_iter()
        .map(|(k, _, new)| (k, new.to_h256()))
        .collect();
    let res = merkle_proof_compiled
        .verify::<CKBBlake2bHasher>(&new_root, new_keys)
        .unwrap();
    assert!(res);

    //将证明转成字节
    let merkle_proof_bytes: Vec<u8> = merkle_proof_compiled.into();

    print!("proof len:{}\n", merkle_proof_bytes.len());

    //得到更新序列
    let mut item_vec_builder = SmtUpdateItemVecBuilder::default();
    for (key, old_value, new_value) in mod_keys.into_iter() {
        let item = SmtUpdateItemBuilder::default()
            .key(ckb_types::packed::Byte32::from_slice(key.as_slice()).unwrap())
            .old_value((&old_value).into())
            .new_value((&new_value).into())
            .build();
        item_vec_builder = item_vec_builder.push(item);
    }

    let sst_data_new = SSTDataBuilder::default()
        .amount(Uint128::from_slice(&(10000000 as u128).to_le_bytes()).unwrap())
        .info(Byte32::from_slice(&[1u8; 32]).unwrap())
        .smt_root(Byte32::from_slice(new_root.as_slice()).unwrap())
        .build();

    let output = CellOutput::new_builder()
        .capacity(1000u64.pack())
        .lock(lock_script.clone())
        .type_(sst_script.clone().pack())
        .build();

    let item_vec = item_vec_builder.build();

    //生成Witness
    let updata_action = SmtUpdateActionBuilder::default()
        .proof(
            SmtProofBuilder::default()
                .extend(merkle_proof_bytes.iter().map(|v| Byte::from(*v)))
                .build(),
        )
        .updates(item_vec)
        .committer(Byte32::from_slice(committer.as_slice()).unwrap())
        .build();

    let tx_with_flag = LegerTransactionWithFlagBuilder::default().txs(txs).build();
    let witness_args = WitnessArgsBuilder::default()
        .input_type(Some(updata_action.as_bytes()).pack())
        .lock(Some(tx_with_flag.as_bytes()).pack())
        .build();

    let witness = witness_args.as_bytes().pack();

    print!("witness len:{}\n", witness.len());
    // build transaction
    let tx = TransactionBuilder::default()
        .input(input)
        .output(output)
        .output_data(sst_data_new.as_bytes().pack())
        .cell_dep(lock_script_dep)
        .cell_dep(sst_script_dep)
        .witness(witness)
        .build();
    let tx = context.complete_tx(tx);

    // run
    let cycles = context
        .verify_tx(&tx, MAX_CYCLES)
        .expect("pass verification");
    println!("consume cycles: {}", cycles);
}

#[test]
fn test_create_ledger() {
    // deploy contract
    let mut context = Context::default();
    let sst_bin: Bytes = Loader::default().load_binary("simple-social-token");
    let sst_out_point = context.deploy_cell(sst_bin);
    let always_success_bin = ALWAYS_SUCCESS.clone();
    let always_success_out_point = context.deploy_cell(always_success_bin);

    let a = u128::MAX as i128;
    print!("a:{}\n", a);

    // prepare scripts
    let lock_script = context
        .build_script(&always_success_out_point, Bytes::from(vec![42]))
        .expect("script");
    let lock_script_dep = CellDep::new_builder()
        .out_point(always_success_out_point)
        .build();

    // prepare cells
    //随便准备一个input
    let input_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(1000u64.pack())
            .lock(lock_script.clone())
            .build(),
        Bytes::new(),
    );

    //计算出type_id
    let type_id = calculate_type_id(input_out_point.clone());

    let input = CellInput::new_builder()
        .previous_output(input_out_point)
        .build();

    //将type_id放入args
    let sst_script = context.build_script(&sst_out_point, Bytes::copy_from_slice(&type_id));
    let sst_script_dep = CellDep::new_builder().out_point(sst_out_point).build();

    //生成一颗SMT
    let mut smt = SMT::default();
    let mut rng = thread_rng();

    //获得空的状态树根
    let old_root: H256 = smt.root().clone();
    print!("old root: {:?}\n", old_root);

    let account_count = 50;
    let mut total_amount = 0;

    let mut mod_keys = Vec::with_capacity(account_count);

    //往状态树里添加值
    for _ in 0..account_count {
        let key: H256 = rng.gen::<[u8; 32]>().into();
        let value = AccountVal {
            amount: 10000,
            nonce: 0,
            clock_id: 0,
        };
        total_amount += value.amount;
        mod_keys.push((key, AccountVal::zero(), value));
        smt.update(key, value).unwrap();
    }

    //得到生成更新后的状态根
    let new_root = smt.root().clone();
    print!("new root:{:?}\n", new_root);

    //生成Merkle proof
    let merkle_proof = smt
        .merkle_proof(mod_keys.clone().into_iter().map(|(k, _, _)| k).collect())
        .unwrap();

    let old_keys: Vec<(H256, H256)> = mod_keys
        .clone()
        .into_iter()
        .map(|(k, old, _)| (k, old.to_h256()))
        .collect();
    let merkle_proof_compiled = merkle_proof.clone().compile(old_keys.clone()).unwrap();

    //验证旧状态
    let res = merkle_proof_compiled
        .verify::<CKBBlake2bHasher>(&old_root, old_keys)
        .unwrap();
    assert!(res);

    // 验证新状态
    let new_keys: Vec<(H256, H256)> = mod_keys
        .clone()
        .into_iter()
        .map(|(k, _, new)| (k, new.to_h256()))
        .collect();
    let res = merkle_proof_compiled
        .verify::<CKBBlake2bHasher>(&new_root, new_keys)
        .unwrap();
    assert!(res);

    //将证明转成字节
    let merkle_proof_bytes: Vec<u8> = merkle_proof_compiled.into();

    print!("proof len:{}\n", merkle_proof_bytes.len());

    //构建输出的Cell data
    let sst_data_new = SSTDataBuilder::default()
        .amount(Uint128::from_slice(&total_amount.to_le_bytes()).unwrap())
        .info(Byte32::from_slice(&[1u8; 32]).unwrap())
        .smt_root(Byte32::from_slice(new_root.as_slice()).unwrap())
        .build();

    let output = CellOutput::new_builder()
        .capacity(1000u64.pack())
        .lock(lock_script.clone())
        .type_(sst_script.clone().pack())
        .build();

    let mut item_vec_builder = SmtUpdateItemVecBuilder::default();
    for (key, old_value, new_value) in mod_keys.into_iter() {
        let item = SmtUpdateItemBuilder::default()
            .key(ckb_types::packed::Byte32::from_slice(key.as_slice()).unwrap())
            .old_value((&old_value).into())
            .new_value((&new_value).into())
            .build();
        item_vec_builder = item_vec_builder.push(item);
    }

    let item_vec = item_vec_builder.build();

    //生成Witness
    let updata_action = SmtUpdateActionBuilder::default()
        .proof(
            SmtProofBuilder::default()
                .extend(merkle_proof_bytes.iter().map(|v| Byte::from(*v)))
                .build(),
        )
        .updates(item_vec)
        .build();

    let witness_args = WitnessArgsBuilder::default()
        .output_type(Some(updata_action.as_bytes()).pack())
        .build();

    let witness = witness_args.as_bytes().pack();

    print!("witness len:{}\n", witness.len());
    // build transaction
    let tx = TransactionBuilder::default()
        .input(input)
        .output(output)
        .output_data(sst_data_new.as_bytes().pack())
        .cell_dep(lock_script_dep)
        .cell_dep(sst_script_dep)
        .witness(witness)
        .build();
    let tx = context.complete_tx(tx);

    // run
    let cycles = context
        .verify_tx(&tx, MAX_CYCLES)
        .expect("pass verification");
    println!("consume cycles: {}", cycles);
}

#[test]
fn test_change_ledger() {
    //设定状态树的参数
    let account_count = 10000;
    let update_count = 50;

    // deploy contract
    let mut context = Context::default();
    let sst_bin: Bytes = Loader::default().load_binary("simple-social-token");
    let sst_out_point = context.deploy_cell(sst_bin);
    let always_success_bin = ALWAYS_SUCCESS.clone();
    let always_success_out_point = context.deploy_cell(always_success_bin);

    // prepare scripts
    let lock_script = context
        .build_script(&always_success_out_point, Bytes::from(vec![42]))
        .expect("script");
    let lock_script_dep = CellDep::new_builder()
        .out_point(always_success_out_point)
        .build();

    let sst_script = context.build_script(&sst_out_point, random_32bytes());
    let sst_script_dep = CellDep::new_builder().out_point(sst_out_point).build();

    let mut smt = SMT::default();
    let mut rng = thread_rng();

    //往状态树里添加随机值
    for _ in 0..account_count {
        let key: H256 = rng.gen::<[u8; 32]>().into();
        let value = AccountVal::random(&mut rng);
        smt.update(key, value).unwrap();
    }

    //设定本次交易的提交者
    let committer: H256 = rng.gen::<[u8; 32]>().into();
    let committer_value = AccountVal {
        amount: 10000,
        nonce: 0,
        clock_id: 0,
    };
    smt.update(committer, committer_value).unwrap();

    //往状态树里添加待测试的值
    let mut keys = Vec::with_capacity(update_count);
    for _ in 0..update_count {
        let key: H256 = rng.gen::<[u8; 32]>().into();
        //每个账户初始10000个币的余额
        let value = AccountVal {
            amount: 10000,
            nonce: 0,
            clock_id: 0,
        };
        keys.push((key, value.clone()));
        smt.update(key, value).unwrap();
    }

    //获得旧的状态树根
    let old_root: H256 = smt.root().clone();
    print!("old root: {:?}\n", old_root);

    //生成旧的Cell data
    let sst_data_old = SSTDataBuilder::default()
        .amount(Uint128::from_slice(&(10000000 as u128).to_le_bytes()).unwrap())
        .info(Byte32::from_slice(&[1u8; 32]).unwrap())
        .smt_root(Byte32::from_slice(old_root.as_slice()).unwrap())
        .build();

    // prepare cells
    let input_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(1000u64.pack())
            .lock(lock_script.clone())
            .type_(sst_script.clone().pack())
            .build(),
        sst_data_old.as_bytes(),
    );
    let input = CellInput::new_builder()
        .previous_output(input_out_point)
        .build();

    let mut mod_keys = Vec::with_capacity(account_count);
    let mut amount_add: u128 = 0;
    for (key, value) in keys.iter() {
        let mut new_value = value.clone();
        new_value.amount += 1000;
        amount_add += 1000;

        smt.update(key.clone(), new_value).unwrap();
        mod_keys.push((key.clone(), value.clone(), new_value));
    }

    //生成更新后的状态根
    let new_root = smt.root().clone();
    print!("new root:{:?}\n", new_root);
    //生成Merkle proof
    let merkle_proof = smt
        .merkle_proof(mod_keys.clone().into_iter().map(|(k, _, _)| k).collect())
        .unwrap();

    let old_keys: Vec<(H256, H256)> = mod_keys
        .clone()
        .into_iter()
        .map(|(k, old, _)| (k, old.to_h256()))
        .collect();
    let merkle_proof_compiled = merkle_proof.clone().compile(old_keys.clone()).unwrap();

    //验证旧状态
    let res = merkle_proof_compiled
        .verify::<CKBBlake2bHasher>(&old_root, old_keys)
        .unwrap();
    assert!(res);

    // 验证新状态
    let new_keys: Vec<(H256, H256)> = mod_keys
        .clone()
        .into_iter()
        .map(|(k, _, new)| (k, new.to_h256()))
        .collect();
    let res = merkle_proof_compiled
        .verify::<CKBBlake2bHasher>(&new_root, new_keys)
        .unwrap();
    assert!(res);

    //将证明转成字节
    let merkle_proof_bytes: Vec<u8> = merkle_proof_compiled.into();

    print!("proof len:{}\n", merkle_proof_bytes.len());

    //得到更新序列
    let mut item_vec_builder = SmtUpdateItemVecBuilder::default();
    for (key, old_value, new_value) in mod_keys.into_iter() {
        let item = SmtUpdateItemBuilder::default()
            .key(ckb_types::packed::Byte32::from_slice(key.as_slice()).unwrap())
            .old_value((&old_value).into())
            .new_value((&new_value).into())
            .build();
        item_vec_builder = item_vec_builder.push(item);
    }

    let sst_data_new = SSTDataBuilder::default()
        .amount(Uint128::from_slice(&(10000000 as u128 + amount_add).to_le_bytes()).unwrap())
        .info(Byte32::from_slice(&[1u8; 32]).unwrap())
        .smt_root(Byte32::from_slice(new_root.as_slice()).unwrap())
        .build();

    let output = CellOutput::new_builder()
        .capacity(1000u64.pack())
        .lock(lock_script.clone())
        .type_(sst_script.clone().pack())
        .build();

    let item_vec = item_vec_builder.build();

    //生成Witness
    let updata_action = SmtUpdateActionBuilder::default()
        .proof(
            SmtProofBuilder::default()
                .extend(merkle_proof_bytes.iter().map(|v| Byte::from(*v)))
                .build(),
        )
        .updates(item_vec)
        .committer(Byte32::from_slice(committer.as_slice()).unwrap())
        .build();

    let witness_args = WitnessArgsBuilder::default()
        .output_type(Some(updata_action.as_bytes()).pack())
        .build();

    let witness = witness_args.as_bytes().pack();

    print!("witness len:{}\n", witness.len());
    // build transaction
    let tx = TransactionBuilder::default()
        .input(input)
        .output(output)
        .output_data(sst_data_new.as_bytes().pack())
        .cell_dep(lock_script_dep)
        .cell_dep(sst_script_dep)
        .witness(witness)
        .build();
    let tx = context.complete_tx(tx);

    // run
    let cycles = context
        .verify_tx(&tx, MAX_CYCLES)
        .expect("pass verification");
    println!("consume cycles: {}", cycles);
}

#[test]
fn test_transer_new() {
    //设定状态树的参数
    let account_count = 10000;
    let update_count = 50;

    // deploy contract
    let mut context = Context::default();
    let sst_bin: Bytes = Loader::default().load_binary("simple-social-token");
    let sst_out_point = context.deploy_cell(sst_bin);
    let always_success_bin = ALWAYS_SUCCESS.clone();
    let always_success_out_point = context.deploy_cell(always_success_bin);

    // prepare scripts
    let lock_script = context
        .build_script(&always_success_out_point, Bytes::from(vec![42]))
        .expect("script");
    let lock_script_dep = CellDep::new_builder()
        .out_point(always_success_out_point)
        .build();

    let sst_script = context.build_script(&sst_out_point, random_32bytes());
    let sst_script_dep = CellDep::new_builder().out_point(sst_out_point).build();

    let mut smt = SMT::default();
    let mut rng = thread_rng();

    //往状态树里添加随机值
    for _ in 0..account_count {
        let key: H256 = rng.gen::<[u8; 32]>().into();
        let value = AccountVal::random(&mut rng);
        smt.update(key, value).unwrap();
    }

    //设定本次交易的提交者
    let committer: H256 = rng.gen::<[u8; 32]>().into();
    let committer_value = AccountVal {
        amount: 10000,
        nonce: 0,
        clock_id: 0,
    };
    smt.update(committer, committer_value).unwrap();

    //往状态树里添加待测试的值
    let key_transfer: H256 = rng.gen::<[u8; 32]>().into();
    //每个账户初始10000个币的余额
    let value = AccountVal {
        amount: 10000,
        nonce: 0,
        clock_id: 0,
    };
    smt.update(key_transfer, value).unwrap();

    //获得旧的状态树根
    let old_root: H256 = smt.root().clone();
    print!("old root: {:?}\n", old_root);

    //生成旧的Cell data
    let sst_data_old = SSTDataBuilder::default()
        .amount(Uint128::from_slice(&(10000000 as u128).to_le_bytes()).unwrap())
        .info(Byte32::from_slice(&[1u8; 32]).unwrap())
        .smt_root(Byte32::from_slice(old_root.as_slice()).unwrap())
        .build();

    // prepare cells
    let input_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(1000u64.pack())
            .lock(lock_script.clone())
            .type_(sst_script.clone().pack())
            .build(),
        sst_data_old.as_bytes(),
    );
    let input = CellInput::new_builder()
        .previous_output(input_out_point)
        .build();

    let mut txs_builder = LegerTransactionVecBuilder::default();
    let mut mod_keys = Vec::with_capacity(update_count);
    let mut fee: u128 = 0;
    //开始构建交易转账

    let key_new = rng.gen::<[u8; 32]>().into();

    let old_value_1 = misc::SMT_NOT_EXISTING.clone();

    let mut new_value_0 = value;
    new_value_0.amount -= 1000;

    //发送方需要修改nonce
    new_value_0.nonce += 1;
    let mut new_value_1 = old_value_1;
    new_value_1.amount += 1000;

    mod_keys.push((key_transfer, value, new_value_0));
    mod_keys.push((key_new, old_value_1, new_value_1));

    smt.update(key_transfer, new_value_0).unwrap();
    smt.update(key_new, new_value_1).unwrap();

    //接收方
    let targets = TargetsBuilder::default()
        .push(
            TargetBuilder::default()
                .to(Byte32::from_slice(key_new.as_slice()).unwrap())
                .amount(Uint128::from_slice(&(1000 as u128).to_le_bytes()).unwrap())
                .build(),
        )
        .build();

    //发送方
    let raw = RawLedgerTransactionBuilder::default()
        .from(Byte32::from_slice(key_transfer.as_slice()).unwrap())
        .targets(targets)
        .nonce(Uint64::from_slice(&(0 as u64).to_le_bytes()).unwrap())
        .total_amount(Uint128::from_slice(&(1000 as u128).to_le_bytes()).unwrap())
        .fee(Uint128::from_slice(&(1 as u128).to_le_bytes()).unwrap())
        .build();

    //收取了一个token作为手续费
    fee += 1;
    let tx = LegerTransactionBuilder::default().raw(raw).build();
    txs_builder = txs_builder.push(tx);

    //把手续费部分加进去
    let mut committer_value_new = AccountVal::clone(&committer_value);
    committer_value_new.amount += fee;

    print!("fee:{},new_value:{:?}\n", fee, committer_value_new);
    mod_keys.push((committer, committer_value, committer_value_new));

    smt.update(committer, committer_value_new).unwrap();

    let txs = txs_builder.build();

    //生成更新后的状态根
    let new_root = smt.root().clone();
    print!("new root:{:?}\n", new_root);
    //生成Merkle proof
    let merkle_proof = smt
        .merkle_proof(mod_keys.clone().into_iter().map(|(k, _, _)| k).collect())
        .unwrap();

    let old_keys: Vec<(H256, H256)> = mod_keys
        .clone()
        .into_iter()
        .map(|(k, old, _)| (k, old.to_h256()))
        .collect();
    let merkle_proof_compiled = merkle_proof.clone().compile(old_keys.clone()).unwrap();

    //验证旧状态
    let res = merkle_proof_compiled
        .verify::<CKBBlake2bHasher>(&old_root, old_keys)
        .unwrap();
    assert!(res);

    // 验证新状态
    let new_keys: Vec<(H256, H256)> = mod_keys
        .clone()
        .into_iter()
        .map(|(k, _, new)| (k, new.to_h256()))
        .collect();
    let res = merkle_proof_compiled
        .verify::<CKBBlake2bHasher>(&new_root, new_keys)
        .unwrap();
    assert!(res);

    //将证明转成字节
    let merkle_proof_bytes: Vec<u8> = merkle_proof_compiled.into();

    print!("proof len:{}\n", merkle_proof_bytes.len());

    //得到更新序列
    let mut item_vec_builder = SmtUpdateItemVecBuilder::default();
    for (key, old_value, new_value) in mod_keys.into_iter() {
        let item = SmtUpdateItemBuilder::default()
            .key(ckb_types::packed::Byte32::from_slice(key.as_slice()).unwrap())
            .old_value((&old_value).into())
            .new_value((&new_value).into())
            .build();
        item_vec_builder = item_vec_builder.push(item);
    }

    let sst_data_new = SSTDataBuilder::default()
        .amount(Uint128::from_slice(&(10000000 as u128).to_le_bytes()).unwrap())
        .info(Byte32::from_slice(&[1u8; 32]).unwrap())
        .smt_root(Byte32::from_slice(new_root.as_slice()).unwrap())
        .build();

    let output = CellOutput::new_builder()
        .capacity(1000u64.pack())
        .lock(lock_script.clone())
        .type_(sst_script.clone().pack())
        .build();

    let item_vec = item_vec_builder.build();

    //生成Witness
    let updata_action = SmtUpdateActionBuilder::default()
        .proof(
            SmtProofBuilder::default()
                .extend(merkle_proof_bytes.iter().map(|v| Byte::from(*v)))
                .build(),
        )
        .updates(item_vec)
        .committer(Byte32::from_slice(committer.as_slice()).unwrap())
        .build();

    let tx_with_flag = LegerTransactionWithFlagBuilder::default().txs(txs).build();
    let witness_args = WitnessArgsBuilder::default()
        .input_type(Some(updata_action.as_bytes()).pack())
        .lock(Some(tx_with_flag.as_bytes()).pack())
        .build();

    let witness = witness_args.as_bytes().pack();

    print!("witness len:{}\n", witness.len());
    // build transaction
    let tx = TransactionBuilder::default()
        .input(input)
        .output(output)
        .output_data(sst_data_new.as_bytes().pack())
        .cell_dep(lock_script_dep)
        .cell_dep(sst_script_dep)
        .witness(witness)
        .build();
    let tx = context.complete_tx(tx);

    // run
    let cycles = context
        .verify_tx(&tx, MAX_CYCLES)
        .expect("pass verification");
    println!("consume cycles: {}", cycles);
}

#[test]
fn test_transer_multi() {
    //设定状态树的参数
    let account_count = 10000;
    let update_count = 50;

    // deploy contract
    let mut context = Context::default();
    let sst_bin: Bytes = Loader::default().load_binary("simple-social-token");
    let sst_out_point = context.deploy_cell(sst_bin);
    let always_success_bin = ALWAYS_SUCCESS.clone();
    let always_success_out_point = context.deploy_cell(always_success_bin);

    // prepare scripts
    let lock_script = context
        .build_script(&always_success_out_point, Bytes::from(vec![42]))
        .expect("script");
    let lock_script_dep = CellDep::new_builder()
        .out_point(always_success_out_point)
        .build();

    let sst_script = context.build_script(&sst_out_point, random_32bytes());
    let sst_script_dep = CellDep::new_builder().out_point(sst_out_point).build();

    let mut smt = SMT::default();
    let mut rng = thread_rng();

    //往状态树里添加随机值
    for _ in 0..account_count {
        let key: H256 = rng.gen::<[u8; 32]>().into();
        let value = AccountVal::random(&mut rng);
        smt.update(key, value).unwrap();
    }

    //设定本次交易的提交者
    let committer: H256 = rng.gen::<[u8; 32]>().into();
    let committer_value = AccountVal {
        amount: 10000,
        nonce: 0,
        clock_id: 0,
    };
    smt.update(committer, committer_value).unwrap();

    //往状态树里添加待测试的值
    let key_transfer: H256 = rng.gen::<[u8; 32]>().into();
    //每个账户初始10000个币的余额
    let value = AccountVal {
        amount: 1000000,
        nonce: 0,
        clock_id: 0,
    };
    smt.update(key_transfer, value).unwrap();

    //往状态树里添加待测试的值
    let mut keys = Vec::with_capacity(update_count);
    for _ in 0..update_count {
        let key: H256 = rng.gen::<[u8; 32]>().into();
        //每个账户初始10000个币的余额
        let value = AccountVal {
            amount: 10000,
            nonce: 0,
            clock_id: 0,
        };
        keys.push((key, value.clone()));
        smt.update(key, value).unwrap();
    }

    //获得旧的状态树根
    let old_root: H256 = smt.root().clone();
    print!("old root: {:?}\n", old_root);

    //生成旧的Cell data
    let sst_data_old = SSTDataBuilder::default()
        .amount(Uint128::from_slice(&(10000000 as u128).to_le_bytes()).unwrap())
        .info(Byte32::from_slice(&[1u8; 32]).unwrap())
        .smt_root(Byte32::from_slice(old_root.as_slice()).unwrap())
        .build();

    // prepare cells
    let input_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(1000u64.pack())
            .lock(lock_script.clone())
            .type_(sst_script.clone().pack())
            .build(),
        sst_data_old.as_bytes(),
    );
    let input = CellInput::new_builder()
        .previous_output(input_out_point)
        .build();

    let mut txs_builder = LegerTransactionVecBuilder::default();
    let mut mod_keys = Vec::with_capacity(update_count);
    let mut fee: u128 = 0;
    //开始构建交易转账
    let mut total_amount: u128 = 0;

    let mut targets_builder = TargetsBuilder::default();

    for (key, value) in keys.iter() {
        //发送方需要修改nonce
        let mut new_value = value.clone();
        new_value.amount += 1000;
        total_amount += 1000;

        mod_keys.push((key.clone(), value.clone(), new_value.clone()));

        smt.update(key.clone(), new_value).unwrap();

        //接收方
        targets_builder = targets_builder.push(
            TargetBuilder::default()
                .to(Byte32::from_slice(key.as_slice()).unwrap())
                .amount(Uint128::from_slice(&(1000 as u128).to_le_bytes()).unwrap())
                .build(),
        );
    }

    let mut transfer_value_new = value.clone();
    transfer_value_new.amount -= total_amount;

    print!(
        "total_amount:{},transfer_value_new.amount:{}",
        total_amount, transfer_value_new.amount
    );

    mod_keys.push((key_transfer.clone(), value, transfer_value_new.clone()));
    smt.update(key_transfer.clone(), transfer_value_new.clone())
        .unwrap();
    //发送方
    let raw = RawLedgerTransactionBuilder::default()
        .from(Byte32::from_slice(key_transfer.as_slice()).unwrap())
        .targets(targets_builder.build())
        .nonce(Uint64::from_slice(&(0 as u64).to_le_bytes()).unwrap())
        .total_amount(Uint128::from_slice(&(total_amount as u128).to_le_bytes()).unwrap())
        .fee(Uint128::from_slice(&(1 as u128).to_le_bytes()).unwrap())
        .build();

    //收取了一个token作为手续费
    fee += 1;
    let tx = LegerTransactionBuilder::default().raw(raw).build();
    txs_builder = txs_builder.push(tx);

    //把手续费部分加进去
    let mut committer_value_new = AccountVal::clone(&committer_value);
    committer_value_new.amount += fee;

    print!("fee:{},new_value:{:?}\n", fee, committer_value_new);
    mod_keys.push((committer, committer_value, committer_value_new));

    smt.update(committer, committer_value_new).unwrap();

    let txs = txs_builder.build();

    //生成更新后的状态根
    let new_root = smt.root().clone();
    print!("new root:{:?}\n", new_root);
    //生成Merkle proof
    let merkle_proof = smt
        .merkle_proof(mod_keys.clone().into_iter().map(|(k, _, _)| k).collect())
        .unwrap();

    let old_keys: Vec<(H256, H256)> = mod_keys
        .clone()
        .into_iter()
        .map(|(k, old, _)| (k, old.to_h256()))
        .collect();
    let merkle_proof_compiled = merkle_proof.clone().compile(old_keys.clone()).unwrap();

    //验证旧状态
    let res = merkle_proof_compiled
        .verify::<CKBBlake2bHasher>(&old_root, old_keys)
        .unwrap();
    assert!(res);

    // 验证新状态
    let new_keys: Vec<(H256, H256)> = mod_keys
        .clone()
        .into_iter()
        .map(|(k, _, new)| (k, new.to_h256()))
        .collect();
    let res = merkle_proof_compiled
        .verify::<CKBBlake2bHasher>(&new_root, new_keys)
        .unwrap();
    assert!(res);

    //将证明转成字节
    let merkle_proof_bytes: Vec<u8> = merkle_proof_compiled.into();

    print!("proof len:{}\n", merkle_proof_bytes.len());

    //得到更新序列
    let mut item_vec_builder = SmtUpdateItemVecBuilder::default();
    for (key, old_value, new_value) in mod_keys.into_iter() {
        let item = SmtUpdateItemBuilder::default()
            .key(ckb_types::packed::Byte32::from_slice(key.as_slice()).unwrap())
            .old_value((&old_value).into())
            .new_value((&new_value).into())
            .build();
        item_vec_builder = item_vec_builder.push(item);
    }

    let sst_data_new = SSTDataBuilder::default()
        .amount(Uint128::from_slice(&(10000000 as u128).to_le_bytes()).unwrap())
        .info(Byte32::from_slice(&[1u8; 32]).unwrap())
        .smt_root(Byte32::from_slice(new_root.as_slice()).unwrap())
        .build();

    let output = CellOutput::new_builder()
        .capacity(1000u64.pack())
        .lock(lock_script.clone())
        .type_(sst_script.clone().pack())
        .build();

    let item_vec = item_vec_builder.build();

    //生成Witness
    let updata_action = SmtUpdateActionBuilder::default()
        .proof(
            SmtProofBuilder::default()
                .extend(merkle_proof_bytes.iter().map(|v| Byte::from(*v)))
                .build(),
        )
        .updates(item_vec)
        .committer(Byte32::from_slice(committer.as_slice()).unwrap())
        .build();

    let tx_with_flag = LegerTransactionWithFlagBuilder::default().txs(txs).build();
    let witness_args = WitnessArgsBuilder::default()
        .input_type(Some(updata_action.as_bytes()).pack())
        .lock(Some(tx_with_flag.as_bytes()).pack())
        .build();

    let witness = witness_args.as_bytes().pack();

    print!("witness len:{}\n", witness.len());
    // build transaction
    let tx = TransactionBuilder::default()
        .input(input)
        .output(output)
        .output_data(sst_data_new.as_bytes().pack())
        .cell_dep(lock_script_dep)
        .cell_dep(sst_script_dep)
        .witness(witness)
        .build();
    let tx = context.complete_tx(tx);

    // run
    let cycles = context
        .verify_tx(&tx, MAX_CYCLES)
        .expect("pass verification");
    println!("consume cycles: {}", cycles);
}
