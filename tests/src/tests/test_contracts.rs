use crate::{
    tests::misc::{AccountVal, CKBBlake2bHasher, SMT},
    Loader,
};

use sst_mol::{
    LegerTransactionVecBuilder, SSTDataBuilder, SmtProofBuilder, SmtUpdateActionBuilder,
    SmtUpdateItemBuilder, SmtUpdateItemVecBuilder,
};

use std::collections::HashMap;

use rand::{thread_rng, Rng};
use sparse_merkle_tree::{traits::Value, H256};

use super::*;
use ckb_testtool::ckb_types::{bytes::Bytes, core::TransactionBuilder, packed::*, prelude::*};
use ckb_testtool::{builtin::ALWAYS_SUCCESS, context::Context};

#[test]
fn test_success() {
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

    let sst_script = context.build_script(&sst_out_point, random_20bytes());
    let sst_script_dep = CellDep::new_builder().out_point(sst_out_point).build();

    //设定状态树的参数
    let account_count = 10000;
    let update_count = 10;
    let mut smt = SMT::default();
    let mut rng = thread_rng();
    let mut keys = HashMap::with_capacity(account_count);
    //往状态树插入随机生成的Key value
    for _ in 0..account_count {
        let key: H256 = rng.gen::<[u8; 32]>().into();
        let value = AccountVal::random(&mut rng);
        keys.insert(key, value.clone());
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

    //随机更新一批Key
    let mut count = 0;
    let mut mod_keys = Vec::with_capacity(update_count);
    for (key, value) in keys.iter() {
        count += 1;
        let new_value = AccountVal::random(&mut rng);

        mod_keys.push((key.clone(), value.clone(), new_value.clone()));

        smt.update(*key, new_value).unwrap();
        if count > update_count {
            break;
        }
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

    let txs = LegerTransactionVecBuilder::default().build();

    //生成Witness
    let updata_action = SmtUpdateActionBuilder::default()
        .proof(
            SmtProofBuilder::default()
                .extend(merkle_proof_bytes.iter().map(|v| Byte::from(*v)))
                .build(),
        )
        .updates(item_vec)
        .txs(txs)
        .build();

    let witness = WitnessArgsBuilder::default()
        .input_type(Some(updata_action.as_bytes()).pack())
        .build();

    // build transaction
    let tx = TransactionBuilder::default()
        .input(input)
        .output(output)
        .output_data(sst_data_new.as_bytes().pack())
        .cell_dep(lock_script_dep)
        .cell_dep(sst_script_dep)
        .witness(witness.as_bytes().pack())
        .build();
    let tx = context.complete_tx(tx);

    // run
    let cycles = context
        .verify_tx(&tx, MAX_CYCLES)
        .expect("pass verification");
    println!("consume cycles: {}", cycles);
}
