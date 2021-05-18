use std::{collections::HashMap};
use super::{misc::*};


use rand::{thread_rng, Rng};
use sparse_merkle_tree::{traits::Value, H256};

#[test]
fn test_new_account() {
    let old_smt_keys = vec![(H256::from(K1.clone()), SMT_EXISTING.clone())];
    let new_smt_keys = vec![
        (H256::from(K1.clone()), SMT_EXISTING.clone()),
        (H256::from(K2.clone()), SMT_EXISTING.clone()),
        (H256::from(K3.clone()), SMT_EXISTING.clone()),
    ];
    let mod_keys_old = vec![
        (H256::from(K2.clone()), SMT_NOT_EXISTING.to_h256()),
        (H256::from(K3.clone()), SMT_NOT_EXISTING.to_h256()),
    ];

    let mod_keys_new = vec![
        (H256::from(K2.clone()), SMT_EXISTING.to_h256()),
        (H256::from(K3.clone()), SMT_EXISTING.to_h256()),
    ];

    let old_smt = new_smt(old_smt_keys);
    let new_smt = new_smt(new_smt_keys);
    let old_smt_root = old_smt.root().clone();
    let new_smt_root = new_smt.root().clone();

    let merkle_proof = old_smt
        .merkle_proof(mod_keys_old.clone().into_iter().map(|(k, _)| k).collect())
        .unwrap();
    let merkle_proof_compiled = merkle_proof.clone().compile(mod_keys_old.clone()).unwrap();

    //验证旧状态
    let res = merkle_proof_compiled
        .verify::<CKBBlake2bHasher>(&old_smt_root, mod_keys_old.clone())
        .ok()
        .unwrap();
    assert!(res);

    //验证新状态
    let res = merkle_proof_compiled
        .verify::<CKBBlake2bHasher>(&new_smt_root, mod_keys_new.clone())
        .ok()
        .unwrap();
    assert!(res);
}

#[test]
fn test_large_keys() {
    let account_count = 1000000;
    let update_count = 100;
    let mut smt = SMT::default();
    let mut rng = thread_rng();
    let mut keys = HashMap::with_capacity(account_count);
    for _ in 0..account_count {
        let key: H256 = rng.gen::<[u8; 32]>().into();
        let value = AccountVal::random(&mut rng);
        keys.insert(key, value.clone());
        smt.update(key, value).unwrap();
    }

    let mut count = 0;
    let mut mod_keys = Vec::with_capacity(update_count);
    let old_root = smt.root().clone();

    for (key, value) in keys.iter() {
        count += 1;
        let new_value = AccountVal::random(&mut rng);

        mod_keys.push((key.clone(), value.clone(), new_value.clone()));

        smt.update(*key, new_value).unwrap();
        if count > update_count {
            break;
        }
    }
    let new_root = smt.root().clone();

    let merkle_proof = smt
        .merkle_proof(mod_keys.clone().into_iter().map(|(k, _, _)| k).collect())
        .unwrap();

         //验证旧状态
    let old_keys: Vec<(H256, H256)> = mod_keys
        .clone()
        .into_iter()
        .map(|(k, old, _)| (k, old.to_h256()))
        .collect();
    let merkle_proof_compiled = merkle_proof.clone().compile(old_keys.clone()).unwrap();

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


    let merkle_proof_bytes: Vec<u8> = merkle_proof_compiled.clone().into();

    print!("proof len : {}\n", &merkle_proof_bytes.len());
}
