// tools, functions, utilities, etc

use std::u128;

use ckb_hash::{new_blake2b, Blake2b, Blake2bBuilder};
use ckb_types::molecule::prelude::{Builder, Entity};
use ckb_types::packed::{Uint128, Uint64};
use lazy_static::lazy_static;
use rand::prelude::ThreadRng;
use rand::Rng;
use sparse_merkle_tree::default_store::DefaultStore;
use sparse_merkle_tree::traits::{Hasher, Value};
use sparse_merkle_tree::{SparseMerkleTree, H256};

use sst_mol::{AccountValue, AccountValueBuilder};

#[derive(Debug, Default, Clone, Copy)]
pub struct AccountVal {
    pub amount: u128,
    pub nonce: u64,
    pub clock_id: u64,
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

impl AccountVal {
    fn is_zero(&self) -> bool {
        return self.amount == 0;
    }

    pub fn random(rng: &mut ThreadRng) -> AccountVal {
        let amount: u128 = rng.gen();
        let nonce: u64 = rng.gen();
        let clock_id: u64 = rng.gen();

        AccountVal {
            amount: amount,
            nonce: nonce,
            clock_id: clock_id,
        }
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

pub const BLAKE2B_KEY: &[u8] = &[];
pub const BLAKE2B_LEN: usize = 32;
pub const PERSONALIZATION: &[u8] = b"ckb-default-hash";

lazy_static! {
    pub static ref SMT_EXISTING: AccountVal = AccountVal {
        amount: 1000,
        nonce: 0,
        clock_id: 0,
    };
    pub static ref SMT_NOT_EXISTING: AccountVal = AccountVal {
        amount: 0,
        nonce: 0,
        clock_id: 0,
    };
    pub static ref TYPE_ID_CODE_HASH: [u8; 32] = [
        0x54, 0x59, 0x50, 0x45, 0x5f, 0x49, 0x44, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00
    ];
    pub static ref K1: [u8; 32] = [
        111, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00
    ];
    pub static ref K2: [u8; 32] = [
        222, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00
    ];
    pub static ref K3: [u8; 32] = [
        222, 111, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00
    ];
}

pub struct CKBBlake2bHasher(Blake2b);

impl Default for CKBBlake2bHasher {
    fn default() -> Self {
        let blake2b = Blake2bBuilder::new(BLAKE2B_LEN)
            .personal(PERSONALIZATION)
            .key(BLAKE2B_KEY)
            .build();
        CKBBlake2bHasher(blake2b)
    }
}

impl Hasher for CKBBlake2bHasher {
    fn write_h256(&mut self, h: &H256) {
        self.0.update(h.as_slice());
    }
    fn finish(self) -> H256 {
        let mut hash = [0u8; 32];
        self.0.finalize(&mut hash);
        hash.into()
    }
}

pub type SMT = SparseMerkleTree<CKBBlake2bHasher, AccountVal, DefaultStore<AccountVal>>;

pub fn new_smt(pairs: Vec<(H256, AccountVal)>) -> SMT {
    let mut smt = SMT::default();
    for (key, value) in pairs {
        smt.update(key, value).unwrap();
    }
    smt
}
