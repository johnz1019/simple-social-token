// Import from `core` instead of from `std` since we are in no-std mode
use core::{result::Result, u64};

// Import heap related library from `alloc`
// https://doc.rust-lang.org/alloc/index.html
use alloc::{vec, vec::Vec};

// Import CKB syscalls and structures
// https://nervosnetwork.github.io/ckb-std/riscv64imac-unknown-none-elf/doc/ckb_std/index.html
use ckb_std::{
    ckb_types::{bytes::Bytes, prelude::*},
    debug,
    high_level::{load_script, load_tx_hash},
};

use crate::error::Error;

struct Value {
    amount: u128,
    nonce: u64,
    timestamp: u64,
}

struct Target {
    to: Bytes,    //接收方公钥hash,转账金额
    amount: u128, //接收方公钥hash,转账金额
}

struct RawLedgerTransaction {
    ledger_cell_typeid: Bytes, // 避免跨ledger cells的签名重放攻击
    from: Bytes,               // publickey hash
    total_transfer: u128,      //转账总额
    to: Vec<Target>,
    nonce: u64,
}

struct LedgerTransaction {
    raw: RawLedgerTransaction,
    signature: Bytes,
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

    let tx_hash = load_tx_hash()?;
    debug!("tx hash is {:?}", tx_hash);

    let _buf: Vec<_> = vec![0u8; 32];

    Ok(())
}
