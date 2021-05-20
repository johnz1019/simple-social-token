use ckb_testtool::bytes::Bytes;
use rand::{thread_rng, Rng};

mod misc;
mod test_contracts;
mod test_smt;

const MAX_CYCLES: u64 = 100_000_000;

pub fn random_20bytes() -> Bytes {
    let mut rng = thread_rng();
    let mut buf = vec![0u8; 20];
    rng.fill(&mut buf[..]);
    Bytes::from(buf)
}