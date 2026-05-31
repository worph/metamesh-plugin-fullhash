mod algorithms;
pub mod btih_v2;
mod cid;
pub mod midhash256;
mod stream;

pub use algorithms::{hash_bytes, hash_file};
pub use stream::hash_stream;
pub use btih_v2::{
    compute_btv2_hashes, compute_info_hash, compute_merkle_root, format_magnet_link,
    format_magnet_urn, BtV2Hashes, BT_BLOCK_SIZE,
};
pub use cid::{multicodec_of, to_cid};
pub use midhash256::compute_midhash256;
