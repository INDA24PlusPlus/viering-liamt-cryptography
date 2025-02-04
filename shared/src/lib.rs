use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Serialize, Deserialize, Clone)]
pub struct EncFile {
    pub nonce: [u8; 12],
    pub tag: [u8; 16],
    pub data: Vec<u8>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct UploadResponse {
    pub id: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct RetrieveResponse {
    pub proof: Vec<u8>,
    pub merkle_root: [u8; 32],
    pub merkle_tree_len: usize,
    pub file: EncFile,
}

#[derive(Serialize, Deserialize)]
#[serde(untagged)]
pub enum RetrieveResponseEnum {
    Success(RetrieveResponse),
    Error { error: String },
}

pub fn hash_encfile(file: &EncFile) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(file.nonce);
    hasher.update(file.tag);
    hasher.update(&file.data);
    hasher.finalize().into()
}
