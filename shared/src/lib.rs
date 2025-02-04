use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone)]
pub struct EncFile {
    pub nonce: [u8; 12],
    pub tag: [u8; 16],
    pub data: Vec<u8>,
    pub id: i32,
}

#[derive(Serialize, Deserialize)]
#[serde(untagged)]
pub enum EncFileResponse {
    Success(EncFile),
    Error { error: String },
}
