pub struct EncFile {
    pub nonce: [u8; 12],
    pub tag: [u8; 16],
    pub data: Vec<u8>,
}
