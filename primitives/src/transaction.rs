#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct Transaction {
    payload: Vec<u8>,
}

impl Transaction {
    pub fn from_bytes(payload: Vec<u8>) -> Self {
        Self { payload }
    }

    pub fn payload(&self) -> &[u8] {
        &self.payload
    }
}
