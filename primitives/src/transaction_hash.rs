#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct TransactionHash([u8; 32]);

impl TransactionHash {
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}
