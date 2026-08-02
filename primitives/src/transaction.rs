#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct Transaction {
    payload: Vec<u8>,
}

impl Transaction {
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }
}
