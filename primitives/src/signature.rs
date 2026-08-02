#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Signature([u8; 64]);

impl Default for Signature {
    fn default() -> Self {
        Self([0; 64])
    }
}
impl Signature {
    pub fn new(bytes: [u8; 64]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 64] {
        &self.0
    }
}
