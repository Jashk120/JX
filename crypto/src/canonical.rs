/// Produces a deterministic, canonical byte encoding of a type.
/// This is the ONLY thing that should ever be fed into a hash function
/// for consensus-critical types.
pub trait CanonicalEncode {
    fn encode_canonical(&self, buf: &mut Vec<u8>);

    fn canonical_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        self.encode_canonical(&mut buf);
        buf
    }
}