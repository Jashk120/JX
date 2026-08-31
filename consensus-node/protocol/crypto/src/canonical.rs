/// Produces a deterministic, canonical byte encoding of a type.
/// This is the ONLY thing that should ever be fed into a hash function
/// for consensus-critical types.
pub trait CanonicalEncode {
    /// Encodes `self` into `buf` in canonical form.
    ///
    /// Returns `OutOfRange` if any length prefix exceeds `u32::MAX`.
    fn encode_canonical(&self, buf: &mut Vec<u8>) -> Result<(), primitives::Error>;

    /// Convenience: allocates and returns the canonical bytes.
    ///
    /// Returns `OutOfRange` if length exceeds `u32::MAX`.
    fn canonical_bytes(&self) -> Result<Vec<u8>, primitives::Error> {
        let mut buf = Vec::new();
        self.encode_canonical(&mut buf)?;
        Ok(buf)
    }
}
