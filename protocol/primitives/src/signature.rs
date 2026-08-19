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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_all_zeros() {
        let sig = Signature::default();
        assert_eq!(sig.as_bytes(), &[0u8; 64]);
    }

    #[test]
    fn new_and_as_bytes_roundtrip() {
        let bytes = [0xAB; 64];
        let sig = Signature::new(bytes);
        assert_eq!(sig.as_bytes(), &bytes);
    }

    #[test]
    fn all_max_byte_signature() {
        let bytes = [0xFF; 64];
        let sig = Signature::new(bytes);
        assert_eq!(sig.as_bytes(), &bytes);
    }

    #[test]
    fn all_zero_vs_all_max_inequality() {
        let zeros = Signature::default();
        let maxed = Signature::new([0xFF; 64]);
        assert_ne!(zeros, maxed);
    }

    #[test]
    fn equality_same_bytes() {
        let bytes = [0x42; 64];
        let a = Signature::new(bytes);
        let b = Signature::new(bytes);
        assert_eq!(a, b);
    }

    #[test]
    fn inequality_single_bit_difference() {
        let mut bytes_a = [0u8; 64];
        let mut bytes_b = [0u8; 64];
        bytes_a[0] = 0x01;
        bytes_b[0] = 0x02;
        assert_ne!(Signature::new(bytes_a), Signature::new(bytes_b));
    }

    #[test]
    fn clone_produces_equal_copy() {
        let sig = Signature::new([0xAA; 64]);
        let cloned = sig.clone();
        assert_eq!(sig, cloned);
    }

    #[test]
    fn debug_format_contains_bytes() {
        let sig = Signature::new([0x01; 64]);
        let dbg = format!("{sig:?}");
        assert!(dbg.starts_with("Signature("));
    }

    #[test]
    fn single_byte_position_distinguishes_signatures() {
        let mut a = [0u8; 64];
        let mut b = [0u8; 64];
        a[63] = 0x01;
        b[63] = 0x02;
        assert_ne!(Signature::new(a), Signature::new(b));
    }

    #[test]
    fn empty_like_pattern_all_zeros_different_from_default() {
        let default_sig = Signature::default();
        let constructed = Signature::new([0u8; 64]);
        assert_eq!(default_sig, constructed);
    }

    #[test]
    fn alternating_byte_pattern() {
        let mut bytes = [0u8; 64];
        for (i, b) in bytes.iter_mut().enumerate() {
            *b = if i % 2 == 0 { 0xAA } else { 0x55 };
        }
        let sig = Signature::new(bytes);
        assert_eq!(sig.as_bytes(), &bytes);
    }
}
