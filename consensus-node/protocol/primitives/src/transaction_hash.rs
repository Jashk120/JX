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

#[cfg(test)]
mod tests {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{
        Hash,
        Hasher,
    };

    use super::*;

    #[test]
    fn new_and_as_bytes_roundtrip() {
        let bytes = [0xAB; 32];
        let h = TransactionHash::new(bytes);
        assert_eq!(h.as_bytes(), &bytes);
    }

    #[test]
    fn all_zero_hash() {
        let h = TransactionHash::new([0u8; 32]);
        assert_eq!(h.as_bytes(), &[0u8; 32]);
    }

    #[test]
    fn all_max_byte_hash() {
        let h = TransactionHash::new([0xFF; 32]);
        assert_eq!(h.as_bytes(), &[0xFF; 32]);
    }

    #[test]
    fn all_zero_vs_all_max_inequality() {
        let a = TransactionHash::new([0u8; 32]);
        let b = TransactionHash::new([0xFF; 32]);
        assert_ne!(a, b);
    }

    #[test]
    fn equality_same_bytes() {
        let bytes = [0x42; 32];
        let a = TransactionHash::new(bytes);
        let b = TransactionHash::new(bytes);
        assert_eq!(a, b);
    }

    #[test]
    fn inequality_single_byte_difference() {
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        a[0] = 0x01;
        b[0] = 0x02;
        assert_ne!(TransactionHash::new(a), TransactionHash::new(b));
    }

    #[test]
    fn inequality_last_byte_difference() {
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        a[31] = 0x01;
        b[31] = 0x02;
        assert_ne!(TransactionHash::new(a), TransactionHash::new(b));
    }

    #[test]
    fn clone_produces_equal_copy() {
        let h = TransactionHash::new([0xAA; 32]);
        let cloned = h;
        assert_eq!(h, cloned);
    }

    #[test]
    fn hash_trait_consistent() {
        let bytes = [0x55; 32];
        let a = TransactionHash::new(bytes);
        let b = TransactionHash::new(bytes);

        let mut hasher_a = DefaultHasher::new();
        let mut hasher_b = DefaultHasher::new();
        a.hash(&mut hasher_a);
        b.hash(&mut hasher_b);
        assert_eq!(hasher_a.finish(), hasher_b.finish());
    }

    #[test]
    fn hash_trait_different_for_different_inputs() {
        let a = TransactionHash::new([0u8; 32]);
        let b = TransactionHash::new([0xFF; 32]);

        let mut hasher_a = DefaultHasher::new();
        let mut hasher_b = DefaultHasher::new();
        a.hash(&mut hasher_a);
        b.hash(&mut hasher_b);
        assert_ne!(hasher_a.finish(), hasher_b.finish());
    }

    #[test]
    fn debug_format() {
        let h = TransactionHash::new([0x01; 32]);
        let dbg = format!("{h:?}");
        assert!(dbg.starts_with("TransactionHash("));
    }

    #[test]
    fn alternating_pattern() {
        let mut bytes = [0u8; 32];
        for (i, b) in bytes.iter_mut().enumerate() {
            *b = if i % 2 == 0 { 0xAA } else { 0x55 };
        }
        let h = TransactionHash::new(bytes);
        assert_eq!(h.as_bytes(), &bytes);
    }

    #[test]
    fn single_bit_difference_at_each_position() {
        for pos in 0..32 {
            let mut a = [0u8; 32];
            let mut b = [0u8; 32];
            a[pos] = 0x01;
            b[pos] = 0x02;
            assert_ne!(
                TransactionHash::new(a),
                TransactionHash::new(b),
                "hashes should differ when byte {pos} differs"
            );
        }
    }
}
