#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Ord, PartialOrd, Default)]
pub struct NodeId(u64);

impl NodeId {
    pub fn new(id: u64) -> Self {
        Self(id)
    }

    pub fn get(self) -> u64 {
        self.0
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
    fn new_and_get_roundtrip() {
        let id = NodeId::new(42);
        assert_eq!(id.get(), 42);
    }

    #[test]
    fn default_is_zero() {
        let id = NodeId::default();
        assert_eq!(id.get(), 0);
    }

    #[test]
    fn zero_id() {
        let id = NodeId::new(0);
        assert_eq!(id.get(), 0);
    }

    #[test]
    fn max_id() {
        let id = NodeId::new(u64::MAX);
        assert_eq!(id.get(), u64::MAX);
    }

    #[test]
    fn equality_same_value() {
        let a = NodeId::new(100);
        let b = NodeId::new(100);
        assert_eq!(a, b);
    }

    #[test]
    fn inequality_different_values() {
        let a = NodeId::new(1);
        let b = NodeId::new(2);
        assert_ne!(a, b);
    }

    #[test]
    fn ordering_less_than() {
        assert!(NodeId::new(1) < NodeId::new(2));
    }

    #[test]
    fn ordering_greater_than() {
        assert!(NodeId::new(100) > NodeId::new(50));
    }

    #[test]
    fn ordering_equal() {
        let a = NodeId::new(7);
        let b = NodeId::new(7);
        assert!(a <= b);
        assert!(a >= b);
    }

    #[test]
    fn partial_ord_consistency() {
        let a = NodeId::new(1);
        let b = NodeId::new(2);
        assert!(a < b);
        assert!(b > a);
        assert!(a <= b);
        assert!(b >= a);
    }

    #[test]
    fn clone_produces_equal_copy() {
        let id = NodeId::new(999);
        let cloned = id;
        assert_eq!(id, cloned);
    }

    #[test]
    fn hash_trait_consistent() {
        let a = NodeId::new(55);
        let b = NodeId::new(55);

        let mut hasher_a = DefaultHasher::new();
        let mut hasher_b = DefaultHasher::new();
        a.hash(&mut hasher_a);
        b.hash(&mut hasher_b);
        assert_eq!(hasher_a.finish(), hasher_b.finish());
    }

    #[test]
    fn hash_trait_different_for_different_inputs() {
        let a = NodeId::new(1);
        let b = NodeId::new(2);

        let mut hasher_a = DefaultHasher::new();
        let mut hasher_b = DefaultHasher::new();
        a.hash(&mut hasher_a);
        b.hash(&mut hasher_b);
        assert_ne!(hasher_a.finish(), hasher_b.finish());
    }

    #[test]
    fn debug_format() {
        let id = NodeId::new(55);
        assert_eq!(format!("{id:?}"), "NodeId(55)");
    }

    #[test]
    fn large_values_ordering() {
        let a = NodeId::new(u64::MAX - 1);
        let b = NodeId::new(u64::MAX);
        assert!(a < b);
    }
}
