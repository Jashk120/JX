#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Timestamp(u64);

impl Timestamp {
    pub fn new(value: u64) -> Self {
        Self(value)
    }

    pub fn get(self) -> u64 {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_and_get_roundtrip() {
        let ts = Timestamp::new(42);
        assert_eq!(ts.get(), 42);
    }

    #[test]
    fn zero_timestamp() {
        let ts = Timestamp::new(0);
        assert_eq!(ts.get(), 0);
    }

    #[test]
    fn max_timestamp() {
        let ts = Timestamp::new(u64::MAX);
        assert_eq!(ts.get(), u64::MAX);
    }

    #[test]
    fn equality_same_value() {
        let a = Timestamp::new(100);
        let b = Timestamp::new(100);
        assert_eq!(a, b);
    }

    #[test]
    fn inequality_different_values() {
        let a = Timestamp::new(1);
        let b = Timestamp::new(2);
        assert_ne!(a, b);
    }

    #[test]
    fn ordering_less_than() {
        assert!(Timestamp::new(1) < Timestamp::new(2));
    }

    #[test]
    fn ordering_greater_than() {
        assert!(Timestamp::new(100) > Timestamp::new(50));
    }

    #[test]
    fn ordering_equal() {
        assert!(Timestamp::new(7) == Timestamp::new(7));
    }

    #[test]
    fn clone_produces_equal_copy() {
        let ts = Timestamp::new(999);
        let cloned = ts;
        assert_eq!(ts, cloned);
    }

    #[test]
    fn debug_format() {
        let ts = Timestamp::new(55);
        assert_eq!(format!("{ts:?}"), "Timestamp(55)");
    }

    #[test]
    fn large_values_ordering() {
        let a = Timestamp::new(u64::MAX - 1);
        let b = Timestamp::new(u64::MAX);
        assert!(a < b);
    }
}
