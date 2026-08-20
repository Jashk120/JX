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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_empty() {
        let tx = Transaction::default();
        assert!(tx.payload().is_empty());
        assert_eq!(tx.payload().len(), 0);
    }

    #[test]
    fn from_bytes_empty_payload() {
        let tx = Transaction::from_bytes(Vec::new());
        assert!(tx.payload().is_empty());
    }

    #[test]
    fn from_bytes_non_empty_payload() {
        let data = vec![1, 2, 3, 4, 5];
        let tx = Transaction::from_bytes(data.clone());
        assert_eq!(tx.payload(), &data[..]);
    }

    #[test]
    fn from_bytes_preserves_exact_bytes() {
        let data = vec![0xFF, 0x00, 0xAB, 0xCD];
        let tx = Transaction::from_bytes(data.clone());
        assert_eq!(tx.payload().to_vec(), data);
    }

    #[test]
    fn equality_same_payload() {
        let data = vec![10, 20, 30];
        let a = Transaction::from_bytes(data.clone());
        let b = Transaction::from_bytes(data);
        assert_eq!(a, b);
    }

    #[test]
    fn inequality_different_payloads() {
        let a = Transaction::from_bytes(vec![1]);
        let b = Transaction::from_bytes(vec![2]);
        assert_ne!(a, b);
    }

    #[test]
    fn empty_vs_nonempty_inequality() {
        let empty = Transaction::default();
        let nonempty = Transaction::from_bytes(vec![0]);
        assert_ne!(empty, nonempty);
    }

    #[test]
    fn clone_produces_equal_copy() {
        let tx = Transaction::from_bytes(vec![7, 8, 9]);
        let cloned = tx.clone();
        assert_eq!(tx, cloned);
    }

    #[test]
    fn debug_format() {
        let tx = Transaction::from_bytes(vec![0xDE, 0xAD]);
        let dbg = format!("{tx:?}");
        assert!(dbg.contains("Transaction"));
    }

    #[test]
    fn large_payload() {
        let data = vec![0x42; 1024 * 1024];
        let tx = Transaction::from_bytes(data.clone());
        assert_eq!(tx.payload().len(), 1024 * 1024);
        assert_eq!(tx.payload()[0], 0x42);
        assert_eq!(tx.payload()[1024 * 1024 - 1], 0x42);
    }

    #[test]
    fn single_byte_payload() {
        let tx = Transaction::from_bytes(vec![0xFF]);
        assert_eq!(tx.payload().len(), 1);
        assert_eq!(tx.payload()[0], 0xFF);
    }

    #[test]
    fn default_equality() {
        let a = Transaction::default();
        let b = Transaction::default();
        assert_eq!(a, b);
    }
}
