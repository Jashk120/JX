use std::fmt;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    Validation { reason: String },
    OutOfRange { field: &'static str, got: String },
    SerializationFailed { reason: String },
    InvalidState { reason: String },
}

pub type Result<T> = std::result::Result<T, Error>;

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Validation { reason } => write!(f, "validation failed: {reason}"),
            Self::OutOfRange { field, got } => write!(f, "{field} is out of range: {got}"),
            Self::SerializationFailed { reason } => write!(f, "serialization failed: {reason}"),
            Self::InvalidState { reason } => write!(f, "invalid state: {reason}"),
        }
    }
}

impl std::error::Error for Error {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validation_display() {
        let err = Error::Validation { reason: "bad input".into() };
        assert_eq!(err.to_string(), "validation failed: bad input");
    }

    #[test]
    fn out_of_range_display() {
        let err = Error::OutOfRange { field: "index", got: "999".into() };
        assert_eq!(err.to_string(), "index is out of range: 999");
    }

    #[test]
    fn serialization_failed_display() {
        let err = Error::SerializationFailed { reason: "unexpected EOF".into() };
        assert_eq!(err.to_string(), "serialization failed: unexpected EOF");
    }

    #[test]
    fn invalid_state_display() {
        let err = Error::InvalidState { reason: "already finalized".into() };
        assert_eq!(err.to_string(), "invalid state: already finalized");
    }

    #[test]
    fn equality_same_variant_same_data() {
        let a = Error::Validation { reason: "x".into() };
        let b = Error::Validation { reason: "x".into() };
        assert_eq!(a, b);
    }

    #[test]
    fn inequality_different_reasons() {
        let a = Error::Validation { reason: "x".into() };
        let b = Error::Validation { reason: "y".into() };
        assert_ne!(a, b);
    }

    #[test]
    fn inequality_different_variants() {
        let a = Error::Validation { reason: "x".into() };
        let b = Error::InvalidState { reason: "x".into() };
        assert_ne!(a, b);
    }

    #[test]
    fn clone_produces_equal_copy() {
        let err = Error::SerializationFailed { reason: "test".into() };
        let cloned = err.clone();
        assert_eq!(err, cloned);
    }

    #[test]
    fn debug_format() {
        let err = Error::Validation { reason: "test".into() };
        let dbg = format!("{err:?}");
        assert!(dbg.contains("Validation"));
        assert!(dbg.contains("test"));
    }

    #[test]
    fn error_trait_object_safe() {
        let err: Box<dyn std::error::Error> =
            Box::new(Error::InvalidState { reason: "oops".into() });
        assert_eq!(err.to_string(), "invalid state: oops");
    }

    #[test]
    fn error_trait_from_std() {
        let err = Error::Validation { reason: "fail".into() };
        let std_err: &dyn std::error::Error = &err;
        assert!(std_err.source().is_none());
    }

    #[test]
    fn empty_reason_strings() {
        let err = Error::Validation { reason: String::new() };
        assert_eq!(err.to_string(), "validation failed: ");
    }

    #[test]
    fn out_of_range_static_field() {
        let err = Error::OutOfRange { field: "timestamp", got: "-1".into() };
        assert_eq!(err.to_string(), "timestamp is out of range: -1");
    }

    #[test]
    fn serialization_failed_long_reason() {
        let reason = "x".repeat(1000);
        let err = Error::SerializationFailed { reason: reason.clone() };
        assert_eq!(err.to_string(), format!("serialization failed: {reason}"));
    }

    #[test]
    fn result_type_ok() {
        let r: Result<i32> = Ok(42);
        assert_eq!(r, Ok(42));
    }

    #[test]
    fn result_type_err() {
        let r: Result<()> = Err(Error::Validation { reason: "bad".into() });
        assert!(r.is_err());
    }

    #[test]
    fn all_variants_are_cloneable() {
        let validation = Error::Validation { reason: "a".into() };
        let out_of_range = Error::OutOfRange { field: "f", got: "0".into() };
        let serialization = Error::SerializationFailed { reason: "b".into() };
        let invalid_state = Error::InvalidState { reason: "c".into() };

        let _ = validation.clone();
        let _ = out_of_range.clone();
        let _ = serialization.clone();
        let _ = invalid_state.clone();
    }

    #[test]
    fn all_variants_are_debuggable() {
        let validation = Error::Validation { reason: "a".into() };
        let out_of_range = Error::OutOfRange { field: "f", got: "0".into() };
        let serialization = Error::SerializationFailed { reason: "b".into() };
        let invalid_state = Error::InvalidState { reason: "c".into() };

        let _ = format!("{validation:?}");
        let _ = format!("{out_of_range:?}");
        let _ = format!("{serialization:?}");
        let _ = format!("{invalid_state:?}");
    }
}
