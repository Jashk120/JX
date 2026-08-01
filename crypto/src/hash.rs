use primitives::{
    Event,
    EventHash,
};

use crate::traits::Hashable;

impl Hashable for Event {
    type Hash = EventHash;

    fn hash(&self) -> Self::Hash {
        todo!()
    }
}