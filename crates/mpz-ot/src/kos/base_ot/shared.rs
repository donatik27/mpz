use std::sync::Arc;

use mpz_common::sync::AsyncMutex;
use mpz_core::Block;
use mpz_ot_core::{kos::CSP, ot::OTSender};

#[derive(Debug)]
struct SenderInner<OT> {
    id: u64,
    ot: OT,
}

#[derive(Debug, Clone)]
pub struct SharedBaseOTSender<OT> {
    ot: Arc<AsyncMutex<SenderInner<OT>>>,
}

impl<OT> SharedBaseOTSender<OT> {
    /// Creates a new shared base OT sender.
    pub fn new(ot: OT) -> Self {
        Self {
            ot: Arc::new(AsyncMutex::new_leader(SenderInner { id: 0, ot })),
        }
    }
}

#[derive(Debug, thiserror::Error)]
#[error(transparent)]
pub struct BaseOTError(#[from] ErrorRepr);

#[derive(Debug, thiserror::Error)]
enum ErrorRepr {}
