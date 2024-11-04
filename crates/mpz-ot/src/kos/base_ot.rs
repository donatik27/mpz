use mpz_core::Block;
use mpz_ot_core::{kos::CSP, ot::OTSender};

/// IKNP setup sender.
pub(crate) trait SetupSender {
    /// Error type.
    type Error: std::error::Error + Send + Sync + 'static;

    /// Allocates the base OT.
    fn alloc(&mut self) -> Result<(), Self::Error>;

    /// Returns the PRG seeds.
    fn seeds(&self) -> [[Block; 2]; CSP];
}

/// IKNP setup receiver.
pub(crate) trait BaseOTReceiver {
    /// Error type.
    type Error: std::error::Error + Send + Sync + 'static;

    /// Allocates the base OT.
    fn alloc(&mut self) -> Result<(), Self::Error>;

    /// Returns the PRG seeds if available.
    fn try_get_seeds(&self) -> Result<[[Block; 2]; CSP], Self::Error>;
}
