use derive_builder::Builder;

/// KOS15 sender configuration.
#[derive(Debug, Default, Clone, Builder)]
pub struct SenderConfig {}

impl SenderConfig {
    /// Creates a new builder for SenderConfig.
    pub fn builder() -> SenderConfigBuilder {
        SenderConfigBuilder::default()
    }
}

/// KOS15 receiver configuration.
#[derive(Debug, Default, Clone, Builder)]
pub struct ReceiverConfig {}

impl ReceiverConfig {
    /// Creates a new builder for ReceiverConfig.
    pub fn builder() -> ReceiverConfigBuilder {
        ReceiverConfigBuilder::default()
    }
}
