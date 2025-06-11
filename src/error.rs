#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("Encountered an error in OQS encryption layer: {0:?}")]
    OQS(#[from] oqs::Error),

    #[error("Invalid key length: {0:?}")]
    InvalidAesKeyLength(#[from] aes_gcm::aes::cipher::InvalidLength),

    #[error("AES cryptography error: {0:?}")]
    Aes(#[from] aes_gcm::Error),

    #[error("Msgpack serialization error: {0:?}")]
    MsgpackSerialization(#[from] rmp_serde::encode::Error),

    #[error("Msgpack deserialization error: {0:?}")]
    MsgpackDeserialization(#[from] rmp_serde::decode::Error),
}

pub type Result<T> = std::result::Result<T, Error>;
