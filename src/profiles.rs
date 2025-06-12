use base64::Engine;
use serde::{Deserialize, Serialize};
use sha2::Digest;

use crate::PublicContext;

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct UserMetadata {
    pub display_name: Option<String>,
    pub pronouns: Option<Vec<String>>,
    pub status: Option<String>,
    pub description: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UserProfile {
    id: String,
    username: String,
    discriminant: String,
    encryption: PublicContext,
    metadata: UserMetadata,
}

impl UserProfile {
    pub fn new(
        username: impl AsRef<str>,
        encryption: PublicContext,
        metadata: UserMetadata,
    ) -> Self {
        let username = username.as_ref().to_string();
        let mut id_info = encryption.as_bytes();
        id_info.extend(username.as_bytes());
        let discriminant = format!(
            "{:X}",
            crc::Crc::<u16>::new(&crc::CRC_16_IBM_3740).checksum(&id_info)
        );
        let full_id =
            base64::prelude::BASE64_URL_SAFE_NO_PAD.encode(sha2::Sha256::digest(id_info).to_vec());
        Self {
            id: full_id,
            username,
            discriminant,
            encryption,
            metadata,
        }
    }

    pub fn username(&self) -> String {
        self.username.clone()
    }

    pub fn discriminant(&self) -> String {
        self.discriminant.clone()
    }

    pub fn metadata(&self) -> UserMetadata {
        self.metadata.clone()
    }

    pub fn encryption_context(&self) -> PublicContext {
        self.encryption.clone()
    }

    pub fn handle(&self) -> String {
        format!("{}#{}", self.username(), self.discriminant())
    }

    pub fn id(&self) -> String {
        self.id.clone()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ServerProfile {
    pub id: String,
    pub encryption: PublicContext,
    pub display_name: String,
    pub motd: Option<String>,
}

impl ServerProfile {
    pub fn new(
        encryption: PublicContext,
        name: impl AsRef<str>,
        motd: Option<impl AsRef<str>>,
    ) -> Self {
        let id = base64::prelude::BASE64_URL_SAFE_NO_PAD.encode(encryption.as_bytes());
        let motd = motd.and_then(|v| Some(v.as_ref().to_string()));
        Self {
            id,
            encryption,
            display_name: name.as_ref().to_string(),
            motd,
        }
    }
}
