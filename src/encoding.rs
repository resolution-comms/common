use serde_with::{base64::UrlSafe, formats::Unpadded};

pub type Base64 = serde_with::base64::Base64<UrlSafe, Unpadded>;
