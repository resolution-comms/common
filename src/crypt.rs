use std::{fmt::Debug, sync::Arc};

use aes_gcm::{
    AeadCore, Aes256Gcm, KeyInit,
    aead::{Aead, OsRng, generic_array::GenericArray},
};
use oqs::{
    kem::{self, Ciphertext},
    sig::{self, Signature},
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_with::serde_as;

fn default_kem() -> Arc<kem::Kem> {
    Arc::new(kem::Kem::new(kem::Algorithm::MlKem768).unwrap())
}

fn default_sig() -> Arc<sig::Sig> {
    Arc::new(sig::Sig::new(sig::Algorithm::MlDsa65).unwrap())
}

#[serde_as]
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct CryptoPacket {
    pub(crate) origin: PublicContext,

    #[serde_as(as = "crate::encoding::Base64")]
    pub(crate) nonce: [u8; 12],
    pub(crate) key: Ciphertext,

    #[serde_as(as = "crate::encoding::Base64")]
    pub(crate) body: Vec<u8>,
    pub(crate) signature: Signature,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PublicContext {
    encrypt: kem::PublicKey,
    sign: sig::PublicKey,
}

impl PublicContext {
    pub(crate) fn new(encrypt: kem::PublicKey, sign: sig::PublicKey) -> Self {
        Self { encrypt, sign }
    }

    pub fn encryption_key(&self) -> kem::PublicKey {
        self.encrypt.clone()
    }

    pub fn signing_key(&self) -> sig::PublicKey {
        self.sign.clone()
    }

    pub fn as_bytes(&self) -> Vec<u8> {
        let mut out: Vec<u8> = Vec::new();
        out.extend(self.encryption_key().into_vec());
        out.extend(self.signing_key().into_vec());
        out
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct CryptoContext {
    encryption_keys: (kem::PublicKey, kem::SecretKey),
    signing_keys: (sig::PublicKey, sig::SecretKey),

    #[serde(skip, default = "default_kem")]
    kem: Arc<kem::Kem>,

    #[serde(skip, default = "default_sig")]
    sig: Arc<sig::Sig>,
}

impl Debug for CryptoContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&format!(
            "CryptoContext {{ encrypt: ({:?}, ...), sign: ({:?}, ...) }}",
            self.encryption_keys.0, self.signing_keys.0
        ))
    }
}

impl CryptoContext {
    pub fn new() -> crate::Result<Self> {
        let _kem = default_kem();
        let _sig = default_sig();

        Ok(Self {
            encryption_keys: _kem.keypair()?,
            signing_keys: _sig.keypair()?,
            kem: _kem,
            sig: _sig,
        })
    }

    pub fn as_public(&self) -> PublicContext {
        PublicContext::new(self.encryption_keys.0.clone(), self.signing_keys.0.clone())
    }

    pub fn encrypt(
        &self,
        target: PublicContext,
        data: impl AsRef<[u8]>,
    ) -> crate::Result<CryptoPacket> {
        let (encrypted_key, clear_key) = self.kem.encapsulate(&target.encryption_key())?;
        let nonce = Aes256Gcm::generate_nonce(OsRng);
        let aes = Aes256Gcm::new_from_slice(clear_key.into_vec().as_slice())?;
        let body = aes.encrypt(&nonce, data.as_ref())?;
        let signature = self.sig.sign(body.as_slice(), &self.signing_keys.1)?;

        Ok(CryptoPacket {
            origin: target.clone(),
            nonce: *nonce.as_ref(),
            key: encrypted_key,
            body,
            signature,
        })
    }

    pub fn decrypt(&self, packet: CryptoPacket) -> crate::Result<Vec<u8>> {
        self.sig.verify(
            &packet.body,
            &packet.signature,
            &packet.origin.signing_key(),
        )?;
        let shared_key = self.kem.decapsulate(&self.encryption_keys.1, &packet.key)?;
        let aes = Aes256Gcm::new_from_slice(&shared_key.into_vec())?;
        let nonce = GenericArray::from(packet.nonce);
        let decrypted = aes.decrypt(&nonce, &*packet.body)?;
        Ok(decrypted)
    }

    pub fn encrypt_object<T: Serialize>(
        &self,
        target: PublicContext,
        data: T,
    ) -> crate::Result<CryptoPacket> {
        let encoded = rmp_serde::to_vec(&data)?;
        self.encrypt(target, encoded)
    }

    pub fn decrypt_object<T: DeserializeOwned>(&self, packet: CryptoPacket) -> crate::Result<T> {
        let decrypted = self.decrypt(packet)?;
        Ok(rmp_serde::from_slice::<T>(&decrypted)?)
    }
}
