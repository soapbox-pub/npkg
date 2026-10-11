//! The gateway's OpenPGP key, which signs every repository's metadata.
//!
//! apt and dnf check signatures with gpg (or Sequoia), not Nostr: they can't
//! check an author's events themselves. The gateway checks those, and vouches
//! for what it built from them with this key. One Ed25519 key, primary only,
//! certifying and signing: everything that verifies repositories today reads
//! Ed25519, back to RHEL 8's and Ubuntu 20.04's gpg 2.2.

use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use anyhow::Context;
use pgp::composed::{
    ArmorOptions, CleartextSignedMessage, Deserializable, DetachedSignature, EncryptionCaps, KeyType, SecretKeyParamsBuilder,
    SignedPublicKey, SignedSecretKey,
};
use pgp::crypto::hash::HashAlgorithm;
use pgp::ser::Serialize;
use pgp::types::{KeyDetails, Password};

pub struct Signer {
    key: SignedSecretKey,
    public: String,
    /// The public key in binary, which Flatpak's `GPGKey=` wants in base64.
    public_binary: Vec<u8>,
}

impl Signer {
    pub fn load(path: &Path) -> anyhow::Result<Signer> {
        let armored = std::fs::read_to_string(path)
            .with_context(|| format!("Couldn't read the signing key at {}. Make one with `npkg-gateway keygen`.", path.display()))?;
        let (key, _) = SignedSecretKey::from_string(&armored).context("The signing key isn't an armored OpenPGP secret key.")?;
        key.verify_bindings().context("The signing key's self-signatures don't verify.")?;
        let public_key = SignedPublicKey::from(key.clone());
        let public = public_key.to_armored_string(ArmorOptions::default())?;
        let public_binary = public_key.to_bytes()?;
        Ok(Signer { key, public, public_binary })
    }

    /// Make a key and write it to `path`, which must not exist yet: a
    /// repository's users have the old key, so replacing it is never casual.
    pub fn generate(path: &Path, user_id: &str) -> anyhow::Result<Signer> {
        let params = SecretKeyParamsBuilder::default()
            .key_type(KeyType::Ed25519Legacy)
            .can_certify(true)
            .can_sign(true)
            .can_encrypt(EncryptionCaps::None)
            .primary_user_id(user_id.into())
            .build()?;
        let key = params.generate(rand::thread_rng())?;
        let armored = key.to_armored_string(ArmorOptions::default())?;

        let mut file = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(path).with_context(|| {
            format!("Couldn't create {}. If a key is already there, it's the one users trust: keep it.", path.display())
        })?;
        file.write_all(armored.as_bytes())?;
        Signer::load(path)
    }

    /// The public key, armored.
    pub fn public_key(&self) -> &str {
        &self.public
    }

    pub fn public_key_binary(&self) -> &[u8] {
        &self.public_binary
    }

    pub fn fingerprint(&self) -> String {
        self.key.fingerprint().to_string()
    }

    /// `text`, as a cleartext-signed message: an InRelease file.
    pub fn sign_cleartext(&self, text: &str) -> anyhow::Result<String> {
        let message = CleartextSignedMessage::sign(rand::thread_rng(), text, &self.key.primary_key, &Password::empty())?;
        Ok(message.to_armored_string(ArmorOptions::default())?)
    }

    /// A detached signature over `data`, armored: Release.gpg, repomd.xml.asc.
    pub fn sign_detached(&self, data: &[u8]) -> anyhow::Result<String> {
        Ok(self.detached(data)?.to_armored_string(ArmorOptions::default())?)
    }

    /// A detached signature over `data`, in binary, as OSTree keeps them
    /// for commits and summaries.
    pub fn sign_binary(&self, data: &[u8]) -> anyhow::Result<Vec<u8>> {
        Ok(self.detached(data)?.to_bytes()?)
    }

    fn detached(&self, data: &[u8]) -> anyhow::Result<DetachedSignature> {
        Ok(DetachedSignature::sign_binary_data(rand::thread_rng(), &self.key.primary_key, &Password::empty(), HashAlgorithm::Sha256, data)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signs_what_verifies() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("key.asc");
        let signer = Signer::generate(&path, "test <test@example.com>").unwrap();
        assert!(Signer::generate(&path, "again").is_err(), "an existing key is never replaced");
        let signer2 = Signer::load(&path).unwrap();
        assert_eq!(signer.fingerprint(), signer2.fingerprint());

        let (public, _) = SignedPublicKey::from_string(signer.public_key()).unwrap();

        let text = "Origin: x\nSHA256:\n 00 1 main/binary-amd64/Packages\n";
        let (message, _) = CleartextSignedMessage::from_string(&signer.sign_cleartext(text).unwrap()).unwrap();
        message.verify(&public).unwrap();
        let armored = signer.sign_cleartext(text).unwrap();
        assert!(armored.contains(text) && !armored.contains('\r'), "{armored:?}");

        let (signature, _) = DetachedSignature::from_string(&signer.sign_detached(b"<repomd/>").unwrap()).unwrap();
        signature.verify(&public, b"<repomd/>").unwrap();
        assert!(signature.verify(&public, b"<repomd />").is_err());

        let signature = DetachedSignature::from_bytes(&signer.sign_binary(b"commit").unwrap()[..]).unwrap();
        signature.verify(&public, b"commit").unwrap();
        assert_eq!(SignedPublicKey::from_bytes(signer.public_key_binary()).unwrap(), public);
    }
}
