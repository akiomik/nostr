// Copyright (c) 2022-2023 Yuki Kishimoto
// Distributed under the MIT software license

//! NIP59
//!
//! <https://github.com/nostr-protocol/nips/blob/master/59.md>

use core::fmt;

use secp256k1::{SecretKey, XOnlyPublicKey};

use super::nip44;
use crate::event::unsigned::{self, UnsignedEvent};
use crate::event::{self, Event};
use crate::key::{self, Keys};
use crate::{Kind, Tag};

/// NIP59 error
#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    /// Key error
    Key(key::Error),
    /// Event error
    Event(event::Error),
    /// Unsigned event error
    Unsigned(unsigned::Error),
    /// NIP44 error
    NIP44(nip44::Error),
    /// Not Gift Wrap event
    NotGiftWrap,
    /// Receiver Public Key
    ReceiverPubkeyNotFound,
}

impl std::error::Error for Error {}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Key(e) => write!(f, "Key: {e}"),
            Self::Event(e) => write!(f, "Event: {e}"),
            Self::Unsigned(e) => write!(f, "Unsigned event: {e}"),
            Self::NIP44(e) => write!(f, "NIP44: {e}"),
            Self::NotGiftWrap => write!(f, "Not Gift Wrap event"),
            Self::ReceiverPubkeyNotFound => write!(f, "Receiver Public Key not found"),
        }
    }
}

impl From<key::Error> for Error {
    fn from(e: key::Error) -> Self {
        Self::Key(e)
    }
}

impl From<event::Error> for Error {
    fn from(e: event::Error) -> Self {
        Self::Event(e)
    }
}

impl From<unsigned::Error> for Error {
    fn from(e: unsigned::Error) -> Self {
        Self::Unsigned(e)
    }
}

impl From<nip44::Error> for Error {
    fn from(e: nip44::Error) -> Self {
        Self::NIP44(e)
    }
}

fn extract_first_public_key(event: &Event) -> Option<XOnlyPublicKey> {
    for tag in event.tags.iter() {
        if let Tag::PubKey(public_key, ..) = tag {
            return Some(*public_key);
        }
    }
    None
}

/// Extract `rumor` from Gift Wrap event
pub fn extract_rumor(keys: &Keys, gift_wrap: Event) -> Result<UnsignedEvent, Error> {
    if gift_wrap.kind != Kind::GiftWrap {
        return Err(Error::NotGiftWrap);
    }

    let secret_key: SecretKey = keys.secret_key()?;
    let receiver = extract_first_public_key(&gift_wrap).ok_or(Error::ReceiverPubkeyNotFound)?;

    let seal: String = nip44::decrypt(&secret_key, &receiver, gift_wrap.content)?;
    let seal: Event = Event::from_json(seal)?;

    let rumor: String = nip44::decrypt(&secret_key, &receiver, seal.content)?;
    let rumor: UnsignedEvent = UnsignedEvent::from_json(rumor)?;

    Ok(rumor)
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;
    use crate::EventBuilder;

    #[test]
    fn test_extract_rumor() {
        let keys = Keys::new(
            SecretKey::from_str("6b911fd37cdf5c81d4c0adb1ab7fa822ed253ab0ad9aa18d77257c88b29b718e")
                .unwrap(),
        );
        let receiver = XOnlyPublicKey::from_str(
            "32e1827635450ebb3c5a7d12c1f8e7b2b514439ac10a67eef3d9fd9c5c68e245",
        )
        .unwrap();

        // Compose Gift Wrap event
        let rumor: UnsignedEvent =
            EventBuilder::new_text_note("Test", &[]).to_unsigned_event(keys.public_key());
        let event: Event = EventBuilder::gift_wrap(&keys, &receiver, rumor.clone())
            .unwrap()
            .to_event(&keys)
            .unwrap();

        println!("{event:#?}");

        assert_eq!(extract_rumor(&keys, event).unwrap(), rumor);

        let event: Event = EventBuilder::new_text_note("", &[])
            .to_event(&keys)
            .unwrap();
        assert_eq!(extract_rumor(&keys, event).unwrap_err(), Error::NotGiftWrap);
    }
}
