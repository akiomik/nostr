// Copyright (c) 2022-2023 Yuki Kishimoto
// Distributed under the MIT software license

use std::ops::Deref;
use std::sync::Arc;

use nostr::nips::nip59;

use crate::error::Result;
use crate::{Event, Keys, UnsignedEvent};

pub fn extract_rumor_from_gift_wrap(
    keys: Arc<Keys>,
    gift_wrap: Arc<Event>,
) -> Result<Arc<UnsignedEvent>> {
    Ok(Arc::new(
        nip59::extract_rumor(keys.as_ref().deref(), gift_wrap.as_ref().deref().clone())?.into(),
    ))
}
