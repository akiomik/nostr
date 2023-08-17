// Copyright (c) 2022-2023 Yuki Kishimoto
// Distributed under the MIT software license

pub enum Kind {
    MetadataK,
    TextNote,
    RecommendRelay,
    ContactList,
    EncryptedDirectMessage,
    EventDeletion,
    Repost,
    Reaction,
    BadgeAward,
    ChannelCreation,
    ChannelMetadata,
    ChannelMessage,
    ChannelHideMessage,
    ChannelMuteUser,
    PublicChatReserved45,
    PublicChatReserved46,
    PublicChatReserved47,
    PublicChatReserved48,
    PublicChatReserved49,
    WalletConnectInfo,
    Reporting,
    ZapRequest,
    ZapReceipt,
    MuteList,
    PinList,
    RelayList,
    Authentication,
    WalletConnectRequest,
    WalletConnectResponse,
    NostrConnect,
    CategorizedPeopleList,
    CategorizedBookmarkList,
    LiveEvent,
    LiveEventMessage,
    ProfileBadges,
    BadgeDefinition,
    LongFormTextNote,
    ApplicationSpecificData,
    FileMetadataK,
    HttpAuth,
    Regular { kind: u16 },
    Replaceable { kind: u16 },
    Ephemeral { kind: u16 },
    ParameterizedReplaceable { kind: u16 },
    Custom { kind: u64 },
}

impl From<nostr::Kind> for Kind {
    fn from(value: nostr::Kind) -> Self {
        match value {
            nostr::Kind::Metadata => Self::MetadataK,
            nostr::Kind::TextNote => Self::TextNote,
            nostr::Kind::RecommendRelay => Self::RecommendRelay,
            nostr::Kind::ContactList => Self::ContactList,
            nostr::Kind::EncryptedDirectMessage => Self::EncryptedDirectMessage,
            nostr::Kind::EventDeletion => Self::EventDeletion,
            nostr::Kind::Repost => Self::Repost,
            nostr::Kind::Reaction => Self::Reaction,
            nostr::Kind::BadgeAward => Self::BadgeAward,
            nostr::Kind::ChannelCreation => Self::ChannelCreation,
            nostr::Kind::ChannelMetadata => Self::ChannelMetadata,
            nostr::Kind::ChannelMessage => Self::ChannelMessage,
            nostr::Kind::ChannelHideMessage => Self::ChannelHideMessage,
            nostr::Kind::ChannelMuteUser => Self::ChannelMuteUser,
            nostr::Kind::PublicChatReserved45 => Self::PublicChatReserved45,
            nostr::Kind::PublicChatReserved46 => Self::PublicChatReserved46,
            nostr::Kind::PublicChatReserved47 => Self::PublicChatReserved47,
            nostr::Kind::PublicChatReserved48 => Self::PublicChatReserved48,
            nostr::Kind::PublicChatReserved49 => Self::PublicChatReserved49,
            nostr::Kind::WalletConnectInfo => Self::WalletConnectInfo,
            nostr::Kind::Reporting => Self::Reporting,
            nostr::Kind::ZapRequest => Self::ZapRequest,
            #[allow(deprecated)]
            nostr::Kind::ZapReceipt | nostr::Kind::Zap => Self::ZapReceipt,
            nostr::Kind::MuteList => Self::MuteList,
            nostr::Kind::PinList => Self::PinList,
            nostr::Kind::RelayList => Self::RelayList,
            nostr::Kind::Authentication => Self::Authentication,
            nostr::Kind::WalletConnectRequest => Self::WalletConnectRequest,
            nostr::Kind::WalletConnectResponse => Self::WalletConnectResponse,
            nostr::Kind::NostrConnect => Self::NostrConnect,
            nostr::Kind::CategorizedPeopleList => Self::CategorizedPeopleList,
            nostr::Kind::CategorizedBookmarkList => Self::CategorizedBookmarkList,
            nostr::Kind::LiveEvent => Self::LiveEvent,
            nostr::Kind::LiveEventMessage => Self::LiveEventMessage,
            nostr::Kind::ProfileBadges => Self::ProfileBadges,
            nostr::Kind::BadgeDefinition => Self::BadgeDefinition,
            nostr::Kind::LongFormTextNote => Self::LongFormTextNote,
            nostr::Kind::ApplicationSpecificData => Self::ApplicationSpecificData,
            nostr::Kind::FileMetadata => Self::FileMetadataK,
            nostr::Kind::HttpAuth => Self::HttpAuth,
            nostr::Kind::Regular(u) => Self::Regular { kind: u },
            nostr::Kind::Replaceable(u) => Self::Replaceable { kind: u },
            nostr::Kind::Ephemeral(u) => Self::Ephemeral { kind: u },
            nostr::Kind::ParameterizedReplaceable(u) => Self::ParameterizedReplaceable { kind: u },
            nostr::Kind::Custom(u) => Self::Custom { kind: u },
        }
    }
}

impl From<Kind> for nostr::Kind {
    fn from(value: Kind) -> Self {
        match value {
            Kind::MetadataK => Self::Metadata,
            Kind::TextNote => Self::TextNote,
            Kind::RecommendRelay => Self::RecommendRelay,
            Kind::ContactList => Self::ContactList,
            Kind::EncryptedDirectMessage => Self::EncryptedDirectMessage,
            Kind::EventDeletion => Self::EventDeletion,
            Kind::Repost => Self::Repost,
            Kind::Reaction => Self::Reaction,
            Kind::BadgeAward => Self::BadgeAward,
            Kind::ChannelCreation => Self::ChannelCreation,
            Kind::ChannelMetadata => Self::ChannelMetadata,
            Kind::ChannelMessage => Self::ChannelMessage,
            Kind::ChannelHideMessage => Self::ChannelHideMessage,
            Kind::ChannelMuteUser => Self::ChannelMuteUser,
            Kind::PublicChatReserved45 => Self::PublicChatReserved45,
            Kind::PublicChatReserved46 => Self::PublicChatReserved46,
            Kind::PublicChatReserved47 => Self::PublicChatReserved47,
            Kind::PublicChatReserved48 => Self::PublicChatReserved48,
            Kind::PublicChatReserved49 => Self::PublicChatReserved49,
            Kind::WalletConnectInfo => Self::WalletConnectInfo,
            Kind::Reporting => Self::Reporting,
            Kind::ZapRequest => Self::ZapRequest,
            Kind::ZapReceipt => Self::ZapReceipt,
            Kind::MuteList => Self::MuteList,
            Kind::PinList => Self::PinList,
            Kind::RelayList => Self::RelayList,
            Kind::Authentication => Self::Authentication,
            Kind::WalletConnectRequest => Self::WalletConnectRequest,
            Kind::WalletConnectResponse => Self::WalletConnectResponse,
            Kind::NostrConnect => Self::NostrConnect,
            Kind::CategorizedPeopleList => Self::CategorizedPeopleList,
            Kind::CategorizedBookmarkList => Self::CategorizedBookmarkList,
            Kind::LiveEvent => Self::LiveEvent,
            Kind::LiveEventMessage => Self::LiveEventMessage,
            Kind::ProfileBadges => Self::ProfileBadges,
            Kind::BadgeDefinition => Self::BadgeDefinition,
            Kind::LongFormTextNote => Self::LongFormTextNote,
            Kind::ApplicationSpecificData => Self::ApplicationSpecificData,
            Kind::FileMetadataK => Self::FileMetadata,
            Kind::HttpAuth => Self::HttpAuth,
            Kind::Regular { kind } => Self::Regular(kind),
            Kind::Replaceable { kind } => Self::Replaceable(kind),
            Kind::Ephemeral { kind } => Self::Ephemeral(kind),
            Kind::ParameterizedReplaceable { kind } => Self::ParameterizedReplaceable(kind),
            Kind::Custom { kind } => Self::Custom(kind),
        }
    }
}
