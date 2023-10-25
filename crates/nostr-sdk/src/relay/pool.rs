// Copyright (c) 2022-2023 Yuki Kishimoto
// Distributed under the MIT software license

//! Relay Pool

use std::collections::{HashMap, VecDeque};
#[cfg(not(target_arch = "wasm32"))]
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use async_utility::thread;
use nostr::message::MessageHandleError;
use nostr::{
    event, ClientMessage, Event, EventId, Filter, JsonUtil, MissingPartialEvent, PartialEvent,
    RawRelayMessage, RelayMessage, SubscriptionId, Timestamp, Url,
};
use thiserror::Error;
use tokio::sync::mpsc::{self, Receiver, Sender};
use tokio::sync::{broadcast, Mutex, RwLock};

use super::options::RelayPoolOptions;
use super::{
    Error as RelayError, FilterOptions, InternalSubscriptionId, Limits, Relay, RelayOptions,
    RelayRole, RelaySendOptions, RelayStatus,
};
use crate::util::TryIntoUrl;

/// [`RelayPool`] error
#[derive(Debug, Error)]
pub enum Error {
    /// Url parse error
    #[error("impossible to parse URL: {0}")]
    Url(#[from] nostr::url::ParseError),
    /// Relay error
    #[error(transparent)]
    Relay(#[from] RelayError),
    /// Event error
    #[error(transparent)]
    Event(#[from] event::Error),
    /// Partial Event error
    #[error(transparent)]
    PartialEvent(#[from] event::partial::Error),
    /// Message handler error
    #[error(transparent)]
    MessageHandler(#[from] MessageHandleError),
    /// Thread error
    #[error(transparent)]
    Thread(#[from] thread::Error),
    /// No relays
    #[error("no relays")]
    NoRelays,
    /// Msg not sent
    #[error("message not sent")]
    MsgNotSent,
    /// Msgs not sent
    #[error("messages not sent")]
    MsgsNotSent,
    /// Event not published
    #[error("event not published")]
    EventNotPublished(EventId),
    /// Events not published
    #[error("events not published")]
    EventsNotPublished,
    /// Relay not found
    #[error("relay not found")]
    RelayNotFound,
    /// Event expired
    #[error("event expired")]
    EventExpired,
}

/// Relay Pool Message
#[derive(Debug)]
pub enum RelayPoolMessage {
    /// Received new message
    ReceivedMsg {
        /// Relay url
        relay_url: Url,
        /// Relay message
        msg: RawRelayMessage,
    },
    /// Events sent
    BatchEvent(Vec<EventId>),
    /// Relay status changed
    RelayStatus {
        /// Relay url
        url: Url,
        /// Relay Status
        status: RelayStatus,
    },
    /// Stop
    Stop,
    /// Shutdown
    Shutdown,
}

/// Relay Pool Notification
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelayPoolNotification {
    /// Received an [`Event`]. Does not include events sent by this client.
    Event(Url, Event),
    /// Received a [`RelayMessage`]. Includes messages wrapping events that were sent by this client.
    Message(Url, RelayMessage),
    /// Relay status changed
    RelayStatus {
        /// Relay url
        url: Url,
        /// Relay Status
        status: RelayStatus,
    },
    /// Stop
    Stop,
    /// Shutdown
    Shutdown,
}

#[derive(Debug, Clone)]
struct RelayPoolTask {
    receiver: Arc<Mutex<Receiver<RelayPoolMessage>>>,
    notification_sender: broadcast::Sender<RelayPoolNotification>,
    events: Arc<Mutex<VecDeque<EventId>>>,
    running: Arc<AtomicBool>,
    max_seen_events: usize,
}

impl RelayPoolTask {
    pub fn new(
        pool_task_receiver: Receiver<RelayPoolMessage>,
        notification_sender: broadcast::Sender<RelayPoolNotification>,
        max_seen_events: usize,
    ) -> Self {
        Self {
            receiver: Arc::new(Mutex::new(pool_task_receiver)),
            events: Arc::new(Mutex::new(VecDeque::new())),
            notification_sender,
            running: Arc::new(AtomicBool::new(false)),
            max_seen_events,
        }
    }

    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    fn set_running_to(&self, value: bool) {
        let _ = self
            .running
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |_| Some(value));
    }

    pub async fn clear_already_seen_events(&self) {
        let mut events = self.events.lock().await;
        events.clear();
    }

    pub fn run(&self) {
        if self.is_running() {
            tracing::warn!("Relay Pool Task is already running!")
        } else {
            tracing::debug!("RelayPoolTask Thread Started");
            self.set_running_to(true);
            let this = self.clone();
            thread::spawn(async move {
                let mut receiver = this.receiver.lock().await;
                while let Some(msg) = receiver.recv().await {
                    match msg {
                        RelayPoolMessage::ReceivedMsg { relay_url, msg } => {
                            match this.handle_relay_message(msg).await {
                                Ok(msg) => {
                                    let _ = this.notification_sender.send(
                                        RelayPoolNotification::Message(
                                            relay_url.clone(),
                                            msg.clone(),
                                        ),
                                    );

                                    match msg {
                                        RelayMessage::Event { event, .. } => {
                                            // Check if event was already seen
                                            if this.add_event(event.id).await {
                                                let notification = RelayPoolNotification::Event(
                                                    relay_url,
                                                    event.as_ref().clone(),
                                                );
                                                let _ = this.notification_sender.send(notification);
                                            }
                                        }
                                        RelayMessage::Notice { message } => {
                                            tracing::warn!("Notice from {relay_url}: {message}")
                                        }
                                        _ => (),
                                    }
                                }
                                Err(e) => tracing::error!(
                                    "Impossible to handle relay message from {relay_url}: {e}"
                                ),
                            }
                        }
                        RelayPoolMessage::BatchEvent(ids) => {
                            this.add_events(ids).await;
                        }
                        RelayPoolMessage::RelayStatus { url, status } => {
                            let _ = this
                                .notification_sender
                                .send(RelayPoolNotification::RelayStatus { url, status });
                        }
                        RelayPoolMessage::Stop => {
                            tracing::debug!("Received stop msg");
                            this.set_running_to(false);
                            if let Err(e) =
                                this.notification_sender.send(RelayPoolNotification::Stop)
                            {
                                tracing::error!("Impossible to send STOP notification: {e}");
                            }
                            break;
                        }
                        RelayPoolMessage::Shutdown => {
                            tracing::debug!("Received shutdown msg");
                            this.set_running_to(false);
                            receiver.close();
                            if let Err(e) = this
                                .notification_sender
                                .send(RelayPoolNotification::Shutdown)
                            {
                                tracing::error!("Impossible to send SHUTDOWN notification: {}", e);
                            }
                            break;
                        }
                    }
                }

                tracing::debug!("Exited from RelayPoolTask thread");
            });
        }
    }

    async fn handle_relay_message(&self, msg: RawRelayMessage) -> Result<RelayMessage, Error> {
        match msg {
            RawRelayMessage::Event {
                subscription_id,
                event,
            } => {
                // Deserialize partial event (id, pubkey and sig)
                let partial_event: PartialEvent = PartialEvent::from_json(event.to_string())?;

                // Verify signature
                partial_event.verify_signature()?;

                // Deserialize missing event fields
                let missing: MissingPartialEvent =
                    MissingPartialEvent::from_json(event.to_string())?;

                // Compose full event
                let event: Event = partial_event.merge(missing);

                // Check if it's expired
                if event.is_expired() {
                    return Err(Error::EventExpired);
                }

                // Verify event ID
                event.verify_id()?;

                // Compose RelayMessage
                Ok(RelayMessage::Event {
                    subscription_id: SubscriptionId::new(subscription_id),
                    event: Box::new(event),
                })
            }
            m => Ok(RelayMessage::try_from(m)?),
        }
    }

    async fn add_event(&self, event_id: EventId) -> bool {
        let mut events = self.events.lock().await;
        if events.contains(&event_id) {
            false
        } else {
            while events.len() >= self.max_seen_events {
                events.pop_front();
            }
            events.push_back(event_id);
            true
        }
    }

    async fn add_events(&self, ids: Vec<EventId>) {
        if !ids.is_empty() {
            let mut events = self.events.lock().await;
            for event_id in ids.into_iter() {
                if !events.contains(&event_id) {
                    while events.len() >= self.max_seen_events {
                        events.pop_front();
                    }
                    events.push_back(event_id);
                }
            }
        }
    }
}

/// Relay Pool
#[derive(Debug, Clone)]
pub struct RelayPool {
    relays: Arc<RwLock<HashMap<Url, Relay>>>,
    pool_task_sender: Sender<RelayPoolMessage>,
    notification_sender: broadcast::Sender<RelayPoolNotification>,
    filters: Arc<RwLock<Vec<Filter>>>,
    pool_task: RelayPoolTask,
    opts: RelayPoolOptions,
    dropped: Arc<AtomicBool>,
}

impl Drop for RelayPool {
    fn drop(&mut self) {
        if self.opts.shutdown_on_drop {
            if self.dropped.load(Ordering::SeqCst) {
                tracing::warn!("Relay Pool already dropped");
            } else {
                tracing::debug!("Dropping the Relay Pool...");
                let _ = self
                    .dropped
                    .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |_| Some(true));
                let pool = self.clone();
                thread::spawn(async move {
                    pool.shutdown()
                        .await
                        .expect("Impossible to drop the relay pool")
                });
            }
        }
    }
}

impl RelayPool {
    /// Create new `RelayPool`
    pub fn new(opts: RelayPoolOptions) -> Self {
        let (notification_sender, _) = broadcast::channel(opts.notification_channel_size);
        let (pool_task_sender, pool_task_receiver) = mpsc::channel(opts.task_channel_size);

        let relay_pool_task = RelayPoolTask::new(
            pool_task_receiver,
            notification_sender.clone(),
            opts.task_max_seen_events,
        );

        let pool = Self {
            relays: Arc::new(RwLock::new(HashMap::new())),
            pool_task_sender,
            notification_sender,
            filters: Arc::new(RwLock::new(Vec::new())),
            pool_task: relay_pool_task,
            opts,
            dropped: Arc::new(AtomicBool::new(false)),
        };

        pool.start();

        pool
    }

    /// Start [`RelayPoolTask`]
    pub fn start(&self) {
        self.pool_task.run();
    }

    /// Stop
    pub async fn stop(&self) -> Result<(), Error> {
        let relays = self.relays().await;
        for relay in relays.values() {
            relay.stop().await?;
        }
        if let Err(e) = self.pool_task_sender.try_send(RelayPoolMessage::Stop) {
            tracing::error!("Impossible to send STOP message: {e}");
        }
        Ok(())
    }

    /// Check if [`RelayPool`] is running
    pub fn is_running(&self) -> bool {
        self.pool_task.is_running()
    }

    /// Completely shutdown pool
    pub async fn shutdown(self) -> Result<(), Error> {
        self.disconnect().await?;
        thread::spawn(async move {
            thread::sleep(Duration::from_secs(3)).await;
            let _ = self.pool_task_sender.send(RelayPoolMessage::Shutdown).await;
        });
        Ok(())
    }

    /// Clear already seen events
    pub async fn clear_already_seen_events(&self) {
        self.pool_task.clear_already_seen_events().await;
    }

    /// Get new notification listener
    pub fn notifications(&self) -> broadcast::Receiver<RelayPoolNotification> {
        self.notification_sender.subscribe()
    }

    /// Get all relays
    pub async fn relays(&self) -> HashMap<Url, Relay> {
        let relays = self.relays.read().await;
        relays.clone()
    }

    /// Get relays by role
    pub async fn relays_by_role(&self, role: RelayRole) -> HashMap<Url, Relay> {
        let relays = self.relays.read().await;
        let mut map = HashMap::new();
        for (url, relay) in relays.iter() {
            if relay.role().await == role {
                map.insert(url.clone(), relay.clone());
            }
        }
        map
    }

    /// Get [`Relay`]
    pub async fn relay<U>(&self, url: U) -> Result<Relay, Error>
    where
        U: TryIntoUrl,
        Error: From<<U as TryIntoUrl>::Err>,
    {
        let url: Url = url.try_into_url()?;
        let relays = self.relays.read().await;
        relays.get(&url).cloned().ok_or(Error::RelayNotFound)
    }

    /// Get subscription filters
    pub async fn subscription_filters(&self) -> Vec<Filter> {
        self.filters.read().await.clone()
    }

    /// Update subscription filters
    async fn update_subscription_filters(&self, filters: Vec<Filter>) {
        let mut f = self.filters.write().await;
        *f = filters;
    }

    /// Add new relay
    #[cfg(not(target_arch = "wasm32"))]
    pub async fn add_relay<U>(
        &self,
        url: U,
        proxy: Option<SocketAddr>,
        role: RelayRole,
        opts: RelayOptions,
    ) -> Result<bool, Error>
    where
        U: TryIntoUrl,
        Error: From<<U as TryIntoUrl>::Err>,
    {
        let url: Url = url.try_into_url()?;
        let mut relays = self.relays.write().await;
        if !relays.contains_key(&url) {
            let relay = Relay::new(
                url,
                role,
                self.pool_task_sender.clone(),
                self.notification_sender.clone(),
                proxy,
                opts,
                Limits::default(),
            );
            relays.insert(relay.url(), relay);
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Add new relay
    #[cfg(target_arch = "wasm32")]
    pub async fn add_relay<U>(
        &self,
        url: U,
        role: RelayRole,
        opts: RelayOptions,
    ) -> Result<bool, Error>
    where
        U: TryIntoUrl,
        Error: From<<U as TryIntoUrl>::Err>,
    {
        let url: Url = url.try_into_url()?;
        let mut relays = self.relays.write().await;
        if !relays.contains_key(&url) {
            let relay = Relay::new(
                url,
                role,
                self.pool_task_sender.clone(),
                self.notification_sender.clone(),
                opts,
                Limits::default(),
            );
            relays.insert(relay.url(), relay);
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Disconnect and remove relay
    pub async fn remove_relay<U>(&self, url: U) -> Result<(), Error>
    where
        U: TryIntoUrl,
        Error: From<<U as TryIntoUrl>::Err>,
    {
        let url: Url = url.try_into_url()?;
        let mut relays = self.relays.write().await;
        if let Some(relay) = relays.remove(&url) {
            self.disconnect_relay(&relay).await?;
        }
        Ok(())
    }

    async fn set_events_as_sent(&self, ids: Vec<EventId>) {
        if let Err(e) = self
            .pool_task_sender
            .send(RelayPoolMessage::BatchEvent(ids))
            .await
        {
            tracing::error!("{e}");
        };
    }

    /// Send client message
    pub async fn send_msg(
        &self,
        msg: ClientMessage,
        roles: &[RelayRole],
        wait: Option<Duration>,
    ) -> Result<(), Error> {
        let relays: HashMap<Url, Relay> = self.relays().await;

        if relays.is_empty() {
            return Err(Error::NoRelays);
        }

        if let ClientMessage::Event(event) = &msg {
            self.set_events_as_sent(vec![event.id]).await;
        }

        let sent_to_at_least_one_relay: Arc<AtomicBool> = Arc::new(AtomicBool::new(false));
        let mut handles = Vec::new();

        for (url, relay) in relays.into_iter() {
            if roles.contains(&relay.role().await) {
                let msg: ClientMessage = msg.clone();
                let sent: Arc<AtomicBool> = sent_to_at_least_one_relay.clone();
                let handle = thread::spawn(async move {
                    match relay.send_msg(msg, wait).await {
                        Ok(_) => {
                            let _ = sent
                                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |_| Some(true));
                        }
                        Err(e) => tracing::error!("Impossible to send msg to {url}: {e}"),
                    }
                });
                handles.push(handle);
            }
        }

        for handle in handles.into_iter().flatten() {
            handle.join().await?;
        }

        if !sent_to_at_least_one_relay.load(Ordering::SeqCst) {
            return Err(Error::MsgNotSent);
        }

        Ok(())
    }

    /// Send multiple client messages at once
    pub async fn batch_msg(
        &self,
        msgs: Vec<ClientMessage>,
        roles: &[RelayRole],
        wait: Option<Duration>,
    ) -> Result<(), Error> {
        let relays: HashMap<Url, Relay> = self.relays().await;

        if relays.is_empty() {
            return Err(Error::NoRelays);
        }

        let ids: Vec<EventId> = msgs
            .iter()
            .filter_map(|msg| {
                if let ClientMessage::Event(event) = msg {
                    Some(event.id)
                } else {
                    None
                }
            })
            .collect();
        self.set_events_as_sent(ids).await;

        let sent_to_at_least_one_relay: Arc<AtomicBool> = Arc::new(AtomicBool::new(false));
        let mut handles = Vec::new();

        for (url, relay) in relays.into_iter() {
            if roles.contains(&relay.role().await) {
                let len: usize = msgs.len();
                let msgs: Vec<ClientMessage> = msgs.clone();
                let sent: Arc<AtomicBool> = sent_to_at_least_one_relay.clone();
                let handle = thread::spawn(async move {
                    match relay.batch_msg(msgs, wait).await {
                        Ok(_) => {
                            let _ = sent
                                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |_| Some(true));
                        }
                        Err(e) => {
                            tracing::error!("Impossible to send {len} messages to {url}: {e}")
                        }
                    }
                });
                handles.push(handle);
            }
        }

        for handle in handles.into_iter().flatten() {
            handle.join().await?;
        }

        if !sent_to_at_least_one_relay.load(Ordering::SeqCst) {
            return Err(Error::MsgNotSent);
        }

        Ok(())
    }

    /// Send client message to a single relay
    pub async fn send_msg_to<U>(
        &self,
        url: U,
        msg: ClientMessage,
        wait: Option<Duration>,
    ) -> Result<(), Error>
    where
        U: TryIntoUrl,
        Error: From<<U as TryIntoUrl>::Err>,
    {
        let relay: Relay = self.relay(url).await?;

        if let ClientMessage::Event(event) = &msg {
            self.set_events_as_sent(vec![event.id]).await;
        }

        Ok(relay.send_msg(msg, wait).await?)
    }

    /// Send event and wait for `OK` relay msg
    pub async fn send_event(
        &self,
        event: Event,
        roles: &[RelayRole],
        opts: RelaySendOptions,
    ) -> Result<EventId, Error> {
        let relays: HashMap<Url, Relay> = self.relays().await;

        if relays.is_empty() {
            return Err(Error::NoRelays);
        }

        self.set_events_as_sent(vec![event.id]).await;

        let sent_to_at_least_one_relay: Arc<AtomicBool> = Arc::new(AtomicBool::new(false));
        let mut handles = Vec::new();

        let event_id: EventId = event.id;

        for (url, relay) in relays.into_iter() {
            if roles.contains(&relay.role().await) {
                let event: Event = event.clone();
                let sent: Arc<AtomicBool> = sent_to_at_least_one_relay.clone();
                let handle = thread::spawn(async move {
                    match relay.send_event(event, opts).await {
                        Ok(_) => {
                            let _ = sent
                                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |_| Some(true));
                        }
                        Err(e) => tracing::error!("Impossible to send event to {url}: {e}"),
                    }
                });
                handles.push(handle);
            }
        }

        for handle in handles.into_iter().flatten() {
            handle.join().await?;
        }

        if !sent_to_at_least_one_relay.load(Ordering::SeqCst) {
            return Err(Error::EventNotPublished(event_id));
        }

        Ok(event_id)
    }

    /// Send multiple [`Event`] at once
    pub async fn batch_event(
        &self,
        events: Vec<Event>,
        roles: &[RelayRole],
        opts: RelaySendOptions,
    ) -> Result<(), Error> {
        let relays: HashMap<Url, Relay> = self.relays().await;

        if relays.is_empty() {
            return Err(Error::NoRelays);
        }

        let ids: Vec<EventId> = events.iter().map(|e| e.id).collect();
        self.set_events_as_sent(ids).await;

        let sent_to_at_least_one_relay: Arc<AtomicBool> = Arc::new(AtomicBool::new(false));
        let mut handles = Vec::new();

        for (url, relay) in relays.into_iter() {
            if roles.contains(&relay.role().await) {
                let len: usize = events.len();
                let events: Vec<Event> = events.clone();
                let sent: Arc<AtomicBool> = sent_to_at_least_one_relay.clone();
                let handle = thread::spawn(async move {
                    match relay.batch_event(events, opts).await {
                        Ok(_) => {
                            let _ = sent
                                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |_| Some(true));
                        }
                        Err(e) => tracing::error!("Impossible to send {len} events to {url}: {e}"),
                    }
                });
                handles.push(handle);
            }
        }

        for handle in handles.into_iter().flatten() {
            handle.join().await?;
        }

        if !sent_to_at_least_one_relay.load(Ordering::SeqCst) {
            return Err(Error::EventsNotPublished);
        }

        Ok(())
    }

    /// Send event to a single relay
    pub async fn send_event_to<U>(
        &self,
        url: U,
        event: Event,
        opts: RelaySendOptions,
    ) -> Result<EventId, Error>
    where
        U: TryIntoUrl,
        Error: From<<U as TryIntoUrl>::Err>,
    {
        let relay: Relay = self.relay(url).await?;
        self.set_events_as_sent(vec![event.id]).await;
        Ok(relay.send_event(event, opts).await?)
    }

    /// Subscribe to filters
    pub async fn subscribe(&self, filters: Vec<Filter>, wait: Option<Duration>) {
        let relays: HashMap<Url, Relay> = self.relays().await;
        self.update_subscription_filters(filters.clone()).await;
        for relay in relays.values() {
            if let Err(e) = relay
                .subscribe_with_internal_id(InternalSubscriptionId::Pool, filters.clone(), wait)
                .await
            {
                tracing::error!("{e}");
            }
        }
    }

    /// Unsubscribe from filters
    pub async fn unsubscribe(&self, wait: Option<Duration>) {
        let relays = self.relays().await;
        for relay in relays.values() {
            if let Err(e) = relay
                .unsubscribe_with_internal_id(InternalSubscriptionId::Pool, wait)
                .await
            {
                tracing::error!("{e}");
            }
        }
    }

    /// Get events of filters
    pub async fn get_events_of(
        &self,
        filters: Vec<Filter>,
        timeout: Duration,
        opts: FilterOptions,
    ) -> Result<Vec<Event>, Error> {
        let events: Arc<Mutex<Vec<Event>>> = Arc::new(Mutex::new(Vec::new()));
        let mut handles = Vec::new();
        let relays = self.relays().await;
        for (url, relay) in relays.into_iter() {
            let filters = filters.clone();
            let events = events.clone();
            let handle = thread::spawn(async move {
                if let Err(e) = relay
                    .get_events_of_with_callback(filters, timeout, opts, |event| async {
                        events.lock().await.push(event);
                    })
                    .await
                {
                    tracing::error!("Failed to get events from {url}: {e}");
                }
            });
            handles.push(handle);
        }

        for handle in handles.into_iter().flatten() {
            handle.join().await?;
        }

        Ok(events.lock_owned().await.clone())
    }

    /// Request events of filter. All events will be sent to notification listener
    /// until the EOSE "end of stored events" message is received from the relay.
    pub async fn req_events_of(
        &self,
        filters: Vec<Filter>,
        timeout: Duration,
        opts: FilterOptions,
    ) {
        let relays = self.relays().await;
        for relay in relays.values() {
            relay.req_events_of(filters.clone(), timeout, opts);
        }
    }

    /// Connect to all added relays and keep connection alive
    pub async fn connect(&self, wait_for_connection: bool) {
        let relays: HashMap<Url, Relay> = self.relays().await;

        if wait_for_connection {
            let mut handles = Vec::new();

            for relay in relays.into_values() {
                let pool = self.clone();
                let handle = thread::spawn(async move {
                    pool.connect_relay(&relay, wait_for_connection).await;
                });
                handles.push(handle);
            }

            for handle in handles.into_iter().flatten() {
                let _ = handle.join().await;
            }
        } else {
            for relay in relays.values() {
                self.connect_relay(relay, wait_for_connection).await;
            }
        }
    }

    /// Disconnect from all relays
    pub async fn disconnect(&self) -> Result<(), Error> {
        let relays = self.relays().await;
        for relay in relays.values() {
            self.disconnect_relay(relay).await?;
        }
        Ok(())
    }

    /// Connect to relay
    pub async fn connect_relay(&self, relay: &Relay, wait_for_connection: bool) {
        let filters: Vec<Filter> = self.subscription_filters().await;
        relay
            .update_subscription_filters(InternalSubscriptionId::Pool, filters)
            .await;
        relay.connect(wait_for_connection).await;
    }

    /// Disconnect from relay
    pub async fn disconnect_relay(&self, relay: &Relay) -> Result<(), Error> {
        relay.terminate().await?;
        Ok(())
    }

    /// Negentropy reconciliation
    pub async fn reconcilie(
        &self,
        filter: Filter,
        my_items: Vec<(EventId, Timestamp)>,
        timeout: Duration,
    ) -> Result<(), Error> {
        let mut handles = Vec::new();
        let relays = self.relays().await;
        for (url, relay) in relays.into_iter() {
            let filter = filter.clone();
            let my_items = my_items.clone();
            let handle = thread::spawn(async move {
                if let Err(e) = relay.reconcilie(filter, my_items, timeout).await {
                    tracing::error!("Failed to get reconcilie with {url}: {e}");
                }
            });
            handles.push(handle);
        }

        for handle in handles.into_iter().flatten() {
            handle.join().await?;
        }

        Ok(())
    }
}
