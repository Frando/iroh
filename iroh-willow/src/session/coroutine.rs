use std::{
    cell::{RefCell, RefMut},
    rc::Rc,
};

use anyhow::anyhow;
use genawaiter::sync::Co;

use tracing::{debug, trace};

use crate::{
    proto::{
        grouping::ThreeDRange,
        keys::NamespaceId,
        wgps::{
            AreaOfInterestHandle, Fingerprint, LengthyEntry, LogicalChannel, Message,
            ReconciliationAnnounceEntries, ReconciliationSendEntry, ReconciliationSendFingerprint,
            ResourceHandle, SetupBindAreaOfInterest, StaticToken, StaticTokenHandle,
        },
        willow::AuthorisedEntry,
    },
    store::{actor::Interest, ReadonlyStore, SplitAction, Store, SyncConfig},
    util::channel::{ReadOutcome, Receiver, Sender, WriteOutcome},
};

use super::{Error, SessionInit, SessionState, SharedSessionState};

#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq)]
pub enum Yield {
    Pending(Readyness),
    StartReconciliation(Option<(AreaOfInterestHandle, AreaOfInterestHandle)>),
}
#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq)]
pub enum Readyness {
    Channel(LogicalChannel, Interest),
    Resource(ResourceHandle),
}

#[derive(derive_more::Debug)]
pub struct Coroutine<S: ReadonlyStore, W: Store> {
    pub store_snapshot: Rc<S>,
    pub store_writer: Rc<RefCell<W>>,
    pub channels: Channels,
    pub state: SharedSessionState,
    #[debug(skip)]
    pub co: Co<Yield, ()>,
}

#[derive(Debug, Clone)]
pub struct Channels {
    pub control_send: Sender<Message>,
    pub control_recv: Receiver<Message>,
    pub reconciliation_send: Sender<Message>,
    pub reconciliation_recv: Receiver<Message>,
}

impl Channels {
    pub fn close_all(&self) {
        self.control_send.close();
        self.control_recv.close();
        self.reconciliation_send.close();
        self.reconciliation_recv.close();
    }
    pub fn close_send(&self) {
        self.control_send.close();
        self.reconciliation_send.close();
    }
    pub fn sender(&self, channel: LogicalChannel) -> &Sender<Message> {
        match channel {
            LogicalChannel::Control => &self.control_send,
            LogicalChannel::Reconciliation => &self.reconciliation_send,
        }
    }
    pub fn receiver(&self, channel: LogicalChannel) -> &Receiver<Message> {
        match channel {
            LogicalChannel::Control => &self.control_recv,
            LogicalChannel::Reconciliation => &self.reconciliation_recv,
        }
    }
}

// Note that all async methods yield to the owner of the coroutine. They are not running in a tokio
// context. You may not perform regular async operations in them.
impl<S: ReadonlyStore, W: Store> Coroutine<S, W> {
    pub async fn run_reconciliation(
        mut self,
        start_with_aoi: Option<(AreaOfInterestHandle, AreaOfInterestHandle)>,
    ) -> Result<(), Error> {
        debug!(start = start_with_aoi.is_some(), "start reconciliation");

        // optionally initiate reconciliation with a first fingerprint. only alfie may do this.
        if let Some((our_handle, their_handle)) = start_with_aoi {
            self.start_reconciliation(our_handle, their_handle).await?;
        }

        while let Some(message) = self.recv(LogicalChannel::Reconciliation).await {
            let message = message?;
            trace!(%message, "recv");
            match message {
                Message::ReconciliationSendFingerprint(message) => {
                    self.on_send_fingerprint(message).await?
                }
                Message::ReconciliationAnnounceEntries(message) => {
                    self.on_announce_entries(message).await?
                }
                Message::ReconciliationSendEntry(message) => self.on_send_entry(message).await?,
                _ => return Err(Error::UnsupportedMessage),
            };

            if self.state_mut().reconciliation_is_complete() {
                self.channels.close_send();
            }
        }

        Ok(())
    }

    pub async fn run_control(mut self, init: SessionInit) -> Result<(), Error> {
        let reveal_message = self.state_mut().commitment_reveal()?;
        self.send_control(reveal_message).await?;

        let mut init = Some(init);
        while let Some(message) = self.recv(LogicalChannel::Control).await {
            let message = message?;
            match message {
                Message::CommitmentReveal(msg) => {
                    self.state_mut().on_commitment_reveal(msg)?;
                    let init = init
                        .take()
                        .ok_or_else(|| Error::InvalidMessageInCurrentState)?;
                    self.setup(init).await?;
                }
                Message::SetupBindReadCapability(msg) => {
                    self.state_mut().on_setup_bind_read_capability(msg)?;
                }
                Message::SetupBindStaticToken(msg) => {
                    self.state_mut().on_setup_bind_static_token(msg);
                }
                Message::SetupBindAreaOfInterest(msg) => {
                    let start = self.state_mut().on_setup_bind_area_of_interest(msg)?;
                    // if let Some(start) = st
                    self.co.yield_(Yield::StartReconciliation(start)).await;
                }
                Message::ControlFreeHandle(_msg) => {
                    // TODO: Free handles
                }
                _ => return Err(Error::UnsupportedMessage),
            }
        }

        Ok(())
    }

    async fn setup(&mut self, init: SessionInit) -> Result<(), Error> {
        debug!(?init, "init");
        for (capability, aois) in init.interests.into_iter() {
            if *capability.receiver() != init.user_secret_key.public_key() {
                return Err(Error::WrongSecretKeyForCapability);
            }

            // TODO: implement private area intersection
            let intersection_handle = 0.into();
            let (our_capability_handle, message) = self.state_mut().bind_and_sign_capability(
                &init.user_secret_key,
                intersection_handle,
                capability,
            )?;
            if let Some(message) = message {
                self.send_control(message).await?;
            }

            for area_of_interest in aois {
                // for area in areas_of_interest {
                let msg = SetupBindAreaOfInterest {
                    area_of_interest,
                    authorisation: our_capability_handle,
                };
                let (_our_handle, is_new) = self
                    .state_mut()
                    .our_resources
                    .areas_of_interest
                    // TODO: avoid clone
                    .bind_if_new(msg.clone());
                if is_new {
                    self.send_control(msg).await?;
                }
            }
        }
        Ok(())
    }

    async fn start_reconciliation(
        &mut self,
        our_handle: AreaOfInterestHandle,
        their_handle: AreaOfInterestHandle,
    ) -> Result<(), Error> {
        debug!("init reconciliation");
        let mut state = self.state_mut();
        let our_aoi = state.our_resources.areas_of_interest.try_get(&our_handle)?;
        let their_aoi = state
            .their_resources
            .areas_of_interest
            .try_get(&their_handle)?;

        let our_capability = state
            .our_resources
            .capabilities
            .try_get(&our_aoi.authorisation)?;
        let namespace: NamespaceId = our_capability.granted_namespace().into();

        let common_aoi = &our_aoi
            .area()
            .intersection(&their_aoi.area())
            .ok_or(Error::AreaOfInterestDoesNotOverlap)?;

        let range = common_aoi.into_range();
        state.reconciliation_started = true;
        drop(state);
        let fingerprint = self.store_snapshot.fingerprint(namespace, &range)?;
        self.send_fingerprint(range, fingerprint, our_handle, their_handle, None)
            .await?;
        Ok(())
    }

    async fn on_send_fingerprint(
        &mut self,
        message: ReconciliationSendFingerprint,
    ) -> Result<(), Error> {
        trace!("on_send_fingerprint start");
        let ReconciliationSendFingerprint {
            range,
            fingerprint: their_fingerprint,
            sender_handle: their_handle,
            receiver_handle: our_handle,
            is_final_reply_for_range,
        } = message;

        let namespace = {
            let mut state = self.state_mut();
            state.reconciliation_started = true;
            state.clear_pending_range_if_some(our_handle, is_final_reply_for_range)?;
            state.range_is_authorised(&range, &our_handle, &their_handle)?
        };

        let our_fingerprint = self.store_snapshot.fingerprint(namespace, &range)?;

        // case 1: fingerprint match.
        if our_fingerprint == their_fingerprint {
            let msg = ReconciliationAnnounceEntries {
                range: range.clone(),
                count: 0,
                want_response: false,
                will_sort: false,
                sender_handle: our_handle,
                receiver_handle: their_handle,
                is_final_reply_for_range: Some(range),
            };
            self.send_reconciliation(msg).await?;
        }
        // case 2: fingerprint is empty
        else if their_fingerprint.is_empty() {
            self.announce_and_send_entries(
                namespace,
                &range,
                our_handle,
                their_handle,
                true,
                Some(range.clone()),
                None,
            )
            .await?;
        }
        // case 3: fingerprint doesn't match and is non-empty
        else {
            // reply by splitting the range into parts unless it is very short
            self.split_range_and_send_parts(namespace, &range, our_handle, their_handle)
                .await?;
        }
        trace!("on_send_fingerprint done");
        Ok(())
    }
    async fn on_announce_entries(
        &mut self,
        message: ReconciliationAnnounceEntries,
    ) -> Result<(), Error> {
        trace!("on_announce_entries start");
        let ReconciliationAnnounceEntries {
            range,
            count,
            want_response,
            will_sort: _,
            sender_handle: their_handle,
            receiver_handle: our_handle,
            is_final_reply_for_range,
        } = message;

        let namespace = {
            let mut state = self.state_mut();
            state.clear_pending_range_if_some(our_handle, is_final_reply_for_range)?;
            if state.pending_entries.is_some() {
                return Err(Error::InvalidMessageInCurrentState);
            }
            let namespace = state.range_is_authorised(&range, &our_handle, &their_handle)?;
            if count != 0 {
                state.pending_entries = Some(count);
            }
            namespace
        };
        if want_response {
            self.announce_and_send_entries(
                namespace,
                &range,
                our_handle,
                their_handle,
                false,
                Some(range.clone()),
                None,
            )
            .await?;
        }
        trace!("on_announce_entries done");
        Ok(())
    }

    async fn on_send_entry(&mut self, message: ReconciliationSendEntry) -> Result<(), Error> {
        let static_token = self
            .get_static_token_eventually(message.static_token_handle)
            .await;

        self.state_mut().on_send_entry()?;

        let authorised_entry = AuthorisedEntry::try_from_parts(
            message.entry.entry,
            static_token,
            message.dynamic_token,
        )?;

        self.store_writer
            .borrow_mut()
            .ingest_entry(&authorised_entry)?;

        Ok(())
    }

    async fn get_static_token_eventually(&mut self, handle: StaticTokenHandle) -> StaticToken {
        loop {
            let state = self.state.borrow_mut();
            match state.their_resources.static_tokens.get(&handle) {
                Some(token) => break token.clone(),
                None => {
                    drop(state);
                    self.co
                        .yield_(Yield::Pending(Readyness::Resource(handle.into())))
                        .await
                }
            }
        }
    }

    async fn send_fingerprint(
        &mut self,
        range: ThreeDRange,
        fingerprint: Fingerprint,
        our_handle: AreaOfInterestHandle,
        their_handle: AreaOfInterestHandle,
        is_final_reply_for_range: Option<ThreeDRange>,
    ) -> anyhow::Result<()> {
        {
            let mut state = self.state_mut();
            state.pending_ranges.insert((our_handle, range.clone()));
        }
        let msg = ReconciliationSendFingerprint {
            range,
            fingerprint,
            sender_handle: our_handle,
            receiver_handle: their_handle,
            is_final_reply_for_range,
        };
        self.send_reconciliation(msg).await?;
        Ok(())
    }

    async fn announce_and_send_entries(
        &mut self,
        namespace: NamespaceId,
        range: &ThreeDRange,
        our_handle: AreaOfInterestHandle,
        their_handle: AreaOfInterestHandle,
        want_response: bool,
        is_final_reply_for_range: Option<ThreeDRange>,
        our_count: Option<u64>,
    ) -> Result<(), Error> {
        if want_response {
            let mut state = self.state_mut();
            state.pending_ranges.insert((our_handle, range.clone()));
        }
        let our_count = match our_count {
            Some(count) => count,
            None => self.store_snapshot.count(namespace, &range)?,
        };
        let msg = ReconciliationAnnounceEntries {
            range: range.clone(),
            count: our_count,
            want_response,
            will_sort: false, // todo: sorted?
            sender_handle: our_handle,
            receiver_handle: their_handle,
            is_final_reply_for_range,
        };
        self.send_reconciliation(msg).await?;
        for authorised_entry in self
            .store_snapshot
            .get_entries_with_authorisation(namespace, &range)
        {
            let authorised_entry = authorised_entry?;
            let (entry, token) = authorised_entry.into_parts();
            let (static_token, dynamic_token) = token.into_parts();
            // TODO: partial payloads
            let available = entry.payload_length;
            let (static_token_handle, static_token_bind_msg) = self
                .state
                .borrow_mut()
                .bind_our_static_token(static_token)?;
            if let Some(msg) = static_token_bind_msg {
                self.send_control(msg).await?;
            }
            let msg = ReconciliationSendEntry {
                entry: LengthyEntry::new(entry, available),
                static_token_handle,
                dynamic_token,
            };
            self.send_reconciliation(msg).await?;
        }
        Ok(())
    }

    async fn split_range_and_send_parts(
        &mut self,
        namespace: NamespaceId,
        range: &ThreeDRange,
        our_handle: AreaOfInterestHandle,
        their_handle: AreaOfInterestHandle,
    ) -> Result<(), Error> {
        // TODO: expose this config
        let config = SyncConfig::default();
        // clone to avoid borrow checker trouble
        let store_snapshot = Rc::clone(&self.store_snapshot);
        let mut iter = store_snapshot
            .split_range(namespace, &range, &config)?
            .peekable();
        while let Some(res) = iter.next() {
            let (subrange, action) = res?;
            let is_last = iter.peek().is_none();
            let is_final_reply = is_last.then(|| range.clone());
            match action {
                SplitAction::SendEntries(count) => {
                    self.announce_and_send_entries(
                        namespace,
                        &subrange,
                        our_handle,
                        their_handle,
                        true,
                        is_final_reply,
                        Some(count),
                    )
                    .await?;
                }
                SplitAction::SendFingerprint(fingerprint) => {
                    self.send_fingerprint(
                        subrange,
                        fingerprint,
                        our_handle,
                        their_handle,
                        is_final_reply,
                    )
                    .await?;
                }
            }
        }
        Ok(())
    }

    fn state_mut(&mut self) -> RefMut<SessionState> {
        self.state.borrow_mut()
    }

    async fn recv(&self, channel: LogicalChannel) -> Option<anyhow::Result<Message>> {
        let receiver = self.channels.receiver(channel);
        loop {
            match receiver.recv_message() {
                Err(err) => return Some(Err(err)),
                Ok(outcome) => match outcome {
                    ReadOutcome::Closed => {
                        debug!("recv: closed");
                        return None;
                    }
                    ReadOutcome::BufferEmpty => {
                        self.co
                            .yield_(Yield::Pending(Readyness::Channel(channel, Interest::Recv)))
                            .await;
                    }
                    ReadOutcome::Item(message) => {
                        debug!(ch=%channel.fmt_short(), %message, "recv");
                        return Some(Ok(message));
                    }
                },
            }
        }
    }

    async fn send_reconciliation(&self, msg: impl Into<Message>) -> anyhow::Result<()> {
        self.send(msg).await
    }

    async fn send_control(&self, msg: impl Into<Message>) -> anyhow::Result<()> {
        self.send(msg).await
    }

    async fn send(&self, message: impl Into<Message>) -> anyhow::Result<()> {
        let message: Message = message.into();
        let channel = message.logical_channel();
        // debug!(%message, ?channel, "send");
        let sender = self.channels.sender(channel);

        loop {
            match sender.send_message(&message)? {
                WriteOutcome::Closed => {
                    debug!("send: closed");
                    return Err(anyhow!("channel closed"));
                }
                WriteOutcome::Ok => {
                    debug!(ch=%channel.fmt_short(), msg=%message, "sent");
                    break Ok(());
                }
                WriteOutcome::BufferFull => {
                    debug!(msg=%message, ch=%channel.fmt_short(), "sent buf full, yield");
                    self.co
                        .yield_(Yield::Pending(Readyness::Channel(channel, Interest::Send)))
                        .await;
                }
            }
        }
    }
}