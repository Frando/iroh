//! Path observation for a [`Connection`].
//!
//! A connection has one or more network paths to the remote endpoint. Two
//! APIs observe them:
//!
//! - [`Connection::paths`] returns a borrowed synchronous view of the
//!   currently-open paths, with live statistics.
//! - [`Connection::path_events`] returns a `'static` stream of
//!   [`PathEvent`]s. The subscription is registered at call time, so pairing
//!   it with a subsequent [`Connection::paths`] read yields a race-free
//!   "check, then wait" loop.
//!
//! Closed paths are not retained in [`Paths`]; their final statistics arrive
//! inline on [`PathEvent::Closed`]. Consumers that want per-path totals for
//! the lifetime of a connection should accumulate from events.
//!
//! # Internal structure
//!
//! - [`PathStoreMut`] is owned by the `RemoteStateActor` and holds the
//!   broadcast [`Sender`]. It is the only type that mutates state.
//! - [`PathStore`] is held by a [`Connection`]. It shares the state [`Arc`]
//!   with the mutable store and subscribes through a [`WeakSender`]. When
//!   the actor drops the mutable store, the weak sender cannot be upgraded
//!   and new [`PathEventStream`]s terminate immediately.
//!
//! [`Connection`]: crate::endpoint::Connection
//! [`Connection::paths`]: crate::endpoint::Connection::paths
//! [`Connection::path_events`]: crate::endpoint::Connection::path_events
//! [`Sender`]: broadcast::Sender
//! [`WeakSender`]: broadcast::WeakSender

use std::{
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use arc_swap::ArcSwap;
use iroh_base::TransportAddr;
use n0_future::time::Duration;
use noq::WeakPathHandle;
use noq_proto::PathId;
use smallvec::SmallVec;
use tokio::sync::broadcast;
use tokio_stream::{
    Stream,
    wrappers::{BroadcastStream, errors::BroadcastStreamRecvError},
};

use crate::endpoint::PathStats;

/// Capacity of the per-connection [`PathEvent`] broadcast channel.
const BROADCAST_CAPACITY: usize = 32;

/// A lifecycle notification for a network path.
///
/// Delivered via [`PathEventStream`]. Under backpressure, a
/// [`PathEvent::Lagged`] notification replaces the missed events; the
/// current live state is always available via [`Connection::paths`].
///
/// There is no explicit "unselected" variant. Consumers tracking selection
/// from the stream alone treat the most recent [`PathEvent::Selected`] as
/// the current selection and a matching [`PathEvent::Closed`] as selection
/// loss. For a synchronous read, use [`Paths::selected`].
///
/// [`Connection::paths`]: crate::endpoint::Connection::paths
#[derive(Clone, Debug)]
#[non_exhaustive]
pub enum PathEvent {
    /// A new network path was opened.
    Opened {
        /// Unique identifier for this path within the connection.
        id: PathId,
        /// Remote transport address of this path.
        remote_addr: TransportAddr,
    },
    /// A network path was closed; its final statistics are carried inline.
    Closed {
        /// Path that closed.
        id: PathId,
        /// Remote transport address of the closed path.
        remote_addr: TransportAddr,
        /// Path statistics captured at close time.
        last_stats: Box<PathStats>,
    },
    /// The selected (primary transmission) path changed.
    Selected {
        /// Newly selected path.
        id: PathId,
        /// Remote transport address of the newly selected path.
        remote_addr: TransportAddr,
    },
    /// The subscriber fell behind by `missed` events.
    ///
    /// Recover the current live state via [`Connection::paths`].
    ///
    /// [`Connection::paths`]: crate::endpoint::Connection::paths
    Lagged {
        /// Number of events missed before this notification was delivered.
        missed: u64,
    },
}

#[derive(Clone, Debug)]
struct PathData {
    handle: WeakPathHandle,
    remote_addr: TransportAddr,
}

#[derive(Default, Debug)]
struct State {
    list: SmallVec<[PathData; 4]>,
    selected: Option<PathId>,
}

/// Shared writer-side handle for a connection's path state.
///
/// Owned by the `RemoteStateActor`. Holds the broadcast [`Sender`]; when it
/// is dropped, every outstanding [`PathEventStream`] ends.
///
/// [`Sender`]: broadcast::Sender
#[derive(Clone, Debug)]
pub(crate) struct PathStateSender {
    state: Arc<ArcSwap<State>>,
    events: broadcast::Sender<PathEvent>,
}

/// Shared reader-side handle for a connection's path state.
///
/// Held by the [`crate::endpoint::Connection`]. Reads state through an
/// [`ArcSwap`] load and subscribes to events through a
/// [`broadcast::WeakSender`]; once the writer drops, new subscriptions
/// produce an already-closed stream.
#[derive(Clone, Debug)]
pub(crate) struct PathStateReceiver {
    state: Arc<ArcSwap<State>>,
    events: broadcast::WeakSender<PathEvent>,
}

impl PathStateSender {
    /// Creates a new empty writer-side store.
    pub(crate) fn new() -> (Self, PathStateReceiver) {
        let (events, _) = broadcast::channel(BROADCAST_CAPACITY);
        let state = Arc::new(ArcSwap::new(Arc::new(State::default())));
        let receiver = PathStateReceiver {
            state: state.clone(),
            events: events.downgrade(),
        };
        let sender = PathStateSender { state, events };
        (sender, receiver)
    }

    /// Records that a path was opened, emitting [`PathEvent::Opened`].
    pub(crate) fn record_opened(&self, handle: WeakPathHandle, remote_addr: TransportAddr) {
        let id = handle.id();
        let entry = PathData {
            handle,
            remote_addr: remote_addr.clone(),
        };
        self.update(|state| {
            if let Some(idx) = state.list.iter().position(|e| e.handle.id() == id) {
                state.list[idx] = entry;
            } else {
                let pos = state
                    .list
                    .iter()
                    .position(|e| e.handle.id() > id)
                    .unwrap_or(state.list.len());
                state.list.insert(pos, entry);
            }
        });
        let _ = self.events.send(PathEvent::Opened { id, remote_addr });
    }

    /// Records that a path was closed, emitting [`PathEvent::Closed`].
    pub(crate) fn record_closed(
        &self,
        id: PathId,
        remote_addr: TransportAddr,
        _conn: &noq::Connection,
    ) {
        let removed = self.update(|state| {
            if state.selected == Some(id) {
                state.selected = None;
            }
            state
                .list
                .iter()
                .position(|e| e.handle.id() == id)
                .map(|pos| state.list.remove(pos))
        });
        if let Some(removed) = removed {
            // Safe because conn is passed as argument to this function.
            let path = removed.handle.upgrade().expect("Connection is not dropped");
            let stats = path.stats();
            let _ = self.events.send(PathEvent::Closed {
                id,
                remote_addr,
                last_stats: Box::new(stats),
            });
        }
    }

    /// Updates the selected path. `None` clears the selection silently.
    ///
    /// Emits [`PathEvent::Selected`] on real `Some`-to-different-`Some`
    /// transitions.
    pub(crate) fn record_selected(&self, selected: Option<(PathId, TransportAddr)>) {
        let prev_id = self.state.load().selected;
        let next_id = selected.as_ref().map(|(id, _)| *id);
        if prev_id == next_id {
            return;
        }
        self.update(|state| state.selected = next_id);
        if let Some((id, remote_addr)) = selected {
            let _ = self.events.send(PathEvent::Selected { id, remote_addr });
        }
    }

    /// Emits synthetic [`PathEvent::Closed`] events for every remaining
    /// open path and clears the list.
    ///
    /// Called by the actor when the connection is being torn down so that
    /// event-stream consumers see the teardown explicitly. After this
    /// returns, dropping the [`PathStoreMut`] ends every outstanding
    /// [`PathEventStream`].
    pub(crate) fn close(self, closed: noq::Closed) {
        let state = self.state.load_full();
        for entry in state.list.iter() {
            if let Some(stats) = closed.path_stats.get(&entry.handle.id()) {
                let _ = self.events.send(PathEvent::Closed {
                    id: entry.handle.id(),
                    remote_addr: entry.remote_addr.clone(),
                    last_stats: Box::new(*stats),
                });
            } else {
                tracing::warn!("Missing path stats from Closed, omitting PathEvent::Closed");
            }
        }
    }

    fn update<R, F: FnOnce(&mut State) -> R>(&self, f: F) -> R {
        let current = self.state.load_full();
        let mut new = State {
            list: current.list.clone(),
            selected: current.selected,
        };
        let ret = f(&mut new);
        self.state.store(Arc::new(new));
        ret
    }
}

impl PathStateReceiver {
    /// Borrowed view of the current paths, tied to `&'a noq::Connection`.
    pub(crate) fn paths<'a>(&'a self, conn: &'a noq::Connection) -> Paths<'a> {
        Paths {
            state: self.state.load_full(),
            conn,
        }
    }

    /// A `'static` stream of [`PathEvent`]s.
    ///
    /// Ends as soon as the writer-side [`PathStoreMut`] is dropped. If the
    /// writer has already been dropped when this is called, the returned
    /// stream yields no events and terminates immediately.
    pub(crate) fn event_stream(&self) -> PathEventStream {
        let receiver = match self.events.upgrade() {
            Some(sender) => sender.subscribe(),
            None => {
                let (_tx, rx) = broadcast::channel(1);
                rx
            }
        };
        PathEventStream {
            inner: Box::pin(BroadcastStream::new(receiver)),
        }
    }
}

/// Borrowed snapshot of a connection's open paths.
///
/// Returned by [`Connection::paths`]. Captured atomically when constructed;
/// later mutations are not reflected. Iteration yields [`Path`] values whose
/// statistics are fetched live from the underlying QUIC state.
///
/// Closed paths are not retained. For per-path totals over the connection's
/// lifetime, accumulate from [`PathEvent`]s.
///
/// [`Connection`]: crate::endpoint::Connection
/// [`Connection::paths`]: crate::endpoint::Connection::paths
#[derive(Clone, Debug)]
pub struct Paths<'conn> {
    state: Arc<State>,
    conn: &'conn noq::Connection,
}

impl<'conn> Paths<'conn> {
    /// Returns the number of open paths in this snapshot.
    pub fn len(&self) -> usize {
        self.state.list.len()
    }

    /// Returns `true` if the snapshot has no open paths.
    pub fn is_empty(&self) -> bool {
        self.state.list.is_empty()
    }

    /// Returns an iterator over all open paths in this snapshot.
    pub fn iter(&self) -> impl Iterator<Item = Path<'_>> + '_ {
        let selected = self.state.selected;
        self.state.list.iter().map(move |data| Path {
            data,
            _conn: self.conn,
            selected,
        })
    }

    /// Returns the currently-selected path, or `None` if none is selected.
    pub fn selected(&self) -> Option<Path<'_>> {
        let id = self.state.selected?;
        self.get(id)
    }

    /// Looks up a path by [`PathId`].
    pub fn get(&self, id: PathId) -> Option<Path<'_>> {
        let selected = self.state.selected;
        self.state
            .list
            .iter()
            .find(|e| e.handle.id() == id)
            .map(|data| Path {
                data,
                _conn: self.conn,
                selected,
            })
    }
}

/// A single path in a [`Paths`] view.
///
/// Borrows from the enclosing [`Paths`] and transitively from the
/// [`crate::endpoint::Connection`]; it cannot be moved across task
/// boundaries.
#[derive(Clone, Debug)]
pub struct Path<'a> {
    data: &'a PathData,
    selected: Option<PathId>,
    _conn: &'a noq::Connection,
}

impl<'a> Path<'a> {
    /// Returns the path's unique [`PathId`] within the connection.
    pub fn id(&self) -> PathId {
        self.data.handle.id()
    }

    /// Returns the path's remote transport address.
    pub fn remote_addr(&self) -> &TransportAddr {
        &self.data.remote_addr
    }

    /// Returns `true` if this path was the selected transmission path at
    /// the moment the enclosing [`Paths`] snapshot was taken.
    pub fn is_selected(&self) -> bool {
        self.selected == Some(self.data.handle.id())
    }

    /// Returns `true` if this is an IP (direct) path.
    pub fn is_ip(&self) -> bool {
        self.data.remote_addr.is_ip()
    }

    /// Returns `true` if this is a relay path.
    pub fn is_relay(&self) -> bool {
        self.data.remote_addr.is_relay()
    }

    /// Returns the path's statistics.
    ///
    /// Stats are fetched live from the QUIC state on every call. If the
    /// path has just been discarded by `noq` but this snapshot has not yet
    /// been invalidated, [`PathStats::default`] is returned.
    pub fn stats(&self) -> PathStats {
        self.data
            .handle
            .upgrade()
            // save because `self` has a `&noq::Connection`
            .expect("Connection is not dropped")
            .stats()
    }

    /// Returns the path's round-trip time estimate.
    pub fn rtt(&self) -> Duration {
        self.stats().rtt
    }
}

/// Stream of [`PathEvent`]s.
///
/// Returned by [`Connection::path_events`]. Ends when the connection
/// closes. Does not keep the connection alive.
///
/// [`Connection::path_events`]: crate::endpoint::Connection::path_events
pub struct PathEventStream {
    inner: Pin<Box<BroadcastStream<PathEvent>>>,
}

impl Stream for PathEventStream {
    type Item = PathEvent;
    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.inner.as_mut().poll_next(cx).map(|event| match event? {
            Ok(event) => Some(event),
            Err(BroadcastStreamRecvError::Lagged(missed)) => Some(PathEvent::Lagged { missed }),
        })
    }
}

impl std::fmt::Debug for PathEventStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PathEventStream").finish_non_exhaustive()
    }
}

// #[cfg(test)]
// mod tests {
//     use std::net::SocketAddr;

//     use iroh_base::TransportAddr;
//     use n0_future::StreamExt;
//     use noq_proto::PathId;

//     use super::*;

//     fn pid(id: u32) -> PathId {
//         PathId::from(id)
//     }

//     fn ip_addr(port: u16) -> TransportAddr {
//         TransportAddr::Ip(SocketAddr::from(([127, 0, 0, 1], port)))
//     }

//     #[test]
//     fn open_close_roundtrip() {
//         let store = PathStateSender::new();
//         let mut events = store.events.subscribe();

//         store.record_opened(pid(1), ip_addr(1));
//         store.record_closed(pid(1), ip_addr(1), PathStats::default());

//         assert!(store.state.load().list.is_empty());
//         assert!(matches!(
//             events.try_recv().expect("Opened"),
//             PathEvent::Opened { id, .. } if id == pid(1)
//         ));
//         assert!(matches!(
//             events.try_recv().expect("Closed"),
//             PathEvent::Closed { id, .. } if id == pid(1)
//         ));
//     }

//     #[test]
//     fn select_transitions_emit_events() {
//         let store = PathStateSender::new();
//         store.record_opened(pid(1), ip_addr(1));
//         store.record_opened(pid(2), ip_addr(2));
//         let mut events = store.events.subscribe();

//         store.record_selected(Some((pid(1), ip_addr(1))));
//         assert!(matches!(
//             events.try_recv().expect("Selected"),
//             PathEvent::Selected { id, .. } if id == pid(1)
//         ));
//         // Dedup.
//         store.record_selected(Some((pid(1), ip_addr(1))));
//         assert!(events.try_recv().is_err());
//         // Switch.
//         store.record_selected(Some((pid(2), ip_addr(2))));
//         assert!(matches!(
//             events.try_recv().expect("Selected"),
//             PathEvent::Selected { id, .. } if id == pid(2)
//         ));
//         // Clear, no event.
//         store.record_selected(None);
//         assert!(events.try_recv().is_err());
//         assert!(store.state.load().selected.is_none());
//     }

//     #[tokio::test]
//     async fn stream_ends_when_store_dropped() {
//         let store = PathStateSender::new();
//         let handle = store.handle();
//         let mut stream = handle.event_stream();
//         store.record_opened(pid(1), ip_addr(1));
//         drop(store);
//         // The Opened event is delivered, then the stream ends.
//         assert!(matches!(
//             stream.next().await,
//             Some(PathEvent::Opened { .. })
//         ));
//         assert!(stream.next().await.is_none());
//     }

//     #[tokio::test]
//     async fn finalize_on_close_emits_synthetic_closes() {
//         let store = PathStateSender::new();
//         store.record_opened(pid(1), ip_addr(1));
//         store.record_opened(pid(2), ip_addr(2));
//         let handle = store.handle();
//         let mut stream = handle.event_stream();
//         store.finalize_on_close(None);
//         drop(store);

//         let mut kinds = Vec::new();
//         while let Some(event) = stream.next().await {
//             kinds.push(match event {
//                 PathEvent::Opened { .. } => "opened",
//                 PathEvent::Closed { .. } => "closed",
//                 PathEvent::Selected { .. } => "selected",
//                 PathEvent::Lagged { .. } => "lagged",
//             });
//         }
//         assert_eq!(kinds, vec!["closed", "closed"]);
//     }

//     #[tokio::test]
//     async fn event_stream_after_drop_is_immediately_empty() {
//         let store = PathStateSender::new();
//         let handle = store.handle();
//         drop(store);
//         let mut stream = handle.event_stream();
//         assert!(stream.next().await.is_none());
//     }

//     #[tokio::test]
//     async fn lagged_surfaces() {
//         let store = PathStateSender::new();
//         let handle = store.handle();
//         let mut stream = handle.event_stream();
//         for i in 0..(BROADCAST_CAPACITY as u32 + 5) {
//             store.record_opened(pid(i + 1), ip_addr((i + 1) as u16));
//         }
//         let event = stream.next().await.expect("event");
//         assert!(matches!(event, PathEvent::Lagged { missed } if missed >= 1));
//     }
// }
