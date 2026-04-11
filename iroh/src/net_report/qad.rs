//! QAD (QUIC Address Discovery) probe types, execution, and connection management.
//!
//! QAD probes open a QUIC connection to a relay server and read back the
//! observed external address. This gives the endpoint its public IP and
//! port as seen by the relay, which is the foundation for direct
//! connectivity between peers.
//!
//! The module contains three layers:
//!
//! 1. **DNS helpers** (`get_relay_addr_ipv4`, `get_relay_addr_ipv6`) that
//!    resolve a relay URL to a concrete socket address.
//! 2. **Probe functions** (`run_probe_v4`, `run_probe_v6`) that perform
//!    the full connect-and-observe cycle and return a long-lived
//!    [`QadConn`] for address change notifications.
//! 3. **Connection management** ([`QadConns`]) that the actor uses to
//!    track the winning v4/v6 connections across probe cycles.

#[cfg(not(wasm_browser))]
use std::net::{SocketAddrV4, SocketAddrV6};
use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
};

use iroh_base::RelayUrl;
#[cfg(not(wasm_browser))]
use iroh_relay::dns::{DnsError, DnsResolver, StaggeredError};
use iroh_relay::{
    RelayConfig,
    defaults::DEFAULT_RELAY_QUIC_PORT,
    quic::{QUIC_ADDR_DISC_CLOSE_CODE, QUIC_ADDR_DISC_CLOSE_REASON},
};
use n0_error::{e, stack_error};
#[cfg(not(wasm_browser))]
use n0_future::task;
use n0_future::{StreamExt, task::AbortOnDropHandle, time::Duration};
use n0_watcher::{Watchable, Watcher};
use tokio_util::sync::CancellationToken;
use tracing::trace;

#[cfg(not(wasm_browser))]
use super::defaults::timeouts::DNS_TIMEOUT;
#[cfg(not(wasm_browser))]
use crate::address_lookup::DNS_STAGGERING_MS;

/// Result of a single QAD probe against one relay server.
///
/// Contains the relay URL, the round-trip latency measured during the
/// QUIC handshake, and the public address the relay observed for us.
#[cfg(not(wasm_browser))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct QadProbeReport {
    /// URL of the relay that was probed.
    pub(super) relay: RelayUrl,
    /// Round-trip latency to the relay, measured from the QUIC connection.
    pub(super) latency: Duration,
    /// Public socket address the relay observed for this endpoint.
    pub(super) addr: SocketAddr,
}

/// Configuration for QUIC Address Discovery probes.
///
/// Bundles the QUIC endpoint, TLS client config, and per-address-family
/// enable flags that the actor needs to run QAD probes.
#[derive(derive_more::Debug, Clone)]
pub(crate) struct QuicConfig {
    /// The QUIC endpoint used to initiate probe connections.
    #[debug("noq::Endpoint")]
    pub(crate) ep: noq::Endpoint,
    /// TLS client configuration for the probe connections.
    pub(crate) client_config: rustls::ClientConfig,
    /// Whether IPv4 QAD probes are enabled.
    pub(crate) ipv4: bool,
    /// Whether IPv6 QAD probes are enabled.
    pub(crate) ipv6: bool,
}

/// Errors that can occur during a QAD probe.
#[cfg(not(wasm_browser))]
#[allow(missing_docs)]
#[stack_error(derive, add_meta)]
#[non_exhaustive]
pub(super) enum QadProbeError {
    #[error("Failed to resolve relay address")]
    GetRelayAddr { source: GetRelayAddrError },
    #[error("Missing host in relay URL")]
    MissingHost,
    #[error("QUIC connection failed")]
    Quic { source: iroh_relay::quic::Error },
    #[error("Receiver dropped")]
    ReceiverDropped,
}

/// Tracks the winning QAD connections for IPv4 and IPv6.
///
/// The actor holds one of these across probe cycles. Each slot stores the
/// relay URL and the [`QadConn`] that won the race for that address
/// family. When a slot is replaced or cleared, the old connection is
/// closed with the standard QAD close code.
#[cfg(not(wasm_browser))]
#[derive(Debug, Default)]
pub(super) struct QadConns {
    /// Winning IPv4 QAD connection, if any.
    pub(super) v4: Option<(RelayUrl, QadConn)>,
    /// Winning IPv6 QAD connection, if any.
    pub(super) v6: Option<(RelayUrl, QadConn)>,
}

#[cfg(not(wasm_browser))]
impl QadConns {
    /// Closes both connections and empties the slots.
    pub(super) fn clear(&mut self) {
        if let Some((_, conn)) = self.v4.take() {
            conn.conn
                .close(QUIC_ADDR_DISC_CLOSE_CODE, QUIC_ADDR_DISC_CLOSE_REASON);
        }
        if let Some((_, conn)) = self.v6.take() {
            conn.conn
                .close(QUIC_ADDR_DISC_CLOSE_CODE, QUIC_ADDR_DISC_CLOSE_REASON);
        }
    }

    /// Returns the most recent QAD report from the IPv4 connection, if one
    /// exists and has produced an observed address.
    ///
    /// The latency is refreshed from the connection's current RTT estimate.
    pub(super) fn current_v4(&self) -> Option<QadProbeReport> {
        if let Some((_, ref conn)) = self.v4
            && let Some(mut r) = conn.observer.get()
        {
            use noq_proto::PathId;
            if let Some(latency) = conn.conn.rtt(PathId::ZERO) {
                r.latency = latency;
            }
            return Some(r);
        }
        None
    }

    /// Returns the most recent QAD report from the IPv6 connection, if one
    /// exists and has produced an observed address.
    ///
    /// The latency is refreshed from the connection's current RTT estimate.
    pub(super) fn current_v6(&self) -> Option<QadProbeReport> {
        if let Some((_, ref conn)) = self.v6
            && let Some(mut r) = conn.observer.get()
        {
            use noq_proto::PathId;
            if let Some(latency) = conn.conn.rtt(PathId::ZERO) {
                r.latency = latency;
            }
            return Some(r);
        }
        None
    }

    /// Returns a watcher over both QAD connections' observed addresses.
    ///
    /// The watcher yields `(v4, v6)` tuples. When either connection
    /// observes a new address the watcher fires. Connections that do not
    /// exist contribute a stable `None`.
    pub(super) fn watch(
        &self,
    ) -> impl Watcher<Value = (Option<QadProbeReport>, Option<QadProbeReport>)> + use<> {
        let v4 = match self.v4.as_ref() {
            Some((_, conn)) => conn.observer.watch(),
            None => Watchable::new(None).watch(),
        };
        let v6 = match self.v6.as_ref() {
            Some((_, conn)) => conn.observer.watch(),
            None => Watchable::new(None).watch(),
        };
        v4.or(v6)
    }
}

/// A live QAD connection to a relay server.
///
/// Holds the QUIC connection, a [`Watchable`] that publishes address
/// updates as the relay observes them, and a background task handle that
/// drives the update loop. Dropping the handle aborts the task.
#[cfg(not(wasm_browser))]
#[derive(Debug)]
pub(super) struct QadConn {
    /// The underlying QUIC connection to the relay.
    pub(super) conn: noq::Connection,
    /// Publishes the latest observed address from this connection.
    pub(super) observer: Watchable<Option<QadProbeReport>>,
    /// Handle to the background task that watches for address changes.
    pub(super) _handle: AbortOnDropHandle<Option<()>>,
}

/// Runs a QAD probe over IPv4 against a single relay server.
///
/// Resolves the relay's IPv4 address, opens a QUIC connection, waits for
/// the first observed external address, and returns the probe report
/// together with a [`QadConn`] that continues watching for address
/// changes in the background.
#[cfg(not(wasm_browser))]
pub(super) async fn run_probe_v4(
    relay: Arc<RelayConfig>,
    quic_client: iroh_relay::quic::QuicClient,
    dns_resolver: DnsResolver,
    shutdown_token: CancellationToken,
) -> n0_error::Result<(QadProbeReport, QadConn), QadProbeError> {
    use noq_proto::PathId;

    let relay_addr = get_relay_addr_ipv4(&dns_resolver, &relay)
        .await
        .map_err(|source| e!(QadProbeError::GetRelayAddr { source }))?;

    trace!(?relay_addr, "resolved relay server address");
    let host = relay
        .url
        .host_str()
        .ok_or_else(|| e!(QadProbeError::MissingHost))?;
    let conn = quic_client
        .create_conn(relay_addr.into(), host)
        .await
        .map_err(|source| e!(QadProbeError::Quic { source }))?;

    let mut watcher = conn.observed_external_addr();

    let addr = watcher
        .next()
        .await
        .ok_or_else(|| e!(QadProbeError::ReceiverDropped))?;
    let report = QadProbeReport {
        relay: relay.url.clone(),
        addr: SocketAddr::new(addr.ip().to_canonical(), addr.port()),
        latency: conn.rtt(PathId::ZERO).unwrap_or_default(),
    };

    let observer = Watchable::new(None);
    let endpoint = relay.url.clone();
    let handle = task::spawn(shutdown_token.run_until_cancelled_owned({
        let conn = conn.clone();
        let observer = observer.clone();
        async move {
            while let Some(val) = watcher.next().await {
                let val = SocketAddr::new(val.ip().to_canonical(), val.port());
                let latency = conn.rtt(PathId::ZERO).unwrap_or_default();
                observer
                    .set(Some(QadProbeReport {
                        relay: endpoint.clone(),
                        addr: val,
                        latency,
                    }))
                    .ok();
            }
        }
    }));
    let handle = AbortOnDropHandle::new(handle);

    Ok((
        report,
        QadConn {
            conn,
            observer,
            _handle: handle,
        },
    ))
}

/// Runs a QAD probe over IPv6 against a single relay server.
///
/// Resolves the relay's IPv6 address, opens a QUIC connection, waits for
/// the first observed external address, and returns the probe report
/// together with a [`QadConn`] that continues watching for address
/// changes in the background.
#[cfg(not(wasm_browser))]
pub(super) async fn run_probe_v6(
    relay: Arc<RelayConfig>,
    quic_client: iroh_relay::quic::QuicClient,
    dns_resolver: DnsResolver,
    shutdown_token: CancellationToken,
) -> n0_error::Result<(QadProbeReport, QadConn), QadProbeError> {
    use noq_proto::PathId;

    let relay_addr = get_relay_addr_ipv6(&dns_resolver, &relay)
        .await
        .map_err(|source| e!(QadProbeError::GetRelayAddr { source }))?;

    trace!(?relay_addr, "resolved relay server address");
    let host = relay
        .url
        .host_str()
        .ok_or_else(|| e!(QadProbeError::MissingHost))?;
    let conn = quic_client
        .create_conn(relay_addr.into(), host)
        .await
        .map_err(|source| e!(QadProbeError::Quic { source }))?;

    let mut watcher = conn.observed_external_addr();

    let addr = watcher
        .next()
        .await
        .ok_or_else(|| e!(QadProbeError::ReceiverDropped))?;
    let report = QadProbeReport {
        relay: relay.url.clone(),
        addr: SocketAddr::new(addr.ip().to_canonical(), addr.port()),
        latency: conn.rtt(PathId::ZERO).unwrap_or_default(),
    };

    let observer = Watchable::new(None);
    let endpoint = relay.url.clone();
    let handle = task::spawn(shutdown_token.run_until_cancelled_owned({
        let observer = observer.clone();
        let conn = conn.clone();
        async move {
            while let Some(val) = watcher.next().await {
                let val = SocketAddr::new(val.ip().to_canonical(), val.port());
                let latency = conn.rtt(PathId::ZERO).unwrap_or_default();
                observer
                    .set(Some(QadProbeReport {
                        relay: endpoint.clone(),
                        addr: val,
                        latency,
                    }))
                    .ok();
            }
        }
    }));
    let handle = AbortOnDropHandle::new(handle);

    Ok((
        report,
        QadConn {
            conn,
            observer,
            _handle: handle,
        },
    ))
}

/// Returns the QUIC port for the relay, falling back to the default when the
/// configured port is zero. Returns `None` if the relay has no QUIC config.
#[cfg(not(wasm_browser))]
fn get_quic_port(relay: &RelayConfig) -> Option<u16> {
    if let Some(ref quic) = relay.quic {
        if quic.port == 0 {
            Some(DEFAULT_RELAY_QUIC_PORT)
        } else {
            Some(quic.port)
        }
    } else {
        None
    }
}

/// Errors from resolving a relay URL to a concrete socket address.
#[cfg(not(wasm_browser))]
#[stack_error(derive, add_meta)]
#[non_exhaustive]
pub(super) enum GetRelayAddrError {
    /// The relay URL has no valid hostname component.
    #[error("No valid hostname in the relay URL")]
    InvalidHostname,
    /// DNS resolved successfully but returned no address of the requested family.
    #[error("No suitable relay address found for {url} ({addr_type})")]
    NoAddrFound {
        /// The relay URL that was being resolved.
        url: RelayUrl,
        /// The DNS record type that was queried ("A" or "AAAA").
        addr_type: &'static str,
    },
    /// The staggered DNS lookup itself failed.
    #[error("DNS lookup failed")]
    DnsLookup { source: StaggeredError<DnsError> },
    /// The relay configuration is not suitable for QAD probes.
    #[error("Relay is not suitable")]
    UnsupportedRelay,
    /// HTTPS-only probes are not supported by this code path.
    #[error("HTTPS probes are not implemented")]
    UnsupportedHttps,
    /// The relay has no QUIC port configured.
    #[error("No port available for this protocol")]
    MissingPort,
}

/// Returns the IP address to use to communicate to this relay for quic.
#[cfg(not(wasm_browser))]
pub(super) async fn get_relay_addr_ipv4(
    dns_resolver: &DnsResolver,
    relay: &RelayConfig,
) -> Result<SocketAddrV4, GetRelayAddrError> {
    let port = get_quic_port(relay).ok_or_else(|| e!(GetRelayAddrError::MissingPort))?;
    relay_lookup_ipv4_staggered(dns_resolver, relay, port).await
}

/// Returns the IPv6 socket address of the relay's QUIC endpoint.
///
/// Resolves the relay URL's hostname via AAAA lookup, or returns the
/// literal address if the URL already contains an IPv6 address.
#[cfg(not(wasm_browser))]
pub(super) async fn get_relay_addr_ipv6(
    dns_resolver: &DnsResolver,
    relay: &RelayConfig,
) -> Result<SocketAddrV6, GetRelayAddrError> {
    let port = get_quic_port(relay).ok_or_else(|| e!(GetRelayAddrError::MissingPort))?;
    relay_lookup_ipv6_staggered(dns_resolver, relay, port).await
}

/// Performs a staggered IPv4 DNS lookup for a relay and returns a [`SocketAddrV4`].
///
/// Combines the first resolved A record with the given `port`.
#[cfg(not(wasm_browser))]
async fn relay_lookup_ipv4_staggered(
    dns_resolver: &DnsResolver,
    relay: &RelayConfig,
    port: u16,
) -> Result<SocketAddrV4, GetRelayAddrError> {
    match relay.url.host() {
        Some(url::Host::Domain(hostname)) => {
            trace!(%hostname, "Performing DNS A lookup for relay addr");
            match dns_resolver
                .lookup_ipv4_staggered(hostname, DNS_TIMEOUT, DNS_STAGGERING_MS)
                .await
            {
                Ok(mut addrs) => addrs
                    .next()
                    .map(|ip| ip.to_canonical())
                    .map(|addr| match addr {
                        IpAddr::V4(ip) => SocketAddrV4::new(ip, port),
                        IpAddr::V6(_) => unreachable!("bad DNS lookup: {:?}", addr),
                    })
                    .ok_or_else(|| {
                        e!(GetRelayAddrError::NoAddrFound {
                            url: relay.url.clone(),
                            addr_type: "A",
                        })
                    }),
                Err(err) => Err(e!(GetRelayAddrError::DnsLookup, err)),
            }
        }
        Some(url::Host::Ipv4(addr)) => Ok(SocketAddrV4::new(addr, port)),
        Some(url::Host::Ipv6(_addr)) => Err(e!(GetRelayAddrError::NoAddrFound {
            url: relay.url.clone(),
            addr_type: "A",
        })),
        None => Err(e!(GetRelayAddrError::InvalidHostname)),
    }
}

/// Performs a staggered IPv6 DNS lookup for a relay and returns a [`SocketAddrV6`].
///
/// Combines the first resolved AAAA record with the given `port`.
#[cfg(not(wasm_browser))]
async fn relay_lookup_ipv6_staggered(
    dns_resolver: &DnsResolver,
    relay: &RelayConfig,
    port: u16,
) -> Result<SocketAddrV6, GetRelayAddrError> {
    match relay.url.host() {
        Some(url::Host::Domain(hostname)) => {
            trace!(%hostname, "Performing DNS AAAA lookup for relay addr");
            match dns_resolver
                .lookup_ipv6_staggered(hostname, DNS_TIMEOUT, DNS_STAGGERING_MS)
                .await
            {
                Ok(mut addrs) => addrs
                    .next()
                    .map(|addr| match addr {
                        IpAddr::V4(_) => unreachable!("bad DNS lookup: {:?}", addr),
                        IpAddr::V6(ip) => SocketAddrV6::new(ip, port, 0, 0),
                    })
                    .ok_or_else(|| {
                        e!(GetRelayAddrError::NoAddrFound {
                            url: relay.url.clone(),
                            addr_type: "AAAA",
                        })
                    }),
                Err(err) => Err(e!(GetRelayAddrError::DnsLookup, err)),
            }
        }
        Some(url::Host::Ipv4(_addr)) => Err(e!(GetRelayAddrError::NoAddrFound {
            url: relay.url.clone(),
            addr_type: "AAAA",
        })),
        Some(url::Host::Ipv6(addr)) => Ok(SocketAddrV6::new(addr, port, 0, 0)),
        None => Err(e!(GetRelayAddrError::InvalidHostname)),
    }
}

#[cfg(all(test, with_crypto_provider))]
mod tests {
    use std::{
        net::{Ipv4Addr, SocketAddr},
        sync::Arc,
    };

    use iroh_relay::dns::DnsResolver;
    use n0_error::{Result, StdResultExt};
    use n0_tracing_test::traced_test;
    use tokio_util::sync::CancellationToken;

    use super::super::test_utils;

    #[tokio::test]
    #[traced_test]
    async fn test_qad_probe_v4() -> Result {
        let (server, relay) = test_utils::relay().await;
        let relay = Arc::new(relay);
        let client_config = iroh_relay::tls::make_dangerous_client_config();
        let ep = noq::Endpoint::client(SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0)).anyerr()?;
        let client_addr = ep.local_addr().anyerr()?;

        let quic_client = iroh_relay::quic::QuicClient::new(ep.clone(), client_config);
        let dns_resolver = DnsResolver::default();

        let (report, conn) =
            super::run_probe_v4(relay, quic_client, dns_resolver, CancellationToken::new())
                .await
                .unwrap();

        assert_eq!(report.addr, client_addr);
        drop(conn);
        ep.wait_idle().await;
        server.shutdown().await?;
        Ok(())
    }
}
