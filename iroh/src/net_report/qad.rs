//! QAD (QUIC Address Discovery) probe types, execution, and connection management.

use std::net::{IpAddr, SocketAddr};
#[cfg(not(wasm_browser))]
use std::net::{SocketAddrV4, SocketAddrV6};

use iroh_base::RelayUrl;
#[cfg(not(wasm_browser))]
use iroh_relay::dns::{DnsError, DnsResolver, StaggeredError};
use iroh_relay::{RelayConfig, defaults::DEFAULT_RELAY_QUIC_PORT};
use n0_error::{e, stack_error};
use n0_future::time::Duration;
use tracing::trace;

#[cfg(not(wasm_browser))]
use super::defaults::timeouts::DNS_TIMEOUT;
#[cfg(not(wasm_browser))]
use crate::address_lookup::DNS_STAGGERING_MS;

#[cfg(not(wasm_browser))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct QadProbeReport {
    /// The relay that was probed
    pub(super) relay: RelayUrl,
    /// The latency to the relay.
    pub(super) latency: Duration,
    /// The discovered public address.
    pub(super) addr: SocketAddr,
}

/// Pieces needed to do QUIC address discovery.
#[derive(derive_more::Debug, Clone)]
pub(crate) struct QuicConfig {
    /// A QUIC Endpoint
    #[debug("noq::Endpoint")]
    pub(crate) ep: noq::Endpoint,
    /// A client config.
    pub(crate) client_config: rustls::ClientConfig,
    /// Enable ipv4 QUIC address discovery probes
    pub(crate) ipv4: bool,
    /// Enable ipv6 QUIC address discovery probes
    pub(crate) ipv6: bool,
}

/// Returns the proper port based on the protocol of the probe.
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

#[cfg(not(wasm_browser))]
#[stack_error(derive, add_meta)]
#[non_exhaustive]
pub(super) enum GetRelayAddrError {
    #[error("No valid hostname in the relay URL")]
    InvalidHostname,
    #[error("No suitable relay address found for {url} ({addr_type})")]
    NoAddrFound {
        url: RelayUrl,
        addr_type: &'static str,
    },
    #[error("DNS lookup failed")]
    DnsLookup { source: StaggeredError<DnsError> },
    #[error("Relay is not suitable")]
    UnsupportedRelay,
    #[error("HTTPS probes are not implemented")]
    UnsupportedHttps,
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

#[cfg(not(wasm_browser))]
pub(super) async fn get_relay_addr_ipv6(
    dns_resolver: &DnsResolver,
    relay: &RelayConfig,
) -> Result<SocketAddrV6, GetRelayAddrError> {
    let port = get_quic_port(relay).ok_or_else(|| e!(GetRelayAddrError::MissingPort))?;
    relay_lookup_ipv6_staggered(dns_resolver, relay, port).await
}

/// Do a staggared ipv4 DNS lookup based on [`RelayConfig`]
///
/// `port` is combined with the resolved [`std::net::Ipv4Addr`] to return a [`SocketAddr`]
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

/// Do a staggared ipv6 DNS lookup based on [`RelayConfig`]
///
/// `port` is combined with the resolved [`std::net::Ipv6Addr`] to return a [`SocketAddr`]
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
            super::super::run_probe_v4(relay, quic_client, dns_resolver, CancellationToken::new())
                .await
                .unwrap();

        assert_eq!(report.addr, client_addr);
        drop(conn);
        ep.wait_idle().await;
        server.shutdown().await?;
        Ok(())
    }
}
