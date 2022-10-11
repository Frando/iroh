use std::{collections::HashMap, sync::Arc};

use anyhow::Result;
use async_trait::async_trait;
use bytes::Bytes;
use cid::Cid;
use futures::{stream::TryStreamExt, StreamExt};
use iroh_car::CarReader;
use iroh_rpc_client::Client;
use par_stream::prelude::*;
use tokio::io::AsyncRead;

use crate::resolver::ContentLoader;

#[async_trait]
pub trait ContentWriter: Sync + Send + std::fmt::Debug + Clone + 'static {
    /// Write bytes to cid and pass any included links.
    /// Does not verify that cid or links are correct.
    async fn write_block_unchecked(&self, cid: Cid, blob: Bytes, links: Vec<Cid>) -> Result<()>;

    /// Write bytes to cid. Verifies the cid and extracts links from the blob.
    async fn write_block(&self, cid: Cid, blob: Bytes) -> Result<()> {
        if iroh_util::verify_hash(&cid, &blob) == Some(false) {
            anyhow::bail!("invalid hash {:?}", cid);
        }
        let links = crate::parse_links(&cid, &blob).unwrap_or_default();
        self.write_block_unchecked(cid, blob, links).await
    }

    /// Write all blocks from a car file. Verifies cids and extracts links.
    /// Returns a tuple of (num_blocks_written, num_bytes_written).
    async fn write_car(
        &self,
        bytes: impl AsyncRead + Send + Unpin + 'static,
    ) -> Result<WriteCarOutput> {
        let car_reader = CarReader::new(bytes).await?;
        let roots = car_reader.header().roots().to_vec();
        let stream = car_reader.stream().boxed();
        let store = self.clone();
        let blocks: HashMap<_, _> = stream
            .map_err(anyhow::Error::from)
            .try_par_then_unordered(None, move |(cid, data)| {
                let store = store.clone();
                async move {
                    let l = data.len();
                    store.write_block(cid, Bytes::from(data)).await?;
                    Ok((cid, l))
                }
            })
            .try_collect()
            .await?;
        Ok(WriteCarOutput { roots, blocks })
    }
}

#[derive(Debug, Clone)]
pub struct WriteCarOutput {
    pub roots: Vec<Cid>,
    pub blocks: HashMap<Cid, usize>,
}

#[async_trait]
impl<T: ContentWriter> ContentWriter for Arc<T> {
    async fn write_block_unchecked(&self, cid: Cid, blob: Bytes, links: Vec<Cid>) -> Result<()> {
        self.as_ref().write_block_unchecked(cid, blob, links).await
    }
}

#[async_trait]
impl ContentWriter for Client {
    async fn write_block_unchecked(&self, cid: Cid, blob: Bytes, links: Vec<Cid>) -> Result<()> {
        self.try_store()?.put(cid, blob, links).await?;
        Ok(())
    }
}

pub trait ContentStore: ContentWriter + ContentLoader {}
impl<T: ContentWriter + ContentLoader> ContentStore for T {}
