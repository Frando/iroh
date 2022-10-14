use anyhow::Result;
use cid::Cid;
use serde::Serialize;
use tokio::io::AsyncRead;
use tracing::debug;

use super::writer::ContentWriter;

#[derive(Clone, Debug)]
pub struct WritingClient<T: ContentWriter> {
    writer: T,
}

impl<T: ContentWriter + std::marker::Unpin> WritingClient<T> {
    pub fn new(writer: T) -> Self {
        Self { writer }
    }

    #[tracing::instrument(skip(self, bytes))]
    pub async fn put_car(
        &self,
        bytes: impl AsyncRead + Send + Unpin + 'static,
        start_time: std::time::Instant,
    ) -> Result<WriteCarOutputSerializable> {
        let out = self.writer.write_car(bytes).await?;
        let count = out.blocks.len();
        let bytes: usize = out.blocks.iter().map(|(_, len)| len).sum();
        debug!(
            "imported {} elements ({}) in {}s",
            count,
            bytes,
            start_time.elapsed().as_secs()
        );
        let out = WriteCarOutputSerializable {
            success: true,
            roots: out.roots.iter().map(Cid::to_string).collect(),
            blocks: count,
            bytes,
        };
        Ok(out)
    }
}

#[derive(Serialize, Debug, Clone)]
pub struct WriteCarOutputSerializable {
    roots: Vec<String>,
    blocks: usize,
    bytes: usize,
    success: bool,
}
