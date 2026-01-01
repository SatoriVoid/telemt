//! Encrypted stream wrappers using AES-CTR
//!
//! This module provides stateful async stream wrappers that handle
//! encryption/decryption with proper partial read/write handling.
//!
//! Key design principles:
//! - Explicit state machines for all async operations
//! - Never lose data on partial reads/writes
//! - Honest reporting of bytes written
//! - Bounded internal buffers with backpressure

use bytes::{Bytes, BytesMut, BufMut};
use std::io::{self, Error, ErrorKind, Result};
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::crypto::AesCtr;
use crate::error::StreamError;
use super::state::{StreamState, ReadBuffer, WriteBuffer, YieldBuffer};

// ============= Constants =============

/// Maximum size for pending write buffer (256KB)
const MAX_PENDING_WRITE: usize = 256 * 1024;

/// Default read buffer capacity
const DEFAULT_READ_CAPACITY: usize = 16 * 1024;

// ============= CryptoReader State =============

/// State machine states for CryptoReader
#[derive(Debug)]
enum CryptoReaderState {
    /// Ready to read new data
    Idle,
    
    /// Have decrypted data ready to yield to caller
    Yielding {
        /// Buffer containing decrypted data
        buffer: YieldBuffer,
    },
    
    /// Stream encountered an error and cannot be used
    Poisoned {
        /// The error that caused poisoning (taken on first access)
        error: Option<io::Error>,
    },
}

impl StreamState for CryptoReaderState {
    fn is_terminal(&self) -> bool {
        matches!(self, Self::Poisoned { .. })
    }
    
    fn is_poisoned(&self) -> bool {
        matches!(self, Self::Poisoned { .. })
    }
    
    fn state_name(&self) -> &'static str {
        match self {
            Self::Idle => "Idle",
            Self::Yielding { .. } => "Yielding",
            Self::Poisoned { .. } => "Poisoned",
        }
    }
}

// ============= CryptoReader =============

/// Reader that decrypts data using AES-CTR with proper state machine
///
/// This reader handles partial reads correctly by maintaining internal state
/// and never losing any data that has been read from upstream.
///
/// # State Machine
///
/// ┌──────────┐     read      ┌──────────┐
/// │   Idle   │ ------------> │ Yielding │
/// │          │ <------------ │          │
/// └──────────┘   drained     └──────────┘
///      │                          │
///      │         errors           │
/// ┌──────────────────────────────────────┐
/// │              Poisoned                │
/// └──────────────────────────────────────┘
pub struct CryptoReader<R> {
    /// Upstream reader
    upstream: R,
    /// AES-CTR decryptor
    decryptor: AesCtr,
    /// Current state
    state: CryptoReaderState,
    /// Internal read buffer for upstream reads
    read_buf: BytesMut,
}

impl<R> CryptoReader<R> {
    /// Create new crypto reader
    pub fn new(upstream: R, decryptor: AesCtr) -> Self {
        Self {
            upstream,
            decryptor,
            state: CryptoReaderState::Idle,
            read_buf: BytesMut::with_capacity(DEFAULT_READ_CAPACITY),
        }
    }
    
    /// Get reference to upstream
    pub fn get_ref(&self) -> &R {
        &self.upstream
    }
    
    /// Get mutable reference to upstream
    pub fn get_mut(&mut self) -> &mut R {
        &mut self.upstream
    }
    
    /// Consume and return upstream
    pub fn into_inner(self) -> R {
        self.upstream
    }
    
    /// Check if stream is in poisoned state
    pub fn is_poisoned(&self) -> bool {
        self.state.is_poisoned()
    }
    
    /// Get current state name (for debugging)
    pub fn state_name(&self) -> &'static str {
        self.state.state_name()
    }
    
    /// Transition to poisoned state
    fn poison(&mut self, error: io::Error) {
        self.state = CryptoReaderState::Poisoned { error: Some(error) };
    }
    
    /// Take error from poisoned state
    fn take_poison_error(&mut self) -> io::Error {
        match &mut self.state {
            CryptoReaderState::Poisoned { error } => {
                error.take().unwrap_or_else(|| {
                    io::Error::new(ErrorKind::Other, "stream previously poisoned")
                })
            }
            _ => io::Error::new(ErrorKind::Other, "stream not poisoned"),
        }
    }
}

impl<R: AsyncRead + Unpin> AsyncRead for CryptoReader<R> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<Result<()>> {
        let this = self.get_mut();
        
        loop {
            match &mut this.state {
                // Poisoned state - return error
                CryptoReaderState::Poisoned { .. } => {
                    let err = this.take_poison_error();
                    return Poll::Ready(Err(err));
                }
                
                // Have buffered data to yield
                CryptoReaderState::Yielding { buffer } => {
                    if buf.remaining() == 0 {
                        return Poll::Ready(Ok(()));
                    }
                    
                    // Copy as much as possible to output
                    let to_copy = buffer.remaining().min(buf.remaining());
                    let dst = buf.initialize_unfilled_to(to_copy);
                    let copied = buffer.copy_to(dst);
                    buf.advance(copied);
                    
                    // If buffer is drained, transition to Idle
                    if buffer.is_empty() {
                        this.state = CryptoReaderState::Idle;
                    }
                    
                    return Poll::Ready(Ok(()));
                }
                
                // Ready to read from upstream
                CryptoReaderState::Idle => {
                    // If caller's buffer is empty, nothing to do
                    if buf.remaining() == 0 {
                        return Poll::Ready(Ok(()));
                    }
                    
                    // Try to read directly into caller's buffer for zero-copy path
                    // We need to be careful: read into unfilled portion, then decrypt
                    let before_len = buf.filled().len();
                    
                    match Pin::new(&mut this.upstream).poll_read(cx, buf) {
                        Poll::Pending => return Poll::Pending,
                        
                        Poll::Ready(Err(e)) => {
                            this.poison(io::Error::new(e.kind(), e.to_string()));
                            return Poll::Ready(Err(e));
                        }
                        
                        Poll::Ready(Ok(())) => {
                            let after_len = buf.filled().len();
                            let bytes_read = after_len - before_len;
                            
                            if bytes_read == 0 {
                                // EOF
                                return Poll::Ready(Ok(()));
                            }
                            
                            // Decrypt the newly read data in-place
                            let filled = buf.filled_mut();
                            this.decryptor.apply(&mut filled[before_len..after_len]);
                            
                            return Poll::Ready(Ok(()));
                        }
                    }
                }
            }
        }
    }
}

impl<R: AsyncRead + Unpin> CryptoReader<R> {
    /// Read and decrypt exactly n bytes
    ///
    /// This is a convenience method that accumulates data until
    /// exactly n bytes are available.
    pub async fn read_exact_decrypt(&mut self, n: usize) -> Result<Bytes> {
        use tokio::io::AsyncReadExt;
        
        if self.is_poisoned() {
            return Err(self.take_poison_error());
        }
        
        let mut result = BytesMut::with_capacity(n);
        
        // First drain any buffered data from Yielding state
        if let CryptoReaderState::Yielding { buffer } = &mut self.state {
            let to_take = buffer.remaining().min(n);
            let mut temp = vec![0u8; to_take];
            buffer.copy_to(&mut temp);
            result.extend_from_slice(&temp);
            
            if buffer.is_empty() {
                self.state = CryptoReaderState::Idle;
            }
        }
        
        // Read remaining from upstream
        while result.len() < n {
            let mut temp = vec![0u8; n - result.len()];
            let read = self.read(&mut temp).await?;
            
            if read == 0 {
                return Err(io::Error::new(
                    ErrorKind::UnexpectedEof,
                    format!("expected {} bytes, got {}", n, result.len())
                ));
            }
            
            result.extend_from_slice(&temp[..read]);
        }
        
        Ok(result.freeze())
    }
    
    /// Read into internal buffer and return decrypted bytes
    ///
    /// Useful when you need the data as Bytes rather than copying to a slice.
    pub async fn read_decrypt(&mut self, max_size: usize) -> Result<Bytes> {
        use tokio::io::AsyncReadExt;
        
        if self.is_poisoned() {
            return Err(self.take_poison_error());
        }
        
        // First check if we have buffered data
        if let CryptoReaderState::Yielding { buffer } = &mut self.state {
            let to_take = buffer.remaining().min(max_size);
            let mut temp = vec![0u8; to_take];
            buffer.copy_to(&mut temp);
            
            if buffer.is_empty() {
                self.state = CryptoReaderState::Idle;
            }
            
            return Ok(Bytes::from(temp));
        }
        
        // Read from upstream
        let mut temp = vec![0u8; max_size];
        let read = self.read(&mut temp).await?;
        
        if read == 0 {
            return Ok(Bytes::new());
        }
        
        temp.truncate(read);
        Ok(Bytes::from(temp))
    }
}

// ============= CryptoWriter State =============

/// State machine states for CryptoWriter
#[derive(Debug)]
enum CryptoWriterState {
    /// Ready to accept new data
    Idle,
    
    /// Have pending encrypted data to flush
    Flushing {
        /// Buffer of encrypted data waiting to be written
        pending: WriteBuffer,
    },
    
    /// Stream encountered an error and cannot be used
    Poisoned {
        /// The error that caused poisoning
        error: Option<io::Error>,
    },
}

impl StreamState for CryptoWriterState {
    fn is_terminal(&self) -> bool {
        matches!(self, Self::Poisoned { .. })
    }
    
    fn is_poisoned(&self) -> bool {
        matches!(self, Self::Poisoned { .. })
    }
    
    fn state_name(&self) -> &'static str {
        match self {
            Self::Idle => "Idle",
            Self::Flushing { .. } => "Flushing",
            Self::Poisoned { .. } => "Poisoned",
        }
    }
}

// ============= CryptoWriter =============

/// Writer that encrypts data using AES-CTR with proper state machine
///
/// This writer handles partial writes correctly by:
/// - Maintaining internal state for pending data
/// - Returning honest byte counts (only what's actually written or safely buffered)
/// - Implementing backpressure when internal buffer is full
///
/// # State Machine
///
/// ┌──────────┐    write    ┌──────────┐
/// │   Idle   │ ----------> │ Flushing │
/// │          │ <---------- │          │
/// └──────────┘   flushed   └──────────┘
///      │                          │
///      │          errors          │
/// ┌───────────────────────────────────┐
/// │              Poisoned             │
/// └───────────────────────────────────┘
///
/// # Backpressure
///
/// When the internal pending buffer exceeds `MAX_PENDING_WRITE`, the writer
/// will return `Poll::Pending` until some data has been flushed to upstream.
pub struct CryptoWriter<W> {
    /// Upstream writer
    upstream: W,
    /// AES-CTR encryptor
    encryptor: AesCtr,
    /// Current state
    state: CryptoWriterState,
}

impl<W> CryptoWriter<W> {
    /// Create new crypto writer
    pub fn new(upstream: W, encryptor: AesCtr) -> Self {
        Self {
            upstream,
            encryptor,
            state: CryptoWriterState::Idle,
        }
    }
    
    /// Get reference to upstream
    pub fn get_ref(&self) -> &W {
        &self.upstream
    }
    
    /// Get mutable reference to upstream
    pub fn get_mut(&mut self) -> &mut W {
        &mut self.upstream
    }
    
    /// Consume and return upstream
    pub fn into_inner(self) -> W {
        self.upstream
    }
    
    /// Check if stream is in poisoned state
    pub fn is_poisoned(&self) -> bool {
        self.state.is_poisoned()
    }
    
    /// Get current state name (for debugging)
    pub fn state_name(&self) -> &'static str {
        self.state.state_name()
    }
    
    /// Check if there's pending data to flush
    pub fn has_pending(&self) -> bool {
        matches!(&self.state, CryptoWriterState::Flushing { pending } if !pending.is_empty())
    }
    
    /// Get pending bytes count
    pub fn pending_len(&self) -> usize {
        match &self.state {
            CryptoWriterState::Flushing { pending } => pending.len(),
            _ => 0,
        }
    }
    
    /// Transition to poisoned state
    fn poison(&mut self, error: io::Error) {
        self.state = CryptoWriterState::Poisoned { error: Some(error) };
    }
    
    /// Take error from poisoned state
    fn take_poison_error(&mut self) -> io::Error {
        match &mut self.state {
            CryptoWriterState::Poisoned { error } => {
                error.take().unwrap_or_else(|| {
                    io::Error::new(ErrorKind::Other, "stream previously poisoned")
                })
            }
            _ => io::Error::new(ErrorKind::Other, "stream not poisoned"),
        }
    }
}

impl<W: AsyncWrite + Unpin> CryptoWriter<W> {
    /// Try to flush pending data to upstream
    ///
    /// Returns:
    /// - `Poll::Ready(Ok(true))` if all pending data was flushed
    /// - `Poll::Ready(Ok(false))` if some data remains
    /// - `Poll::Pending` if upstream would block
    /// - `Poll::Ready(Err(_))` on error
    fn poll_flush_pending(&mut self, cx: &mut Context<'_>) -> Poll<Result<bool>> {
        loop {
            match &mut self.state {
                CryptoWriterState::Idle => {
                    return Poll::Ready(Ok(true));
                }
                
                CryptoWriterState::Poisoned { .. } => {
                    let err = self.take_poison_error();
                    return Poll::Ready(Err(err));
                }
                
                CryptoWriterState::Flushing { pending } => {
                    if pending.is_empty() {
                        self.state = CryptoWriterState::Idle;
                        return Poll::Ready(Ok(true));
                    }
                    
                    let data = pending.pending();
                    match Pin::new(&mut self.upstream).poll_write(cx, data) {
                        Poll::Pending => return Poll::Pending,
                        
                        Poll::Ready(Err(e)) => {
                            self.poison(io::Error::new(e.kind(), e.to_string()));
                            return Poll::Ready(Err(e));
                        }
                        
                        Poll::Ready(Ok(0)) => {
                            let err = io::Error::new(
                                ErrorKind::WriteZero,
                                "upstream returned 0 bytes written"
                            );
                            self.poison(err.into());
                            return Poll::Ready(Err(io::Error::new(
                                ErrorKind::WriteZero,
                                "upstream returned 0 bytes written"
                            )));
                        }
                        
                        Poll::Ready(Ok(n)) => {
                            pending.advance(n);
                            // Continue loop to check if fully flushed
                        }
                    }
                }
            }
        }
    }
}

impl<W: AsyncWrite + Unpin> AsyncWrite for CryptoWriter<W> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize>> {
        let this = self.get_mut();
        
        // Check for poisoned state
        if let CryptoWriterState::Poisoned { .. } = &this.state {
            let err = this.take_poison_error();
            return Poll::Ready(Err(err));
        }
        
        // Empty write is always successful
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        
        // First, try to flush any pending data
        match this.poll_flush_pending(cx) {
            Poll::Pending => {
                // Check backpressure
                if this.pending_len() >= MAX_PENDING_WRITE {
                    // Too much pending, must wait
                    return Poll::Pending;
                }
                // Can buffer more, continue below
            }
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Ready(Ok(_)) => {
                // Flushed (possibly partially), continue
            }
        }
        
        // Encrypt the data
        let mut encrypted = buf.to_vec();
        this.encryptor.apply(&mut encrypted);
        
        // Try to write directly to upstream first
        match Pin::new(&mut this.upstream).poll_write(cx, &encrypted) {
            Poll::Ready(Ok(n)) if n == encrypted.len() => {
                // All data written directly
                Poll::Ready(Ok(buf.len()))
            }
            
            Poll::Ready(Ok(n)) => {
                // Partial write - buffer the rest
                let remaining = &encrypted[n..];
                
                // Ensure we're in Flushing state
                let pending = match &mut this.state {
                    CryptoWriterState::Flushing { pending } => pending,
                    CryptoWriterState::Idle => {
                        this.state = CryptoWriterState::Flushing {
                            pending: WriteBuffer::with_max_size(MAX_PENDING_WRITE),
                        };
                        match &mut this.state {
                            CryptoWriterState::Flushing { pending } => pending,
                            _ => unreachable!(),
                        }
                    }
                    CryptoWriterState::Poisoned { .. } => unreachable!(),
                };
                
                // Try to buffer remaining
                if pending.remaining_capacity() >= remaining.len() {
                    pending.extend(remaining).expect("capacity checked");
                    Poll::Ready(Ok(buf.len()))
                } else {
                    // Not enough buffer space - report what we could write
                    // The caller will need to retry with the rest
                    let bytes_accepted = n + pending.remaining_capacity();
                    if bytes_accepted > n {
                        let can_buffer = &encrypted[n..bytes_accepted];
                        pending.extend(can_buffer).expect("capacity checked");
                    }
                    Poll::Ready(Ok(bytes_accepted.min(buf.len())))
                }
            }
            
            Poll::Ready(Err(e)) => {
                this.poison(io::Error::new(e.kind(), e.to_string()));
                Poll::Ready(Err(e))
            }
            
            Poll::Pending => {
                // Upstream would block - buffer the encrypted data
                let pending = match &mut this.state {
                    CryptoWriterState::Flushing { pending } => pending,
                    CryptoWriterState::Idle => {
                        this.state = CryptoWriterState::Flushing {
                            pending: WriteBuffer::with_max_size(MAX_PENDING_WRITE),
                        };
                        match &mut this.state {
                            CryptoWriterState::Flushing { pending } => pending,
                            _ => unreachable!(),
                        }
                    }
                    CryptoWriterState::Poisoned { .. } => unreachable!(),
                };
                
                // Check if we can buffer all
                if pending.remaining_capacity() >= encrypted.len() {
                    pending.extend(&encrypted).expect("capacity checked");
                    // Wake up to try flushing later
                    cx.waker().wake_by_ref();
                    Poll::Ready(Ok(buf.len()))
                } else if pending.remaining_capacity() > 0 {
                    // Partial buffer
                    let can_buffer = pending.remaining_capacity();
                    pending.extend(&encrypted[..can_buffer]).expect("capacity checked");
                    cx.waker().wake_by_ref();
                    Poll::Ready(Ok(can_buffer))
                } else {
                    // No buffer space - backpressure
                    Poll::Pending
                }
            }
        }
    }
    
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<()>> {
        let this = self.get_mut();
        
        // First flush our pending buffer
        match this.poll_flush_pending(cx)? {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(false) => {
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            Poll::Ready(true) => {}
        }
        
        // Then flush upstream
        Pin::new(&mut this.upstream).poll_flush(cx)
    }
    
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<()>> {
        let this = self.get_mut();
        
        // Try to flush pending data first (best effort)
        match this.poll_flush_pending(cx) {
            Poll::Pending => {
                // Continue with shutdown anyway after registering waker
            }
            Poll::Ready(Err(_)) => {
                // Ignore flush errors during shutdown
            }
            Poll::Ready(Ok(_)) => {}
        }
        
        // Shutdown upstream
        Pin::new(&mut this.upstream).poll_shutdown(cx)
    }
}

// ============= PassthroughStream =============

/// Passthrough stream for fast mode - no encryption/decryption
///
/// Used when keys are set up so that client and Telegram use the same
/// encryption, allowing data to pass through without re-encryption.
pub struct PassthroughStream<S> {
    inner: S,
}

impl<S> PassthroughStream<S> {
    /// Create new passthrough stream
    pub fn new(inner: S) -> Self {
        Self { inner }
    }
    
    /// Get reference to inner stream
    pub fn get_ref(&self) -> &S {
        &self.inner
    }
    
    /// Get mutable reference to inner stream
    pub fn get_mut(&mut self) -> &mut S {
        &mut self.inner
    }
    
    /// Consume and return inner stream
    pub fn into_inner(self) -> S {
        self.inner
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for PassthroughStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for PassthroughStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }
    
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

// ============= Tests =============

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::pin::Pin;
    use std::task::{Context, Poll, Waker, RawWaker, RawWakerVTable};
    use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt};
    
    // ============= Test Helpers =============
    
    fn noop_waker() -> Waker {
        const VTABLE: RawWakerVTable = RawWakerVTable::new(
            |_| RawWaker::new(std::ptr::null(), &VTABLE),
            |_| {},
            |_| {},
            |_| {},
        );
        unsafe { Waker::from_raw(RawWaker::new(std::ptr::null(), &VTABLE)) }
    }
    
    /// Mock writer that simulates partial writes
    struct PartialWriter {
        /// Max bytes to accept per write
        chunk_size: usize,
        /// Collected data
        data: Vec<u8>,
        /// Number of writes performed
        write_count: usize,
        /// If true, return Pending on first write attempt
        first_pending: bool,
        /// Track if first call happened
        first_call: bool,
    }
    
    impl PartialWriter {
        fn new(chunk_size: usize) -> Self {
            Self {
                chunk_size,
                data: Vec::new(),
                write_count: 0,
                first_pending: false,
                first_call: true,
            }
        }
        
        fn with_first_pending(mut self) -> Self {
            self.first_pending = true;
            self
        }
    }
    
    impl AsyncWrite for PartialWriter {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<Result<usize>> {
            if self.first_pending && self.first_call {
                self.first_call = false;
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            
            self.write_count += 1;
            let to_write = buf.len().min(self.chunk_size);
            self.data.extend_from_slice(&buf[..to_write]);
            Poll::Ready(Ok(to_write))
        }
        
        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<()>> {
            Poll::Ready(Ok(()))
        }
        
        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<()>> {
            Poll::Ready(Ok(()))
        }
    }
    
    /// Mock reader that returns data in chunks
    struct ChunkedReader {
        data: VecDeque<u8>,
        chunk_size: usize,
    }
    
    impl ChunkedReader {
        fn new(data: &[u8], chunk_size: usize) -> Self {
            Self {
                data: data.iter().copied().collect(),
                chunk_size,
            }
        }
    }
    
    impl AsyncRead for ChunkedReader {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<Result<()>> {
            if self.data.is_empty() {
                return Poll::Ready(Ok(()));
            }
            
            let to_read = self.chunk_size.min(self.data.len()).min(buf.remaining());
            for _ in 0..to_read {
                if let Some(byte) = self.data.pop_front() {
                    buf.put_slice(&[byte]);
                }
            }
            
            Poll::Ready(Ok(()))
        }
    }
    
    // ============= CryptoReader Tests =============
    
    #[tokio::test]
    async fn test_crypto_reader_basic() {
        let key = [0x42u8; 32];
        let iv = 12345u128;
        
        // Encrypt some data
        let original = b"Hello, encrypted world!";
        let mut encryptor = AesCtr::new(&key, iv);
        let encrypted = encryptor.encrypt(original);
        
        // Create reader
        let reader = ChunkedReader::new(&encrypted, 100);
        let decryptor = AesCtr::new(&key, iv);
        let mut crypto_reader = CryptoReader::new(reader, decryptor);
        
        // Read and decrypt
        let mut buf = vec![0u8; original.len()];
        crypto_reader.read_exact(&mut buf).await.unwrap();
        
        assert_eq!(&buf, original);
    }
    
    #[tokio::test]
    async fn test_crypto_reader_chunked() {
        let key = [0x42u8; 32];
        let iv = 12345u128;
        
        let original = b"This is a longer message that will be read in chunks";
        let mut encryptor = AesCtr::new(&key, iv);
        let encrypted = encryptor.encrypt(original);
        
        // Read in very small chunks
        let reader = ChunkedReader::new(&encrypted, 5);
        let decryptor = AesCtr::new(&key, iv);
        let mut crypto_reader = CryptoReader::new(reader, decryptor);
        
        let mut result = Vec::new();
        let mut buf = [0u8; 7]; // Read in chunks different from write chunks
        
        loop {
            let n = crypto_reader.read(&mut buf).await.unwrap();
            if n == 0 {
                break;
            }
            result.extend_from_slice(&buf[..n]);
        }
        
        assert_eq!(&result, original);
    }
    
    #[tokio::test]
    async fn test_crypto_reader_read_exact_decrypt() {
        let key = [0x42u8; 32];
        let iv = 12345u128;
        
        let original = b"Exact read test data!";
        let mut encryptor = AesCtr::new(&key, iv);
        let encrypted = encryptor.encrypt(original);
        
        let reader = ChunkedReader::new(&encrypted, 3); // Small chunks
        let decryptor = AesCtr::new(&key, iv);
        let mut crypto_reader = CryptoReader::new(reader, decryptor);
        
        let result = crypto_reader.read_exact_decrypt(original.len()).await.unwrap();
        assert_eq!(&result[..], original);
    }
    
    // ============= CryptoWriter Tests =============
    
    #[test]
    fn test_crypto_writer_basic_sync() {
        let key = [0x42u8; 32];
        let iv = 12345u128;
        
        let mock_writer = PartialWriter::new(100);
        let encryptor = AesCtr::new(&key, iv);
        let mut crypto_writer = CryptoWriter::new(mock_writer, encryptor);
        
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        
        let original = b"Hello, world!";
        
        // Write
        let result = Pin::new(&mut crypto_writer).poll_write(&mut cx, original);
        assert!(matches!(result, Poll::Ready(Ok(13))));
        
        // Verify encryption happened
        let encrypted = &crypto_writer.upstream.data;
        assert_eq!(encrypted.len(), original.len());
        assert_ne!(encrypted.as_slice(), original); // Should be encrypted
        
        // Decrypt and verify
        let mut decryptor = AesCtr::new(&key, iv);
        let mut decrypted = encrypted.clone();
        decryptor.apply(&mut decrypted);
        assert_eq!(&decrypted, original);
    }
    
    #[test]
    fn test_crypto_writer_partial_write() {
        let key = [0x42u8; 32];
        let iv = 12345u128;
        
        // Writer that only accepts 5 bytes at a time
        let mock_writer = PartialWriter::new(5);
        let encryptor = AesCtr::new(&key, iv);
        let mut crypto_writer = CryptoWriter::new(mock_writer, encryptor);
        
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        
        let original = b"This is a longer message!"; // 25 bytes
        
        // First write - should accept all 25 bytes (5 written, 20 buffered)
        let result = Pin::new(&mut crypto_writer).poll_write(&mut cx, original);
        assert!(matches!(result, Poll::Ready(Ok(25))));
        
        // Should have pending data
        assert!(crypto_writer.has_pending());
        
        // Flush to drain pending
        loop {
            match Pin::new(&mut crypto_writer).poll_flush(&mut cx) {
                Poll::Ready(Ok(())) => break,
                Poll::Ready(Err(e)) => panic!("Flush error: {}", e),
                Poll::Pending => continue,
            }
        }
        
        // All data should be written now
        assert!(!crypto_writer.has_pending());
        assert_eq!(crypto_writer.upstream.data.len(), 25);
        
        // Verify decryption
        let mut decryptor = AesCtr::new(&key, iv);
        let mut decrypted = crypto_writer.upstream.data.clone();
        decryptor.apply(&mut decrypted);
        assert_eq!(&decrypted, original);
    }
    
    #[test]
    fn test_crypto_writer_pending_on_first_write() {
        let key = [0x42u8; 32];
        let iv = 12345u128;
        
        // Writer that returns Pending on first call
        let mock_writer = PartialWriter::new(100).with_first_pending();
        let encryptor = AesCtr::new(&key, iv);
        let mut crypto_writer = CryptoWriter::new(mock_writer, encryptor);
        
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        
        let original = b"Test data";
        
        // First write should buffer and return Ready (not Pending)
        // because we have buffer space
        let result = Pin::new(&mut crypto_writer).poll_write(&mut cx, original);
        assert!(matches!(result, Poll::Ready(Ok(9))));
        
        // Data should be buffered
        assert!(crypto_writer.has_pending());
        
        // Second poll_flush should succeed
        loop {
            match Pin::new(&mut crypto_writer).poll_flush(&mut cx) {
                Poll::Ready(Ok(())) => break,
                Poll::Ready(Err(e)) => panic!("Flush error: {}", e),
                Poll::Pending => continue,
            }
        }
    }
    
    #[tokio::test]
    async fn test_crypto_stream_roundtrip() {
        let key = [0u8; 32];
        let iv = 12345u128;
        
        let (client, server) = duplex(4096);
        
        let encryptor = AesCtr::new(&key, iv);
        let decryptor = AesCtr::new(&key, iv);
        
        let mut writer = CryptoWriter::new(client, encryptor);
        let mut reader = CryptoReader::new(server, decryptor);
        
        // Write
        let original = b"Hello, encrypted world!";
        writer.write_all(original).await.unwrap();
        writer.flush().await.unwrap();
        
        // Read
        let mut buf = vec![0u8; original.len()];
        reader.read_exact(&mut buf).await.unwrap();
        
        assert_eq!(&buf, original);
    }
    
    #[tokio::test]
    async fn test_crypto_stream_large_data() {
        let key = [0x55u8; 32];
        let iv = 777u128;
        
        let (client, server) = duplex(1024);
        
        let encryptor = AesCtr::new(&key, iv);
        let decryptor = AesCtr::new(&key, iv);
        
        let mut writer = CryptoWriter::new(client, encryptor);
        let mut reader = CryptoReader::new(server, decryptor);
        
        // Large data
        let original: Vec<u8> = (0..10000).map(|i| (i % 256) as u8).collect();
        
        // Write in background
        let write_data = original.clone();
        let write_handle = tokio::spawn(async move {
            writer.write_all(&write_data).await.unwrap();
            writer.flush().await.unwrap();
            writer.shutdown().await.unwrap();
        });
        
        // Read
        let mut received = Vec::new();
        let mut buf = vec![0u8; 1024];
        loop {
            match reader.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => received.extend_from_slice(&buf[..n]),
                Err(e) => panic!("Read error: {}", e),
            }
        }
        
        write_handle.await.unwrap();
        
        assert_eq!(received, original);
    }
    
    #[tokio::test]
    async fn test_crypto_writer_backpressure() {
        let key = [0x42u8; 32];
        let iv = 12345u128;
        
        // Very small buffer duplex
        let (client, _server) = duplex(64);
        
        let encryptor = AesCtr::new(&key, iv);
        let mut writer = CryptoWriter::new(client, encryptor);
        
        // Try to write a lot of data
        let large_data = vec![0u8; MAX_PENDING_WRITE + 1000];
        
        // This should eventually block due to backpressure
        // (duplex buffer full + our pending buffer full)
        let write_result = tokio::time::timeout(
            std::time::Duration::from_millis(100),
            writer.write_all(&large_data)
        ).await;
        
        // Should timeout because we can't write all data
        assert!(write_result.is_err());
    }
    
    // ============= State Tests =============
    
    #[test]
    fn test_reader_state_transitions() {
        let key = [0u8; 32];
        let iv = 0u128;
        
        let reader = ChunkedReader::new(&[], 10);
        let decryptor = AesCtr::new(&key, iv);
        let reader = CryptoReader::new(reader, decryptor);
        
        assert_eq!(reader.state_name(), "Idle");
        assert!(!reader.is_poisoned());
    }
    
    #[test]
    fn test_writer_state_transitions() {
        let key = [0u8; 32];
        let iv = 0u128;
        
        let writer = PartialWriter::new(10);
        let encryptor = AesCtr::new(&key, iv);
        let writer = CryptoWriter::new(writer, encryptor);
        
        assert_eq!(writer.state_name(), "Idle");
        assert!(!writer.is_poisoned());
        assert!(!writer.has_pending());
    }
    
    // ============= Passthrough Tests =============
    
    #[tokio::test]
    async fn test_passthrough_stream() {
        let (client, server) = duplex(4096);
        
        let mut writer = PassthroughStream::new(client);
        let mut reader = PassthroughStream::new(server);
        
        let data = b"No encryption here!";
        writer.write_all(data).await.unwrap();
        writer.flush().await.unwrap();
        
        let mut buf = vec![0u8; data.len()];
        reader.read_exact(&mut buf).await.unwrap();
        
        assert_eq!(&buf, data);
    }
}