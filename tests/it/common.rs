//! Shared harness for the integration suites.
//!
//! Every suite here needs the same three things: bind a loopback port, run a [`Server`] on it,
//! and point a `reqwest` client at it. [`TestServer`] owns that, so the suites are left holding
//! only what they actually assert.
//!
//! # No startup sleeps
//!
//! These helpers do not sleep after spawning. A `TcpListener` is bound *and listening* by the
//! time `bind` returns, so the kernel queues client connections into the backlog whether or not
//! the server task has been polled yet; the accept loop drains them when it first runs. Only an
//! entry point that binds its own listener internally needs waiting — [`wait_until_listening`]
//! polls for that rather than guessing a fixed delay.

#![allow(dead_code)]
#![allow(clippy::redundant_pub_crate)]

use reqwest::{Client, RequestBuilder};
use std::net::SocketAddr;
use std::time::Duration;
use tachyon_web::{Router, Server};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

/// A [`Server`] running on loopback for the lifetime of the value, plus a client pointed at it.
///
/// The server task is aborted on drop, so a test can't leak an accept loop into the rest of
/// the run.
pub(crate) struct TestServer {
    addr: SocketAddr,
    client: Client,
    task: JoinHandle<()>,
}

impl Drop for TestServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl TestServer {
    /// Serves `router` over plaintext HTTP on an OS-assigned loopback port.
    pub(crate) async fn spawn(router: Router<()>) -> Self {
        Self::spawn_inner(router, |server| server, Client::new()).await
    }

    /// As [`spawn`](Self::spawn), with a chance to configure the [`Server`] first (e.g.
    /// `.max_body_size(..)`).
    pub(crate) async fn spawn_with(
        router: Router<()>,
        configure: impl FnOnce(Server<()>) -> Server<()>,
    ) -> Self {
        Self::spawn_inner(router, configure, Client::new()).await
    }

    /// As [`spawn`](Self::spawn), but with a client that persists cookies across requests.
    pub(crate) async fn spawn_with_cookie_store(router: Router<()>) -> Self {
        let client = Client::builder()
            .cookie_store(true)
            .build()
            .expect("build cookie-store client");
        Self::spawn_inner(router, |server| server, client).await
    }

    async fn spawn_inner(
        router: Router<()>,
        configure: impl FnOnce(Server<()>) -> Server<()>,
        client: Client,
    ) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("local_addr");
        let server = configure(Server::new(router));
        let task = tokio::spawn(async move {
            let _ = server.serve_http(listener).await;
        });
        Self { addr, client, task }
    }

    /// The address the server is listening on.
    pub(crate) const fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// The client pointed at this server.
    pub(crate) const fn client(&self) -> &Client {
        &self.client
    }

    /// An absolute `http://` URL for `path` on this server.
    pub(crate) fn url(&self, path: &str) -> String {
        format!("http://{}{path}", self.addr)
    }

    /// A `GET` request builder for `path`.
    pub(crate) fn get(&self, path: &str) -> RequestBuilder {
        self.client.get(self.url(path))
    }

    /// A `POST` request builder for `path`.
    pub(crate) fn post(&self, path: &str) -> RequestBuilder {
        self.client.post(self.url(path))
    }
}

/// Binds an ephemeral port, immediately frees it, and returns the `SocketAddr` — for entry
/// points that take an address (rather than a pre-bound listener) and bind it themselves.
pub(crate) async fn free_loopback_addr() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind ephemeral port");
    let addr = listener.local_addr().expect("local addr");
    drop(listener);
    addr
}

/// Waits until something is accepting connections on `addr`, polling rather than sleeping a
/// fixed guess. Panics if nothing comes up within a few seconds.
pub(crate) async fn wait_until_listening(addr: SocketAddr) {
    const ATTEMPTS: u32 = 200;
    for _ in 0..ATTEMPTS {
        if tokio::net::TcpStream::connect(addr).await.is_ok() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("nothing started listening on {addr} within {ATTEMPTS} attempts");
}

/// A `reqwest` client that accepts the self-signed certificates these tests generate.
#[cfg(feature = "tls")]
pub(crate) fn tls_client() -> Client {
    Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .expect("build TLS test client")
}
