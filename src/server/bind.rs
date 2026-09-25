//! [`Bind`]: where a clearnet listener listens.

use tokio::net::TcpListener;

/// Where a clearnet transport listens: an address to bind when the server starts, or a
/// listener the caller already bound.
///
/// Built implicitly from `&str`/`String` (`"0.0.0.0:443"`, `"localhost:8080"`), a
/// [`SocketAddr`](std::net::SocketAddr), or a [`TcpListener`].
#[derive(Debug)]
pub struct Bind(Inner);

#[derive(Debug)]
enum Inner {
    Addr(String),
    Listener(TcpListener),
}

impl Bind {
    pub(crate) async fn listen(self) -> Result<TcpListener, crate::Error> {
        match self.0 {
            Inner::Listener(listener) => Ok(listener),
            Inner::Addr(addr) => TcpListener::bind(&addr)
                .await
                .map_err(|source| crate::Error::Bind { addr, source }),
        }
    }
}

impl From<&str> for Bind {
    fn from(addr: &str) -> Self {
        Self(Inner::Addr(addr.to_string()))
    }
}

impl From<String> for Bind {
    fn from(addr: String) -> Self {
        Self(Inner::Addr(addr))
    }
}

impl From<std::net::SocketAddr> for Bind {
    fn from(addr: std::net::SocketAddr) -> Self {
        Self(Inner::Addr(addr.to_string()))
    }
}

impl From<TcpListener> for Bind {
    fn from(listener: TcpListener) -> Self {
        Self(Inner::Listener(listener))
    }
}
