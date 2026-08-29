//! repro
use tachyon_web::{get, Router, Server};

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    println!("addr={addr}");

    let router = Router::new().route("/", get(|| async { "ok-str" }));
    let server = Server::new(router);
    let addr_str = addr.to_string();
    tokio::spawn(async move {
        let _ = server.start_http(&addr_str).await;
    });

    println!("connecting via raw tokio...");
    loop {
        if tokio::net::TcpStream::connect(addr).await.is_ok() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    println!("raw tokio connect OK");

    println!("connecting via reqwest...");
    let client = reqwest::Client::new();
    let url = format!("http://{addr}/");
    let res =
        tokio::time::timeout(std::time::Duration::from_secs(5), client.get(&url).send()).await;
    match res {
        Ok(Ok(r)) => println!("reqwest OK: {}", r.status()),
        Ok(Err(e)) => println!("reqwest error: {e:?}"),
        Err(_) => println!("reqwest TIMED OUT"),
    }
}
