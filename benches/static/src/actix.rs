#![allow(missing_docs)]
#![allow(clippy::unwrap_used)]

use actix_files::Files;
use actix_web::{App, HttpServer};

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    println!("Actix static server on 127.0.0.1:8082");
    HttpServer::new(|| {
        App::new().service(Files::new("/", "benches/static/public").index_file("index.html"))
    })
    .bind(("127.0.0.1", 8082))?
    .run()
    .await
}
