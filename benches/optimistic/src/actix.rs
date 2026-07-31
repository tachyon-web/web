#![allow(missing_docs)]
#![allow(clippy::unwrap_used)]

use actix_web::{App, HttpResponse, HttpServer, Responder, get};
use serde::Serialize;

#[derive(Serialize)]
struct Message {
    message: &'static str,
}

#[get("/")]
async fn plaintext() -> impl Responder {
    HttpResponse::Ok().body("Hello, World!")
}

#[get("/json")]
async fn json() -> impl Responder {
    HttpResponse::Ok().json(Message {
        message: "Hello, World!",
    })
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    println!("Actix server listening on 127.0.0.1:8082");
    HttpServer::new(|| App::new().service(plaintext).service(json))
        .bind(("127.0.0.1", 8082))?
        .run()
        .await
}
