#![allow(missing_docs)]
#![allow(clippy::unwrap_used)]

#[macro_use]
extern crate rocket;
use rocket::serde::json::Json;
use serde::Serialize;

#[derive(Serialize)]
struct Message {
    message: &'static str,
}

#[get("/")]
fn plaintext() -> &'static str {
    "Hello, World!"
}

#[get("/json")]
fn json() -> Json<Message> {
    Json(Message {
        message: "Hello, World!",
    })
}

#[launch]
fn rocket() -> _ {
    let config = rocket::Config::figment()
        .merge(("port", 8083))
        .merge(("address", "127.0.0.1"))
        .merge(("log_level", rocket::config::LogLevel::Off));
    rocket::custom(config).mount("/", routes![plaintext, json])
}
