#![allow(missing_docs)]
#![allow(clippy::unwrap_used)]

#[macro_use]
extern crate rocket;
use rocket::fs::FileServer;

#[launch]
fn rocket() -> _ {
    let config = rocket::Config::figment()
        .merge(("port", 8083))
        .merge(("address", "127.0.0.1"))
        .merge(("log_level", rocket::config::LogLevel::Off));
    rocket::custom(config).mount("/", FileServer::from("benches/static/public"))
}
