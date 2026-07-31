//! Golden-response parity: Server-Sent Events (`Sse`/`Event`/`KeepAlive`).

use axum::routing::get as axum_get;
use parity_tests::{assert_same_response, get_req as get};
use std::convert::Infallible;
use tachyon_web::{get as t_get, Router};
use tokio_stream::Stream;

#[tokio::test]
async fn sse_stream_wire_format_matches() {
    async fn axum_handler(
    ) -> axum::response::Sse<impl Stream<Item = Result<axum::response::sse::Event, Infallible>>>
    {
        let events = vec![
            Ok(axum::response::sse::Event::default().data("first")),
            Ok(axum::response::sse::Event::default()
                .event("update")
                .data("second")),
        ];
        axum::response::Sse::new(tokio_stream::iter(events))
    }

    async fn tachyon_handler() -> tachyon_web::response::sse::Sse<
        impl Stream<Item = Result<tachyon_web::response::sse::Event, Infallible>>,
    > {
        let events = vec![
            Ok(tachyon_web::response::sse::Event::new().data("first")),
            Ok(tachyon_web::response::sse::Event::new()
                .event("update")
                .data("second")),
        ];
        tachyon_web::response::sse::Sse::new(tokio_stream::iter(events))
    }

    let axum_app = axum::Router::new().route("/events", axum_get(axum_handler));
    let tachyon_app = Router::new().route("/events", t_get(tachyon_handler));

    assert_same_response(axum_app, tachyon_app, || get("/events")).await;
}
