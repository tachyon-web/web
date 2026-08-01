use crate::common::TestServer;
use std::fs;
use tachyon_web::{Router, ServeDir};

#[tokio::test]
async fn test_static_dir_serving() {
    // A `tempfile` dir rather than a fixed path under the system temp dir: the fixed path
    // was shared by every concurrent run of this test (and left behind on failure), so two
    // runs at once raced over the same files.
    let dir = tempfile::tempdir().expect("tempdir");
    fs::write(dir.path().join("index.html"), "<h1>Home</h1>").expect("write html");
    fs::write(dir.path().join("style.css"), "body { color: red; }").expect("write css");

    let static_service = ServeDir::new(dir.path())
        .index("index.html")
        .preload()
        .await
        .expect("preload");

    // Serve at / — root → index.html, /style.css → style.css
    let app: Router<()> = Router::new().serve_dir("/", static_service);
    let server = TestServer::spawn(app).await;

    for (path, expected_type, expected_body) in [
        ("/", "text/html", "<h1>Home</h1>"),
        ("/style.css", "text/css", "body { color: red; }"),
    ] {
        let res = server.get(path).send().await.expect("request");
        assert_eq!(res.status(), 200, "path: {path}");
        let content_type = res
            .headers()
            .get("content-type")
            .expect("content-type")
            .to_str()
            .expect("utf-8 content-type")
            .to_owned();
        assert!(
            content_type.starts_with(expected_type),
            "path: {path}, content-type: {content_type}"
        );
        assert_eq!(res.text().await.unwrap(), expected_body, "path: {path}");
    }

    let res = server.get("/missing.js").send().await.expect("get missing");
    assert_eq!(res.status(), 404);
}
