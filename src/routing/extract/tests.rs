//! Test suite for the `extract` module split across path.rs / query.rs / body.rs / parts.rs / ext.rs.

#![allow(clippy::unwrap_used)]
use super::*;
use bytes::Bytes;
use hyper::header::HeaderMap;
use hyper::http::Request;
use hyper::{Method, StatusCode, Uri};
use serde::Deserialize;
use std::convert::Infallible;

#[cfg(feature = "json")]
use crate::routing::extract::body::is_json_content_type;
use crate::routing::extract::path::PathDeserializer;
#[cfg(any(feature = "query", feature = "form"))]
use crate::routing::extract::query::QueryIter;

#[tokio::test]
async fn add_extension_layer_inserts_the_bound_value_into_every_request() {
    #[derive(Clone, PartialEq, Debug)]
    struct Shared(u32);

    struct Echo;
    impl tower::Service<hyper::Request<Body>> for Echo {
        type Response = Option<Shared>;
        type Error = Infallible;
        type Future = std::future::Ready<Result<Self::Response, Self::Error>>;

        fn poll_ready(
            &mut self,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Result<(), Self::Error>> {
            std::task::Poll::Ready(Ok(()))
        }

        fn call(&mut self, req: hyper::Request<Body>) -> Self::Future {
            std::future::ready(Ok(req.extensions().get::<Shared>().cloned()))
        }
    }

    let mut svc = tower::Layer::layer(&Extension(Shared(42)), Echo);
    let req = Request::builder().body(Body::empty()).unwrap();
    let seen = tower::Service::call(&mut svc, req).await.unwrap();
    assert_eq!(seen, Some(Shared(42)));
}

#[tokio::test]
async fn option_extractor_is_some_on_success_and_none_on_rejection() {
    let mut present = Request::builder().body(()).unwrap().into_parts().0;
    present.extensions.insert(7u32);
    let ext_or_none = Option::<Extension<u32>>::from_request_parts(&mut present, &())
        .await
        .unwrap();
    assert_eq!(ext_or_none.map(|Extension(v)| v), Some(7));

    let mut absent = Request::builder().body(()).unwrap().into_parts().0;
    let none = Option::<Extension<u32>>::from_request_parts(&mut absent, &())
        .await
        .unwrap();
    assert!(none.is_none());
}

#[tokio::test]
async fn request_ext_extract_parts_preserves_the_body() {
    let req = Request::builder()
        .uri("/x?a=1")
        .body(Body::full(Bytes::from("payload")))
        .unwrap();
    let mut req = req;
    let RawQuery(q) = req.extract_parts::<RawQuery>().await.unwrap();
    assert_eq!(q.as_deref(), Some("a=1"));
    // The body must still be there after `extract_parts` returns.
    let bytes = req.into_body().collect_bytes(1024).await.unwrap();
    assert_eq!(bytes.as_ref(), b"payload");
}

#[tokio::test]
async fn request_parts_ext_extract_runs_against_unit_state() {
    let mut parts = Request::builder()
        .uri("/x?a=1")
        .body(())
        .unwrap()
        .into_parts()
        .0;
    let RawQuery(q) = parts.extract::<RawQuery>().await.unwrap();
    assert_eq!(q.as_deref(), Some("a=1"));
}

#[cfg(any(feature = "query", feature = "form"))]
#[derive(Deserialize, Debug)]
#[allow(clippy::struct_excessive_bools)]
struct BigCoerce {
    a: u16,
    b: u64,
    c: i8,
    d: i16,
    e: i32,
    f: i64,
    g: f32,
    h: f64,
    i: bool,
    j: bool,
    k: bool,
    l: bool,
}

#[derive(Deserialize)]
#[allow(dead_code)]
struct BoolTest {
    val: bool,
}

#[derive(Deserialize, PartialEq, Debug)]
enum Color {
    Red,
    Blue,
}

#[cfg(any(feature = "query", feature = "form"))]
#[derive(Deserialize)]
struct EnumTest {
    val: Color,
}

#[cfg(any(feature = "query", feature = "form"))]
#[test]
fn test_coercing_cow_deserializer() {
    let query_str = "a=12&b=34&c=5&d=6&e=7&f=8&g=1.2&h=3.4&i=true&j=1&k=false&l=0";
    let iter = QueryIter { input: query_str };
    let map_de = serde::de::value::MapDeserializer::new(iter);
    let data = BigCoerce::deserialize(map_de).unwrap();
    assert_eq!(data.a, 12);
    assert_eq!(data.b, 34);
    assert_eq!(data.c, 5);
    assert_eq!(data.d, 6);
    assert_eq!(data.e, 7);
    assert_eq!(data.f, 8);
    assert!((data.g - 1.2).abs() < 0.001);
    assert!((data.h - 3.4).abs() < 0.001);
    assert!(data.i);
    assert!(data.j);
    assert!(!data.k);
    assert!(!data.l);

    // Test bool parse error
    let iter = QueryIter {
        input: "val=not_bool",
    };
    let map_de = serde::de::value::MapDeserializer::new(iter);
    assert!(BoolTest::deserialize(map_de).is_err());

    // Test enum deserialization
    let iter = QueryIter { input: "val=Red" };
    let map_de = serde::de::value::MapDeserializer::new(iter);
    let et = EnumTest::deserialize(map_de).unwrap();
    assert_eq!(et.val, Color::Red);
}

#[cfg(any(feature = "query", feature = "form"))]
#[test]
fn test_query_iter_edge_cases() {
    // Empty pair and key without value
    let query_str = "&&foo&&bar=baz";
    let mut iter = QueryIter { input: query_str };
    let first = iter.next().unwrap();
    assert_eq!(first.0, "foo");
    assert_eq!(first.1.val, "");
    let second = iter.next().unwrap();
    assert_eq!(second.0, "bar");
    assert_eq!(second.1.val, "baz");

    // Invalid percent decoding in query param
    let query_str2 = "foo=bar%xy&baz=%";
    let mut iter2 = QueryIter { input: query_str2 };
    let first2 = iter2.next().unwrap();
    assert_eq!(first2.0, "foo");
    assert_eq!(first2.1.val, "bar%xy");
    let second2 = iter2.next().unwrap();
    assert_eq!(second2.0, "baz");
    assert_eq!(second2.1.val, "%");
}

#[tokio::test]
async fn test_extractors_direct() {
    let req = Request::builder()
        .method("POST")
        .uri("/path?q=1")
        .header("x-test", "hello")
        .body(Body::full(Bytes::from("body_bytes")))
        .unwrap();
    let (mut parts, body) = req.into_parts();

    // HeaderMap
    let headers = HeaderMap::from_request_parts(&mut parts, &())
        .await
        .unwrap();
    assert_eq!(headers.get("x-test").unwrap(), "hello");

    // Method
    let method = Method::from_request_parts(&mut parts, &()).await.unwrap();
    assert_eq!(method, "POST");

    // Uri
    let uri = Uri::from_request_parts(&mut parts, &()).await.unwrap();
    assert_eq!(uri.path(), "/path");

    // Bytes
    let req_bytes = Request::from_parts(parts.clone(), Body::full(Bytes::from("body_bytes")));
    let bytes = Bytes::from_request(req_bytes, &()).await.unwrap();
    assert_eq!(bytes.as_ref(), b"body_bytes");

    // Request<Bytes>
    let req_full = Request::from_parts(parts, body);
    let extracted_req = <Request<Bytes>>::from_request(req_full, &()).await.unwrap();
    assert_eq!(extracted_req.uri().path(), "/path");
}

#[cfg(feature = "cookies")]
#[test]
fn test_cookies_remove() {
    use cookie::Cookie;
    let cookies = Cookies::new().add(Cookie::new("foo", "bar"));
    assert_eq!(cookies.get("foo").unwrap().value(), "bar");
    let cookies = cookies.remove(Cookie::new("foo", ""));
    assert!(cookies.get("foo").is_none());
}

#[tokio::test]
async fn test_host_missing() {
    let mut parts = Request::builder().uri("/").body(()).unwrap().into_parts().0;
    let res = Host::from_request_parts(&mut parts, &()).await;
    assert!(res.is_err());
}

#[tokio::test]
async fn test_connect_info_missing() {
    let mut parts = Request::builder().uri("/").body(()).unwrap().into_parts().0;
    let res = ConnectInfo::<std::net::SocketAddr>::from_request_parts(&mut parts, &()).await;
    assert!(res.is_err());
}

#[cfg(feature = "form")]
#[tokio::test]
async fn test_form_errors() {
    #[derive(Deserialize, Debug)]
    #[allow(dead_code)]
    struct FormPayload {
        foo: String,
    }

    // The method must be POST (or any non-GET/HEAD): `Form::from_request` delegates
    // GET/HEAD to the query-string path without ever reaching the Content-Type check.
    let req = Request::builder()
        .method("POST")
        .header(hyper::header::CONTENT_TYPE, "text/plain")
        .body(Body::full(Bytes::from("foo=bar")))
        .unwrap();
    let res = Form::<FormPayload>::from_request(req, &()).await;
    assert!(res.is_err());

    // Invalid UTF-8 body.
    let utf8_req = Request::builder()
        .method("POST")
        .header(
            hyper::header::CONTENT_TYPE,
            "application/x-www-form-urlencoded",
        )
        .body(Body::full(Bytes::from(vec![0xff, 0xff])))
        .unwrap();
    let utf8_result = Form::<FormPayload>::from_request(utf8_req, &()).await;
    assert!(utf8_result.is_err());

    // Invalid payload (missing required field).
    let payload_req = Request::builder()
        .method("POST")
        .header(
            hyper::header::CONTENT_TYPE,
            "application/x-www-form-urlencoded",
        )
        .body(Body::full(Bytes::from("not_valid")))
        .unwrap();
    let payload_result = Form::<FormPayload>::from_request(payload_req, &()).await;
    assert!(payload_result.is_err());
}

#[cfg(feature = "form")]
#[tokio::test]
async fn test_form_from_request_parts_deserialize_error() {
    #[derive(Deserialize, Debug)]
    #[allow(dead_code)]
    struct FormPayload {
        foo: String,
    }

    // The GET/HEAD "read from the query string" path (`FromRequestParts`), exercised
    // directly rather than via the `FromRequest::from_request` GET delegation, so it's
    // clear which branch is under test.
    let mut parts = Request::builder()
        .uri("/search?bar=baz")
        .body(())
        .unwrap()
        .into_parts()
        .0;
    let result = Form::<FormPayload>::from_request_parts(&mut parts, &()).await;
    assert!(result.is_err());
}

#[cfg(feature = "form")]
#[tokio::test]
async fn test_form_get_request_reads_from_query_string() {
    #[derive(Deserialize, Debug, PartialEq)]
    struct FormPayload {
        foo: String,
    }

    let req = Request::builder()
        .method("GET")
        .uri("/search?foo=bar")
        .body(Body::empty())
        .unwrap();
    let Form(payload) = Form::<FormPayload>::from_request(req, &()).await.unwrap();
    assert_eq!(
        payload,
        FormPayload {
            foo: "bar".to_string(),
        }
    );
}

#[cfg(feature = "form")]
#[tokio::test]
async fn test_raw_form_reads_query_on_get_and_body_on_post() {
    let get_req = Request::builder()
        .method("GET")
        .uri("/search?foo=bar")
        .body(Body::empty())
        .unwrap();
    let RawForm(query) = RawForm::from_request(get_req, &()).await.unwrap();
    assert_eq!(&query[..], b"foo=bar");

    let post_req = Request::builder()
        .method("POST")
        .header(
            hyper::header::CONTENT_TYPE,
            "application/x-www-form-urlencoded",
        )
        .body(Body::full(Bytes::from("foo=bar")))
        .unwrap();
    let RawForm(body) = RawForm::from_request(post_req, &()).await.unwrap();
    assert_eq!(&body[..], b"foo=bar");
}

#[cfg(feature = "form")]
#[tokio::test]
async fn test_raw_form_rejects_wrong_content_type_on_post() {
    let req = Request::builder()
        .method("POST")
        .body(Body::full(Bytes::from("foo=bar")))
        .unwrap();
    let err = RawForm::from_request(req, &()).await.unwrap_err();
    assert!(matches!(
        err,
        rejection::RawFormRejection::InvalidFormContentType(_)
    ));
}

#[cfg(feature = "query")]
#[tokio::test]
async fn test_query_deserialize_error() {
    #[derive(Deserialize, Debug)]
    #[allow(dead_code)]
    struct QueryPayload {
        foo: u32,
    }

    let mut parts = Request::builder()
        .uri("/?foo=not_a_number")
        .body(())
        .unwrap()
        .into_parts()
        .0;
    let result = Query::<QueryPayload>::from_request_parts(&mut parts, &()).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_raw_query_present_and_absent() {
    let mut with_query = Request::builder()
        .uri("/path?a=1&b=2")
        .body(())
        .unwrap()
        .into_parts()
        .0;
    let RawQuery(q) = RawQuery::from_request_parts(&mut with_query, &())
        .await
        .unwrap();
    assert_eq!(q.as_deref(), Some("a=1&b=2"));

    let mut without_query = Request::builder()
        .uri("/path")
        .body(())
        .unwrap()
        .into_parts()
        .0;
    let RawQuery(q2) = RawQuery::from_request_parts(&mut without_query, &())
        .await
        .unwrap();
    assert!(q2.is_none());
}

#[cfg(feature = "cookies")]
#[test]
fn test_cookies_default() {
    let cookies = Cookies::default();
    assert!(cookies.get("anything").is_none());
}

#[tokio::test]
async fn test_body_stream_from_request() {
    let req = Request::builder()
        .body(Body::full(Bytes::from("stream me")))
        .unwrap();
    let BodyStream(body) = BodyStream::from_request(req, &()).await.unwrap();
    let collected = body.collect_bytes(1024).await.unwrap();
    assert_eq!(collected.as_ref(), b"stream me");
}

#[cfg(feature = "json")]
#[test]
fn test_is_json_content_type_without_a_slash_is_rejected() {
    assert!(!is_json_content_type("not-a-media-type"));
}

// --- PathDeserializer coverage ---

fn make_path_parts(params: Vec<(&str, &str)>) -> hyper::http::request::Parts {
    let mut parts = Request::builder().body(()).unwrap().into_parts().0;
    let path_params = PathParams(
        params
            .into_iter()
            .map(|(k, v)| (std::sync::Arc::from(k), v.to_string()))
            .collect(),
    );
    parts.extensions.insert(path_params);
    parts
}

#[tokio::test]
async fn test_path_tuple_success_and_length_mismatch() {
    let mut ok_parts = make_path_parts(vec![("id", "42"), ("name", "hello")]);
    let Path((id, name)) =
        <Path<(u32, String)> as FromRequestParts<()>>::from_request_parts(&mut ok_parts, &())
            .await
            .unwrap();
    assert_eq!(id, 42);
    assert_eq!(name, "hello");

    // Too many params for a 2-tuple.
    let mut too_many = make_path_parts(vec![("a", "1"), ("b", "2"), ("c", "3")]);
    assert!(
        <Path<(u32, String)> as FromRequestParts<()>>::from_request_parts(&mut too_many, &())
            .await
            .is_err()
    );

    // Too few params for a 2-tuple.
    let mut too_few = make_path_parts(vec![("a", "1")]);
    assert!(
        <Path<(u32, String)> as FromRequestParts<()>>::from_request_parts(&mut too_few, &())
            .await
            .is_err()
    );
}

#[tokio::test]
async fn test_path_vec_seq_target() {
    // `Vec<T>` reaches `deserialize_seq` directly (not via tuple delegation),
    // and its `Deserialize` impl calls `SeqAccess::size_hint` to preallocate.
    let mut parts = make_path_parts(vec![("a", "x"), ("b", "y"), ("c", "z")]);
    let Path(values) =
        <Path<Vec<String>> as FromRequestParts<()>>::from_request_parts(&mut parts, &())
            .await
            .unwrap();
    assert_eq!(
        values,
        vec!["x".to_string(), "y".to_string(), "z".to_string()]
    );
}

#[tokio::test]
async fn test_raw_path_params_iterates_key_value_pairs_in_order() {
    let mut parts = make_path_parts(vec![("user_id", "1"), ("team_id", "2")]);
    let params = RawPathParams::from_request_parts(&mut parts, &())
        .await
        .unwrap();
    let collected: Vec<_> = params.iter().collect();
    assert_eq!(collected, vec![("user_id", "1"), ("team_id", "2")]);
}

#[tokio::test]
async fn test_raw_path_params_succeeds_empty_on_a_parameterless_route() {
    let mut parts = make_path_parts(vec![]);
    let params = RawPathParams::from_request_parts(&mut parts, &())
        .await
        .unwrap();
    assert_eq!(params.iter().count(), 0);
}

#[tokio::test]
async fn test_path_scalar_wrong_param_count() {
    // Zero params for a bare scalar target.
    let mut zero = make_path_parts(vec![]);
    assert!(
        <Path<u32> as FromRequestParts<()>>::from_request_parts(&mut zero, &())
            .await
            .is_err()
    );

    // More than one param for a bare scalar target.
    let mut two = make_path_parts(vec![("a", "1"), ("b", "2")]);
    assert!(
        <Path<u32> as FromRequestParts<()>>::from_request_parts(&mut two, &())
            .await
            .is_err()
    );

    // Exactly one param succeeds.
    let mut one = make_path_parts(vec![("id", "7")]);
    let Path(v) = <Path<u32> as FromRequestParts<()>>::from_request_parts(&mut one, &())
        .await
        .unwrap();
    assert_eq!(v, 7);
}

#[tokio::test]
async fn test_path_error_kind_pinpoints_the_failing_field_or_index() {
    #[derive(Debug, serde::Deserialize)]
    #[allow(dead_code)]
    struct Params {
        a: u32,
        b: u32,
    }

    let mut struct_target = make_path_parts(vec![("a", "1"), ("b", "not-a-number")]);
    let err = <Path<Params> as FromRequestParts<()>>::from_request_parts(&mut struct_target, &())
        .await
        .unwrap_err();
    let rejection::PathRejection::FailedToDeserializePathParams(err) = err else {
        panic!("expected FailedToDeserializePathParams");
    };
    assert_eq!(err.status(), StatusCode::BAD_REQUEST);
    assert!(matches!(
        err.into_kind(),
        rejection::ErrorKind::ParseErrorAtKey { key, expected_type: "u32", .. }
            if key == "b"
    ));

    let mut tuple_target = make_path_parts(vec![("a", "true"), ("b", "nope")]);
    let err =
        <Path<(bool, u32)> as FromRequestParts<()>>::from_request_parts(&mut tuple_target, &())
            .await
            .unwrap_err();
    let rejection::PathRejection::FailedToDeserializePathParams(err) = err else {
        panic!("expected FailedToDeserializePathParams");
    };
    assert!(matches!(
        err.into_kind(),
        rejection::ErrorKind::ParseErrorAtIndex {
            index: 1,
            expected_type: "u32",
            ..
        }
    ));

    let mut scalar_target = make_path_parts(vec![("id", "nope")]);
    let err = <Path<u32> as FromRequestParts<()>>::from_request_parts(&mut scalar_target, &())
        .await
        .unwrap_err();
    let rejection::PathRejection::FailedToDeserializePathParams(err) = err else {
        panic!("expected FailedToDeserializePathParams");
    };
    assert!(matches!(
        err.into_kind(),
        rejection::ErrorKind::ParseError {
            expected_type: "u32",
            ..
        }
    ));
}

#[tokio::test]
async fn test_path_option_top_level_target() {
    // `Path<Option<T>>` makes `Option<T>` the *whole* deserialization target, so
    // `T::deserialize` dispatches straight to `PathDeserializer::deserialize_option`
    // (as opposed to a struct field being `Option<T>`, which is handled entirely by
    // `MapDeserializer`/`CoercingCowDeserializer` without ever calling back into
    // `PathDeserializer::deserialize_option`).
    let mut parts = make_path_parts(vec![("id", "9")]);
    let Path(v) = <Path<Option<u32>> as FromRequestParts<()>>::from_request_parts(&mut parts, &())
        .await
        .unwrap();
    assert_eq!(v, Some(9));
}

#[tokio::test]
async fn test_path_enum_target() {
    let mut parts = make_path_parts(vec![("color", "Red")]);
    let Path(c) = <Path<Color> as FromRequestParts<()>>::from_request_parts(&mut parts, &())
        .await
        .unwrap();
    assert_eq!(c, Color::Red);
}

#[tokio::test]
async fn test_path_unit_and_unit_struct_targets() {
    #[derive(Deserialize, PartialEq, Debug)]
    struct UnitStruct;

    // `()` as the whole target reaches `deserialize_unit` and ignores any params.
    let mut parts = make_path_parts(vec![("a", "1"), ("b", "2")]);
    let Path(unit_val) = <Path<()> as FromRequestParts<()>>::from_request_parts(&mut parts, &())
        .await
        .unwrap();
    assert_eq!(unit_val, ());

    // A derived unit struct reaches `deserialize_unit_struct`.
    let mut empty_parts = make_path_parts(vec![]);
    let Path(u) =
        <Path<UnitStruct> as FromRequestParts<()>>::from_request_parts(&mut empty_parts, &())
            .await
            .unwrap();
    assert_eq!(u, UnitStruct);
}

#[tokio::test]
async fn test_path_newtype_struct_target() {
    #[derive(Deserialize, PartialEq, Debug)]
    struct Wrapper(u32);

    let mut parts = make_path_parts(vec![("id", "77")]);
    let Path(Wrapper(v)) =
        <Path<Wrapper> as FromRequestParts<()>>::from_request_parts(&mut parts, &())
            .await
            .unwrap();
    assert_eq!(v, 77);
}

#[tokio::test]
async fn test_path_ignored_any_top_level_target() {
    // `IgnoredAny`'s `Deserialize` impl calls `deserialize_ignored_any` directly on the
    // top-level deserializer.
    let mut parts = make_path_parts(vec![("a", "1"), ("b", "2")]);
    let result =
        <Path<serde::de::IgnoredAny> as FromRequestParts<()>>::from_request_parts(&mut parts, &())
            .await;
    assert!(result.is_ok());
}

struct IdentifierVisitor;

impl serde::de::Visitor<'_> for IdentifierVisitor {
    type Value = String;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a string identifier")
    }

    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(v.to_string())
    }
}

#[test]
fn test_path_deserializer_identifier_direct() {
    // No public `Deserialize` target routes into `PathDeserializer::deserialize_identifier`
    // through `Path<T>`: struct/map field names are resolved by the key type inside
    // `MapDeserializer` (a `Cow<str>`/`StrDeserializer`), and enum variant names are
    // resolved via `val.into_deserializer()` in `deserialize_enum` above — neither ever
    // hands control back to `PathDeserializer` itself. So this calls the trait method
    // directly on the (module-private) `PathDeserializer` to exercise its forwarding
    // logic to `deserialize_str`.
    let params: Vec<(std::sync::Arc<str>, String)> =
        vec![(std::sync::Arc::from("k"), "myvalue".to_string())];
    let de = PathDeserializer { params: &params };
    let result = serde::de::Deserializer::deserialize_identifier(de, IdentifierVisitor).unwrap();
    assert_eq!(result, "myvalue");
}
