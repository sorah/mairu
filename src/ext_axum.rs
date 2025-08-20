/// Axum extractor for Bearer token per [RFC 6750][]
///
/// [RFC 6750]: https://datatracker.ietf.org/doc/html/rfc6750
/// [rfc9110]: https://datatracker.ietf.org/doc/html/rfc9110#section-11.1
#[derive(Debug)]
pub(crate) struct ExtractBearer {
    #[allow(dead_code)]
    pub(crate) source: BearerSource,
    pub(crate) value: secrecy::SecretString,
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum BearerSource {
    Header,
    Query,
}

const ACCESS_TOKEN: &str = "access_token";

impl<S> axum::extract::FromRequestParts<S> for ExtractBearer
where
    S: Send + Sync,
{
    type Rejection = ExtractBearerRejection;

    #[tracing::instrument(skip_all)]
    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        _state: &S,
    ) -> Result<Self, Self::Rejection> {
        use headers::Header;

        let query_values_maybe = parts
            .uri
            .query()
            .map(|v| url::form_urlencoded::parse(v.as_bytes()))
            .ok_or(ExtractBearerRejection::Missing)
            .and_then(|q| {
                let ts: Vec<_> = q.filter(|(k, _)| k == ACCESS_TOKEN).collect();
                match ts.len().cmp(&1) {
                    std::cmp::Ordering::Equal => Ok(ts[0].1.clone()),
                    std::cmp::Ordering::Less => Err(ExtractBearerRejection::Missing),
                    std::cmp::Ordering::Greater => Err(ExtractBearerRejection::Unambiguous),
                }
            });
        let query_value = match query_values_maybe {
            Ok(vs) => Some(vs),
            Err(ExtractBearerRejection::Unambiguous) => {
                return Err(ExtractBearerRejection::Unambiguous);
            }
            Err(ExtractBearerRejection::Error(_)) => {
                unreachable!("ExtractBearerRejection::Error shouldn't appear at this point")
            }
            Err(ExtractBearerRejection::Missing) => None,
        };

        let mut header_values = parts
            .headers
            .get_all(headers::Authorization::<headers::authorization::Bearer>::name())
            .iter();
        let header_value = match header_values.size_hint() {
            (1, Some(1)) => {
                match headers::Authorization::<headers::authorization::Bearer>::decode(
                    &mut header_values,
                ) {
                    Ok(c) => Some(c),
                    Err(e) => return Err(ExtractBearerRejection::Error(e)),
                }
            }
            (0, Some(0)) => None,
            (1, None) => {
                return Err(ExtractBearerRejection::Unambiguous);
            }
            (_, _) => {
                return Err(ExtractBearerRejection::Unambiguous);
            }
        };

        match (query_value, header_value) {
            (None, None) => Err(ExtractBearerRejection::Missing),
            (Some(_), Some(_)) => Err(ExtractBearerRejection::Unambiguous),
            (Some(q), None) => Ok(ExtractBearer {
                source: BearerSource::Query,
                value: secrecy::SecretString::new(q.as_ref().to_owned().into()),
            }),
            (None, Some(h)) => Ok(ExtractBearer {
                source: BearerSource::Header,
                value: secrecy::SecretString::new(h.token().to_owned().into()),
            }),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum ExtractBearerRejection {
    /// no bearer token was given
    #[error(
        "bearer token was missing, must be given through Authorization header or access_token query parameter"
    )]
    Missing,
    /// multiple tokens were given, had to decline per [RFC 6750 Section 2.](https://datatracker.ietf.org/doc/html/rfc6750#section-2)
    #[error("multiple bearer tokens were given")]
    Unambiguous,
    /// other possible header parse error
    #[error(transparent)]
    Error(headers::Error),
}

impl axum::response::IntoResponse for ExtractBearerRejection {
    fn into_response(self) -> axum::response::Response {
        (axum::http::StatusCode::BAD_REQUEST, self.to_string()).into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tower::ServiceExt; // for `oneshot` and `ready`

    mod extract_bearer {
        use super::*;

        async fn handler(bearer: ExtractBearer) -> impl axum::response::IntoResponse {
            use secrecy::ExposeSecret;
            format!(
                "source={:?},value={}",
                bearer.source,
                bearer.value.expose_secret()
            )
        }

        fn app() -> axum::Router {
            axum::Router::new().route("/", axum::routing::get(handler))
        }

        async fn do_request_and_body(req: axum::http::Request<axum::body::Body>) -> String {
            let resp = app().oneshot(req).await.unwrap();
            String::from_utf8(
                axum::body::to_bytes(resp.into_body(), usize::MAX)
                    .await
                    .unwrap()
                    .to_vec(),
            )
            .unwrap()
        }

        #[tokio::test]
        async fn test_header() {
            let req = axum::http::Request::builder()
                .uri("/")
                .header("Authorization", "Bearer himitsu")
                .body(axum::body::Body::empty())
                .unwrap();
            let body = do_request_and_body(req).await;
            assert_eq!(body, "source=Header,value=himitsu");
        }

        #[tokio::test]
        async fn test_header_invalid() {
            let req = axum::http::Request::builder()
                .uri("/")
                .header("Authorization", "Basic Zm9vOmJhcg==") // foo:bar
                .body(axum::body::Body::empty())
                .unwrap();
            let resp = app().oneshot(req).await.unwrap();
            assert_eq!(resp.status(), 400);
        }

        #[tokio::test]
        async fn test_query() {
            let req = axum::http::Request::builder()
                .uri("/?access_token=kueri")
                .body(axum::body::Body::empty())
                .unwrap();
            let body = do_request_and_body(req).await;
            assert_eq!(body, "source=Query,value=kueri");
        }

        #[tokio::test]
        async fn test_query_invalid() {
            let req = axum::http::Request::builder()
                .uri("/?a==")
                .body(axum::body::Body::empty())
                .unwrap();
            let resp = app().oneshot(req).await.unwrap();
            assert_eq!(resp.status(), 400);
        }

        #[tokio::test]
        async fn test_missing() {
            let req = axum::http::Request::builder()
                .uri("/")
                .body(axum::body::Body::empty())
                .unwrap();
            let resp = app().oneshot(req).await.unwrap();
            assert_eq!(resp.status(), 400);
        }

        #[tokio::test]
        async fn test_header_unambiguous() {
            let req = axum::http::Request::builder()
                .header("Authorization", "Bearer hedda1")
                .header("Authorization", "Bearer hedda2")
                .body(axum::body::Body::empty())
                .unwrap();
            let resp = app().oneshot(req).await.unwrap();
            assert_eq!(resp.status(), 400);
        }
        #[tokio::test]
        async fn test_query_unambiguous() {
            let req = axum::http::Request::builder()
                .uri("/?access_token=kueri&access_token=kueri2")
                .body(axum::body::Body::empty())
                .unwrap();
            let resp = app().oneshot(req).await.unwrap();
            assert_eq!(resp.status(), 400);
        }
        #[tokio::test]
        async fn test_both_unambiguous() {
            let req = axum::http::Request::builder()
                .uri("/?access_token=kueri")
                .header("Authorization", "Bearer hedda")
                .body(axum::body::Body::empty())
                .unwrap();
            let resp = app().oneshot(req).await.unwrap();
            assert_eq!(resp.status(), 400);
        }
    }
}
