use axum::body::Body;
use axum::http::request::Request;
use axum::response::Response;

pub async fn adapt_request(request: Request<Body>) -> Request<Vec<u8>> {
    let (parts, body) = request.into_parts();
    let concrete_body = axum::body::to_bytes(body, 50000).await.map(|x| x.into()).unwrap_or_else(|_| Vec::new());
    Request::from_parts(parts, concrete_body)
}

pub fn adapt_response(response: Response<Vec<u8>>) -> Response {
    let (parts, body) = response.into_parts();
    Response::from_parts(parts, body.into())
}


