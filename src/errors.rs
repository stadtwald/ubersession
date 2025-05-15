use axum::http::status::StatusCode;
use axum::response::{Html, IntoResponse, Response};

macro_rules! render_error_message {
    ($title:literal) => {
        Html(concat!(
            "<!DOCTYPE html><html><head><title>",
            $title,
            "</title></head><body style=\"background-color:#FFFFF0; color:#000040; font-family:roboto, 'open sans', sans-serif\"><h1>",
            $title,
            "</h1></body></html>"
        ))
    }
}

pub async fn handle_404() -> Response {
    (StatusCode::NOT_FOUND, render_error_message!("404 Not Found")).into_response()
}

pub async fn handle_400() -> Response {
    (StatusCode::BAD_REQUEST, render_error_message!("400 Bad Request")).into_response()
}

pub async fn handle_500() -> Response {
    (StatusCode::INTERNAL_SERVER_ERROR, render_error_message!("500 Internal Server Error")).into_response()
}



