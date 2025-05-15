use axum::http::status::StatusCode;
use axum::response::{Html, IntoResponse, Response};

fn render_html(title: &'static str) -> Html<String> {
    Html(format!("<!DOCTYPE html><html><head><title>{}</title></head><body style=\"background-color:#FFFFF0; color:#000040; font-family:roboto, 'open sans', sans-serif\"><h1>{}</h1></body></html>", title, title))
}

pub async fn handle_404() -> Response {
    (StatusCode::NOT_FOUND, render_html("404 Not Found")).into_response()
}

pub async fn handle_400() -> Response {
    (StatusCode::BAD_REQUEST, render_html("400 Bad Request")).into_response()
}

pub async fn handle_500() -> Response {
    (StatusCode::INTERNAL_SERVER_ERROR, render_html("500 Internal Server Error")).into_response()
}



