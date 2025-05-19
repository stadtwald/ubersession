/*
 * Copyright (c) 2025 William Stadtwald Demchick <william.demchick@gmail.com>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

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
pub fn build_404() -> Response {
    (StatusCode::NOT_FOUND, render_error_message!("404 Not Found")).into_response()
}

pub async fn handle_404() -> Response {
    build_404()
}

pub fn build_400() -> Response {
    (StatusCode::BAD_REQUEST, render_error_message!("400 Bad Request")).into_response()
}

pub async fn handle_400() -> Response {
    build_400()
}

pub fn build_500() -> Response {
    (StatusCode::INTERNAL_SERVER_ERROR, render_error_message!("500 Internal Server Error")).into_response()
}


