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

use http::header::{HeaderValue, CONTENT_TYPE};
use http::response::Response;
use http::status::StatusCode;

macro_rules! render_error_message {
    ($title:literal) => {
        concat!(
            "<!DOCTYPE html><html><head><title>",
            $title,
            "</title></head><body style=\"background-color:#FFFFF0; color:#000040; font-family:roboto, 'open sans', sans-serif\"><h1>",
            $title,
            "</h1></body></html>"
        )
    }
}

const HTML: HeaderValue = HeaderValue::from_static("text/html; charset=utf-8");

fn build_error(status: StatusCode, body: &'static str) -> Response<Vec<u8>> {
    let mut response = Response::new(body.as_bytes().to_owned());
    *response.status_mut() = status;
    response.headers_mut().insert(CONTENT_TYPE, HTML);
    response
}

pub fn build_404() -> Response<Vec<u8>> {
    build_error(StatusCode::NOT_FOUND, render_error_message!("404 Not Found"))
}

pub fn build_400() -> Response<Vec<u8>> {
    build_error(StatusCode::BAD_REQUEST, render_error_message!("400 Bad Request"))
}

pub fn build_500() -> Response<Vec<u8>> {
    build_error(StatusCode::INTERNAL_SERVER_ERROR, render_error_message!("500 Internal Server Error"))
}


