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


