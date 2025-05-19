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

use std::fmt::{Display, Formatter, Write};

pub struct HtmlEscapedText<'a>(&'a str);

impl<'a> HtmlEscapedText<'a> {
    pub fn new(text: &'a str) -> Self {
        Self(text)
    }
}

impl<'a> Display for HtmlEscapedText<'a> {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        for c in self.0.chars() {
            if c == '&' {
                formatter.write_str("&amp;")?;
            } else if c == '<' {
                formatter.write_str("&lt;")?;
            } else if c == '>' {
                formatter.write_str("&gt;")?;
            } else if c == '"' {
                formatter.write_str("&quot;")?;
            } else if c == '\'' {
                formatter.write_str("&#39;")?;
            } else {
                formatter.write_char(c)?;
            }
        }
        Ok(())
    }
}

