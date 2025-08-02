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

#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include "session_token.h"
#include "crypto/crypto_api.h"

static int hexdigit(char digit) {
    if(digit >= '0' && digit <= '9') {
        return digit - '0';
    } else if(digit >= 'A' && digit <= 'F') {
        return digit - 'A' + 10;
    } else if(digit >= 'a' && digit <= 'f') {
        return digit - 'a' + 10;
    } else {
        return -1;
    }
}

static int b64digit(char digit) {
    if(digit >= 'A' && digit <= 'Z') {
        return digit - 'A';
    } else if(digit >= 'a' && digit <= 'z') {
        return digit - 'a' + 26;
    } else if(digit >= '0' && digit <= '9') {
        return digit - '0' + 52;
    } else if(digit == '+') {
        return 62;
    } else if(digit == '/') {
        return 63;
    } else {
        return -1;
    }
}

static char *urldecode(char *encoded) {
    size_t percentages_count = 0;
    size_t total_count = 0;
    int errored = 1;
    char *storage = 0;

    {
        char *p = encoded;

        while(*p != 0) {
            if(*p == '%') {
                percentages_count += 1;
            }
            if(*p < ' ') {
                goto cleanup;
            }
            total_count += 1;
            if(total_count > 2000) {
                goto cleanup;
            }
            p += 1;
        }
    }

    size_t theoretical_savings = percentages_count * 2;

    if (theoretical_savings >= total_count) {
        goto cleanup;
    }

    size_t outlength = total_count - theoretical_savings;

    storage = malloc(1 + outlength);

    if (storage == 0) {
        goto cleanup;
    }

    char *outp = storage;
    char *inp = encoded;

    while(*inp != 0) {
        if(*inp == '%') {
            inp += 1;

            char high = hexdigit(*inp);
            if(high < 0) {
                goto cleanup;
            }
            inp += 1;

            char low = hexdigit(*inp);
            if(low < 0) {
                goto cleanup;
            }
            
            *outp = (high << 4) + low;

            if(*outp == 0) {
                goto cleanup;
            }
        } else {
            *outp = *inp;
        }
        inp += 1;
        outp += 1;
    }
   
    errored = 0;

cleanup:

    if(errored && storage != 0) {
        free(storage);
        storage = 0;
    }

    return storage;
}

// outp must point to a buffer of at least 32 bytes
static int decode_base64_v32(char *encoded, uint8_t *outp) {
    if(strlen(encoded) != 44) {
        return -1;
    }

    char *inp = encoded;

    for(int x = 0; x < 10; x += 1) {
        int b0 = b64digit(*inp);
        if(b0 < 0) {
            return -1;
        }
        inp += 1;

        int b1 = b64digit(*inp);
        if(b1 < 0) {
            return -1;
        }
        inp += 1;

        int b2 = b64digit(*inp);
        if(b2 < 0) {
            return -1;
        }
        inp += 1;

        int b3 = b64digit(*inp);
        if(b3 < 0) {
            return -1;
        }
        inp += 1;

        uint8_t c0 = (b0 << 2) + (b1 >> 4);
        uint8_t c1 = ((b1 & 0xF) << 4) + (b2 >> 2);
        uint8_t c2 = ((b2 & 0x3) << 6) + b3;

        *outp = c0;
        outp += 1;
        *outp = c1;
        outp += 1;
        *outp = c2;
        outp += 1;
    }

    int b0 = b64digit(*inp);
    if(b0 < 0) {
        return -1;
    }
    inp += 1;

    int b1 = b64digit(*inp);
    if(b1 < 0) {
        return -1;
    }
    inp += 1;

    int b2 = b64digit(*inp);
    if(b2 < 0) {
        return -1;
    }
    inp += 1;

    if(*inp != '=') {
        return -1;
    }

    uint8_t c0 = (b0 << 2) + (b1 >> 4);
    uint8_t c1 = ((b1 & 0xF) << 4) + (b2 >> 2);

    *outp = c0;
    outp += 1;
    *outp = c1;
 
    return 0;
}

// outp must point to a buffer of at least 64 bytes
static int decode_base64_v64(char *encoded, uint8_t *outp) {
    if(strlen(encoded) != 88) {
        return -1;
    }

    char *inp = encoded;

    for(int x = 0; x < 21; x += 1) {
        int b0 = b64digit(*inp);
        if(b0 < 0) {
            return -1;
        }
        inp += 1;

        int b1 = b64digit(*inp);
        if(b1 < 0) {
            return -1;
        }
        inp += 1;

        int b2 = b64digit(*inp);
        if(b2 < 0) {
            return -1;
        }
        inp += 1;

        int b3 = b64digit(*inp);
        if(b3 < 0) {
            return -1;
        }
        inp += 1;

        uint8_t c0 = (b0 << 2) + (b1 >> 4);
        uint8_t c1 = ((b1 & 0xF) << 4) + (b2 >> 2);
        uint8_t c2 = ((b2 & 0x3) << 6) + b3;

        *outp = c0;
        outp += 1;
        *outp = c1;
        outp += 1;
        *outp = c2;
        outp += 1;
    }

    int b0 = b64digit(*inp);
    if(b0 < 0) {
        return -1;
    }
    inp += 1;

    int b1 = b64digit(*inp);
    if(b1 < 0) {
        return -1;
    }
    inp += 1;

    if(*inp != '=') {
        return -1;
    }

    inp += 1;

    if(*inp != '=') {
        return -1;
    }

    uint8_t c0 = (b0 << 2) + (b1 >> 4);

    *outp = c0;
    outp += 1;
 
    return 0;
}


// outp must point to a buffer of at least 16 bytes
static int decode_uuid(char *encoded, uint8_t *outp) {
    size_t length = 0;
    size_t hyphens = 0;

    {
        char *inp = encoded;

        while(*inp != 0) {
            length += 1;
            if(*inp == '-') {
                hyphens += 1;
            }
            inp += 1;
        }
    }

    if(length != 8 + 1 + 4 + 1 + 4 + 1 + 4 + 1 + 12) {
        return -1;
    }

    if(hyphens != 4) {
        return -1;
    }

    {
        char *inp = encoded;

        inp += 8;
        if(*inp != '-') {
            return -1;
        }

        inp += 5;
        if(*inp != '-') {
            return -1;
        }

        inp += 5;
        if(*inp != '-') {
            return -1;
        }

        inp += 5;
        if(*inp != '-') {
            return -1;
        }
    }

    {
        char *inp = encoded;
        
        while(*inp != 0) {
            if(*inp == '-') {
                inp += 1;
            }
            int high = hexdigit(*inp);
            inp += 1;
            int low = hexdigit(*inp);
            inp += 1;
            if(high < 0 || low < 0) {
                return -1;
            }
            *outp = (high << 4) + low;
            outp += 1;
        }
    }

    return 0;
}

static inline void skip_whitespace(char **p) {
    while(**p == ' ' || **p == '\t' || **p == '\n' || **p == '\r') {
        *p += 1;
    }
}

int session_token_from_encoded(char *encoded, struct session_token *session_token) {
    char *urldecoded = urldecode(encoded);

    if(urldecoded == 0) {
        goto cleanup;
    }

    int errored = 1;
    char *inp = urldecoded;
    char *encoded_public_key = 0;
    char *encoded_signature = 0;
    char *encoded_host = 0;
    char *encoded_expires = 0;
    char *encoded_id = 0;

    if(*inp != '{') {
        goto cleanup;
    }
    inp += 1;

    while(1) {
        skip_whitespace(&inp);

        if(*inp != '"') {
            goto cleanup;
        }
        inp += 1;

        char *key = inp;
        while (*inp != 0 && *inp != '"') {
            inp += 1;
        }

        if (*inp != '"') {
            goto cleanup;
        }
        *inp = 0;
        inp += 1;

        skip_whitespace(&inp);

        if (*inp != ':') {
            goto cleanup;
        }
        inp += 1;

        skip_whitespace(&inp);

        int quoted = 0;

        if(*inp == '"') {
            inp += 1;
            quoted = 1;
        } else if(*inp < '0' || *inp > '9') {
            goto cleanup;
        }

        char *value = inp;
        char next;

        if(quoted) {
            while(*inp != '"' && *inp != 0) {
                if(*inp == '\\') { // we don't support escape sequences
                    goto cleanup;
                }
                if(*inp < ' ' || *inp > 126) { // we only support a subset of ASCII
                    goto cleanup;
                }
                inp += 1;
            }
            if(*inp != '"') {
                goto cleanup;
            }
            *inp = 0;
            inp += 1;
            next = *inp;
            inp += 1;
        } else {
            while(*inp >= '0' && *inp <= '9') {
                inp += 1;
            }
            next = *inp;
            *inp = 0;
            inp += 1;
        }

        if(strcmp("public_key", key) == 0) {
            encoded_public_key = value;
        } else if(strcmp("signature", key) == 0) {
            encoded_signature = value;
        } else if(strcmp("host", key) == 0) {
            encoded_host = value;
        } else if(strcmp("expires", key) == 0) {
            encoded_expires = value;
        } else if(strcmp("id", key) == 0) {
            encoded_id = value;
        }

        if(next == ' ') {
            skip_whitespace(&inp);
            next = *inp;
            inp += 1;
        }
        if(next == ',') {
            continue;
        }
        if(next == '}') {
            skip_whitespace(&inp);
            if(*inp != 0) {
                goto cleanup;
            }
            break;
        }
    }

    if(
        encoded_public_key == 0 ||
        encoded_signature == 0 ||
        encoded_host == 0 ||
        encoded_expires == 0 ||
        encoded_id == 0
    ) {
        goto cleanup;
    }

    if (session_token == 0) {
        goto cleanup;
    }

    {
        errno = 0;
        char *end = 0;
        long long expires = strtoll(encoded_expires, &end, 10);
        if (errno != 0 || *end != 0 || expires > 0xFFFFFFFF) {
            goto cleanup;
        }

        session_token->expires = expires;
    }

    if(decode_uuid(encoded_id, &session_token->uuid[0]) == -1) {
        goto cleanup;
    }

    if(decode_base64_v32(encoded_public_key, &session_token->public_key[0]) == -1) {
        goto cleanup;
    }

    if(decode_base64_v64(encoded_signature, &session_token->signature[0]) == -1) {
        goto cleanup;
    }

    if(strlen(encoded_host) > SESSION_TOKEN_MAX_HOST_LENGTH) {
        goto cleanup;
    }

    strncpy(&session_token->host[0], encoded_host, SESSION_TOKEN_MAX_HOST_LENGTH + 1);

    errored = 0;

cleanup:
    if(urldecoded != 0) {
        free(urldecoded);
    }

    if(errored) {
        bzero(session_token, sizeof(struct session_token));
    }

    return errored ? -1 : 0;
}

int session_token_verify(struct session_token *session_token) {
    if(time(0) > session_token->expires) {
        return -1;
    }

    size_t host_length = strlen(session_token->host);
    size_t message_length = host_length + 9 + 4 + 16;
    size_t signature_length = message_length + 64;
    uint8_t signature_buffer[SESSION_TOKEN_MAX_HOST_LENGTH + 9 + 4 + 16 + 64];
    uint8_t dummy_buffer[SESSION_TOKEN_MAX_HOST_LENGTH + 9 + 4 + 16 + 64];

    uint8_t *p = &signature_buffer[0];

    memcpy(p, &session_token->signature[0], 64);
    p += 64;

    memcpy(p, "UBERSESS", 9);
    p += 9;

    *p = (session_token->expires >> 24);
    p += 1;
    *p = (session_token->expires >> 16) & 0xFF;
    p += 1;
    *p = (session_token->expires >> 8) & 0xFF;
    p += 1;
    *p = session_token->expires & 0xFF;
    p += 1;

    memcpy(p, session_token->uuid, 16);
    p += 16;

    memcpy(p, session_token->host, host_length);

    unsigned long long dummy_length;

    int verified = crypto_sign_ed25519_open(dummy_buffer, &dummy_length, signature_buffer, signature_length, session_token->public_key) != -1;

    return verified ? 0 : -1;
}

