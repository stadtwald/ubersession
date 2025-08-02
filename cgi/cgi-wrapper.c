#include <stdlib.h>
#include <string.h>
#include <err.h>
#include <stdio.h>
#include <unistd.h>
#include "session_token.h"

#define MAX_COOKIE_VALUE_LENGTH 4096

static int find_cookie_value(char *outp) {
    char *cookie_header = getenv("HTTP_COOKIE");

    if(cookie_header != 0) {
        size_t cookie_header_length = strlen(cookie_header);

        if(cookie_header_length > MAX_COOKIE_VALUE_LENGTH) {
            return -1;
        }

        char *current = cookie_header;

        while(1) {
            int match = (strncmp(current, "UBERSESSION=", 12) == 0);

            if(match) {
                current += 12;
                while(*current != ';' && *current != 0) {
                    *outp = *current;
                    current += 1;
                    outp += 1;
                }
                *outp = 0;

                return 0;
            } else {
                while(*current != ';' && *current != 0) {
                    current += 1;
                }
            
                if(*current != ';') {
                    return -1;
                }
                current += 1;
    
                if(*current != ' ') {
                    return -1;
                }
                current += 1;
            }
        }
    }

    return -1;
}

static int compare_hosts(char *host1, char *host2) {
    while(1) {
        int host1_ended = (*host1 == ':' || *host1 == 0);
        int host2_ended = (*host2 == ':' || *host2 == 0);

        if(host1_ended && host2_ended) {
            return 0;
        }

        if(host1_ended || host2_ended) {
            return -1;
        }

        if(*host1 != *host2) {
            return -1;
        }

        host1 += 1;
        host2 += 1;
    }
}

int main(int argc, char **argv) {
    if(argc != 2) {
        errx(1, "must be called with exactly one command line argument; was called with %i", argc);
    }

    char *next = getenv("NEXT_CGI_HANDLER");

    if(next == 0) {
        errx(1, "no NEXT_CGI_HANDLER provided");
    }

    if(*next != '/') {
        errx(1, "NEXT_CGI_HANDLER must be an absolute path name");
    }

    char cookie_value[MAX_COOKIE_VALUE_LENGTH + 1];
    struct session_token session_token;
    int verified = 0;

    if(find_cookie_value(&cookie_value[0]) != -1) {
        if(session_token_from_encoded(cookie_value, &session_token) != -1) {
            char *http_host = getenv("HTTP_HOST");
            if(http_host != 0) {
                if(compare_hosts(session_token.host, http_host) == 0) {
                    if(session_token_verify(&session_token) != -1) {
                        verified = 1;
                    }
                }
            }
        }
    }

    if(verified) {
        if(setenv("UBERSESSION_UUID", session_token.encoded_uuid, 1) == -1) {
            err(1, "could not set UBERSESSION_UUID");
        }

        if(setenv("UBERSESSION_VERIFIED", "1", 1) == -1) {
            err(1, "could not set UBERSESSION_VERIFIED");
        }

        if(setenv("UBERSESSION_PUBLIC_KEY", session_token.encoded_public_key, 1) == -1) {
            err(1, "could not set UBERSESSION_PUBLIC_KEY");
        }
    } else {
        if(unsetenv("UBERSESSION_UUID") == -1) {
            err(1, "could not unset UBERSESSION_UUID");
        }

        if(setenv("UBERSESSION_VERIFIED", "0", 1) == -1) {
            err(1, "could not set UBERSESSION_VERIFIED");
        }

        if(unsetenv("UBERSESSION_PUBLIC_KEY") == -1) {
            err(1, "could not unset UBERSESSION_PUBLIC_KEY");
        }
    }

    if(execl(next, next, *(argv + 1), 0) == -1) {
        err(1, "could not run next handler");
    }

    return 0;
}

