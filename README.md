# ubersession

## What is this

ubersession is a simple system for establishing a shared web session across multiple domains.  The domains can have arbitrary names; they need not have a common parent domain.  However, all domain names participating in the shared session must be configured to use this system with a shared private key.

This system does not provide authentication or authorisation facilities.  The intention is that it can be one building block for such a solution.

## How it works

The ubersession server publishes a single HTTP endpoint that is used in the session workflow.  (By default, this is `/_session/flow`, but it can be customised if necessary.)  This endpoint should typically be exposed under each relevant domain using a reverse proxy.  The reverse proxy should forward most requests to the actual web app on that domain, but should send relevant requests to the ubersession server.

One domain name is specified as the "authority".  As the workflow progresses, a session token is first generated and stored as a cookie under the authority domain.  Then, tokens specifying the same session ID are replicated to other participating domains as necessary.

When a shared session is being initialised for the first time, the ubersession server generates a random UUID to serve as the session ID.  It then signs this along with an expiry timestamp and a domain name.  The result is a bearer token which authorises the holder to act in that session under the specified domain.  (This means that you can allow untrusted web apps to participate in the shared session.  But, note that the reverse proxies used must still be trusted.)

When a web app wishes to determine what session it is a part of, it looks up the token in the cookies sent to it, parses the token, and validates it.  Note that the web app must do the validation itself; it should never blindly trust that a token is valid.  Tokens are constructed to be easy to validate in most popular programming languages.

Given that bearer tokens are used, care has been taken to never expose the token in URLs.  Rather, when cross-domain communication is performed, `POST`s are used.

## Project status

This project should currently be considered alpha quality.  You should not use it for anything critical at present.  There could easily be flaws in the software with security implications.

The plan is to continue to improve the software's engineering and to check it for security bugs.  Additional features may be added if they would make the system more usable in real-world applications.  However, the scope of the project won't be expanding substantially - this is to make the system easy to understand and lightweight.

