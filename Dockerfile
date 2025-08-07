FROM rust:1.88-alpine AS build

COPY / /app

RUN sh -c 'apk add musl-dev'
RUN sh -c 'cd /app && cargo build -r -p ubersession'

FROM alpine

COPY --from=build /app/target/release/ubersession /usr/bin/ubersession

ENTRYPOINT ["/usr/bin/ubersession"]

