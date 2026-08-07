# Minimal image wrapping the locally-built static geth binary.
# Build: docker build -t my-geth:bal -f devnet/Dockerfile .
FROM alpine:latest

RUN apk add --no-cache ca-certificates
COPY build/bin/geth /usr/local/bin/

EXPOSE 8545 8546 8551 30303 30303/udp
ENTRYPOINT ["geth"]
