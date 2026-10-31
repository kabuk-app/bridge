# Self-hosted Kabuk bridge. Build:
#   docker build -t kabuk-bridge .
# Run:
#   docker run -d --name kabuk-bridge -p 21226:21226 kabuk-bridge
# With limits:
#   docker run -d -p 21226:21226 kabuk-bridge --allow-port 2222
FROM rust:1-alpine AS build
RUN apk add --no-cache musl-dev git
WORKDIR /src
COPY . .
RUN cargo build --release --locked

FROM scratch
COPY --from=build /src/target/release/kabuk-bridge /kabuk-bridge
USER 65534:65534
EXPOSE 21226/tcp
HEALTHCHECK --interval=30s --timeout=5s CMD ["/kabuk-bridge", "--health"]
ENTRYPOINT ["/kabuk-bridge"]
