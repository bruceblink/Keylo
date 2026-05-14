# ---------- Build Stage ----------
FROM lukemathwalker/cargo-chef:latest-rust-1.88 AS chef
WORKDIR /app
RUN apt update && apt install -y lld clang

# Planner: prepare dependency recipe
FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

# Builder: build dependencies and project
FROM chef AS builder
COPY --from=planner /app/recipe.json recipe.json
RUN cargo chef cook --release --recipe-path recipe.json
COPY . .
ENV SQLX_OFFLINE=true
RUN cargo build --release --bin keylo

# ---------- Runtime Stage ----------
FROM debian:bookworm-slim AS runtime
WORKDIR /app

# Install runtime dependencies
RUN apt-get update -y \
    && apt-get install -y --no-install-recommends openssl ca-certificates \
    && apt-get clean -y \
    && rm -rf /var/lib/apt/lists/*

# Copy binary and configuration
COPY --from=builder /app/target/release/keylo /app/keylo
#COPY configuration /app/configuration

# Set environment variables
ENV APP_ENV=production
ENV ENVIRONMENT=production
ENV SERVER_ADDR=0.0.0.0
ENV RUST_LOG=keylo=info,axum=info

# Expose the port your app listens on
EXPOSE 2345

# Start the application
ENTRYPOINT ["/app/keylo"]
