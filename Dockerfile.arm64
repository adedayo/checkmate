# Use a minimal base image
FROM debian:bookworm-slim

WORKDIR /app

# Create necessary directories
RUN mkdir -p /var/lib/checkmate && mkdir -p /app/plugins

# Install ca-certificates for secure HTTPS operations
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates git && rm -rf /var/lib/apt/lists/*

# Copy the prebuilt Checkmate binary
COPY checkmate /app/checkmate

# Set a non-root user for security
USER 65532:65532

# Run the binary (defaults to search, supports 'api' or other subcommands)
ENTRYPOINT ["/app/checkmate"]
CMD ["search"]
