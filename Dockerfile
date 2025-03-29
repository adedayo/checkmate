# Use a minimal base image - base ruby for asciidoctor-pdf
FROM ruby:slim

WORKDIR /app

# Create necessary directories
RUN mkdir -p /var/lib/checkmate /app/plugins

# Copy the prebuilt Checkmate binary from the host (Goreleaser output), passed through extra_files
COPY checkmate /app/checkmate

# Copy additional assets if needed
# COPY dist/plugins /app/plugins
# COPY dist/cors_config.yaml  .

# Install dependencies for PDF generation
RUN apt update -y && apt install -y ghostscript
RUN gem install rouge text-hyphen asciidoctor-pdf

# Set a non-root user for security
USER 65532:65532

# Run the binary
ENTRYPOINT ["/app/checkmate", "search"]
