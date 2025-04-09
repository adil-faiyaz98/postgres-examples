# Use official PostgreSQL 15 base image with pinned digest for security
FROM postgres:15.4@sha256:4d9244b8e219e44c5a37a1d2c7c07c6a9e0ad3b1e0b5f6d0c396d0a0f2c8d6a AS builder

# Install additional PostgreSQL extensions and utilities
RUN apt-get update && apt-get install -y --no-install-recommends \
    postgresql-contrib \
    postgresql-15-pgtap \
    curl \
    jq \
    && rm -rf /var/lib/apt/lists/*

# Create a non-privileged user
RUN groupadd -g 999 postgres_secure && \
    useradd -r -u 999 -g postgres_secure postgres_secure

# Final stage with pinned digest for security
FROM postgres:15.4-alpine@sha256:6f7a4f4c0d3c0f0f8f1b5a2a9836a3c73357e8f29c062789f4f3f764b3f375a7

# Set build arguments (can be overridden via environment variables)
ARG POSTGRES_USER
ARG POSTGRES_PASSWORD
ARG POSTGRES_DB

# Set environment variables dynamically
ENV POSTGRES_USER=$POSTGRES_USER
ENV POSTGRES_PASSWORD=$POSTGRES_PASSWORD
ENV POSTGRES_DB=$POSTGRES_DB

# Set locale and timezone for consistency
ENV LANG=en_US.utf8
ENV TZ=UTC

# Security hardening
ENV POSTGRES_INITDB_ARGS="--data-checksums"
ENV POSTGRES_HOST_AUTH_METHOD=scram-sha-256

# Copy PostgreSQL extensions from builder
COPY --from=builder /usr/lib/postgresql /usr/lib/postgresql
COPY --from=builder /usr/share/postgresql /usr/share/postgresql

# Install minimal required packages
RUN apk add --no-cache \
    tzdata \
    su-exec \
    libpq \
    && rm -rf /var/cache/apk/*

# Use non-root user for security
USER postgres

# Define working directory
WORKDIR /var/lib/postgresql

# Ensure PostgreSQL logs are stored in the correct directory
VOLUME /var/lib/postgresql/data

# Copy custom configuration files
COPY config/postgres.conf /etc/postgresql/postgresql.conf
COPY config/pg_hba.conf /etc/postgresql/pg_hba.conf
COPY config/recovery.conf /etc/postgresql/recovery.conf

# Copy database initialization scripts
COPY docker/initdb/ /docker-entrypoint-initdb.d/

# Expose PostgreSQL port
EXPOSE 5432

# Add health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
  CMD pg_isready -U postgres || exit 1

# Ensure PostgreSQL uses our custom configuration
CMD ["postgres", "-c", "config_file=/etc/postgresql/postgresql.conf"]
