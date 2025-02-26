# Use official PostgreSQL 15 base image
FROM postgres:15

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

# Use non-root user for security
USER postgres

# Define working directory
WORKDIR /var/lib/postgresql

# Install additional PostgreSQL extensions and utilities
RUN apt-get update && apt-get install -y --no-install-recommends \
    postgresql-contrib \
    postgresql-15-pgtap \
    curl \
    jq \
    && rm -rf /var/lib/apt/lists/*

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

# Ensure PostgreSQL uses our custom configuration
CMD ["postgres", "-c", "config_file=/etc/postgresql/postgresql.conf"]
