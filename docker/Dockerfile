# Use official PostgreSQL 15 base image
FROM postgres:15

# Set environment variables (can be overridden in `.env`)
ENV POSTGRES_USER=app_user
ENV POSTGRES_PASSWORD=securepassword
ENV POSTGRES_DB=db_dev

# Set locale and timezone for consistency
ENV LANG=en_US.utf8
ENV TZ=UTC

# Install additional PostgreSQL extensions
RUN apt-get update && apt-get install -y \
    postgresql-contrib \
    postgresql-15-pgtap \
    curl \
    jq \
    && rm -rf /var/lib/apt/lists/*

# Copy custom configuration files (if any)
COPY config/postgres.conf /etc/postgresql/postgresql.conf
COPY config/pg_hba.conf /etc/postgresql/pg_hba.conf
COPY config/recovery.conf /etc/postgresql/recovery.conf

# Copy database initialization scripts
COPY docker/initdb/ /docker-entrypoint-initdb.d/

# Ensure PostgreSQL uses our custom configuration
CMD ["postgres", "-c", "config_file=/etc/postgresql/postgresql.conf"]

# Expose PostgreSQL port
EXPOSE 5432

# Set working directory
WORKDIR /var/lib/postgresql

# Define entrypoint for running scripts before startup
ENTRYPOINT ["docker-entrypoint.sh"]

# Define default command to run PostgreSQL
CMD ["postgres"]
