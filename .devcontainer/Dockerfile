FROM rust:1-bullseye

# Install additional dependencies
RUN apt-get update && export DEBIAN_FRONTEND=noninteractive \
    && apt-get -y install --no-install-recommends \
        postgresql-client \
        default-mysql-client \
        sqlite3 \
        pkg-config \
        libssl-dev \
    && apt-get clean -y \
    && rm -rf /var/lib/apt/lists/*

# Install Rust components
RUN rustup component add rustfmt clippy

# Create non-root user
ARG USERNAME=vscode
ARG USER_UID=1000
ARG USER_GID=$USER_UID

RUN groupadd --gid $USER_GID $USERNAME \
    && useradd --uid $USER_UID --gid $USER_GID -m $USERNAME \
    && apt-get update \
    && apt-get install -y sudo \
    && echo $USERNAME ALL=\(root\) NOPASSWD:ALL > /etc/sudoers.d/$USERNAME \
    && chmod 0440 /etc/sudoers.d/$USERNAME

# Create test helper script
RUN echo '#!/bin/bash\n\
cargo test --features postgres -- --test-threads=1\n\
cargo test --features mysql -- --test-threads=1\n\
cargo test --features sqlite -- --test-threads=1\n\
' > /usr/local/bin/test-all && chmod +x /usr/local/bin/test-all

# Set up working directory
WORKDIR /workspace

# Switch to non-root user
USER $USERNAME

# Pre-fetch dependencies
RUN cargo install cargo-watch 