#!/bin/bash

# Start PostgreSQL container
docker run --name postgres-test -e POSTGRES_PASSWORD=postgres -e POSTGRES_DB=casbin -d -p 5432:5432 postgres:13

# Start MySQL container
docker run --name mysql-test -e MYSQL_ROOT_PASSWORD=root -e MYSQL_DATABASE=casbin -d -p 3306:3306 mysql:8

# Wait for databases to be ready
sleep 10

# Run tests for each database
echo "Testing SQLite..."
cargo test --features sqlite -- --test-threads=1

echo "Testing PostgreSQL..."
cargo test --features postgres -- --test-threads=1

echo "Testing MySQL..."
cargo test --features mysql -- --test-threads=1

# Clean up
docker stop postgres-test mysql-test
docker rm postgres-test mysql-test