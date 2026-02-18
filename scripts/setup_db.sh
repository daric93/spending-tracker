#!/bin/bash

# Script to create the spending_tracker database
# This script assumes PostgreSQL is installed and running

set -e

echo "Creating spending_tracker database..."

# Try to create the database
# This will fail gracefully if the database already exists
psql -c "CREATE DATABASE spending_tracker;" 2>/dev/null || echo "Database spending_tracker already exists or could not be created"

echo "Database setup complete!"
echo ""
echo "To verify the database was created, run:"
echo "  psql -l | grep spending_tracker"
