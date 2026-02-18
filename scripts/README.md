# Database Setup Scripts

## Prerequisites

- PostgreSQL must be installed and running
- You must have permissions to create databases

## Environment Configuration

Before running the application, you need to configure the DATABASE_URL environment variable:

1. Copy the example environment file:
   ```bash
   cp .env.example .env
   ```

2. Edit `.env` and update the DATABASE_URL if needed:
   ```
   DATABASE_URL=postgresql://localhost/spending_tracker
   ```

3. If your PostgreSQL requires authentication, update the URL format:
   ```
   DATABASE_URL=postgresql://username:password@localhost/spending_tracker
   ```

## Creating the Database

Run the setup script:

```bash
./scripts/setup_db.sh
```

This will create the `spending_tracker` database if it doesn't already exist.

## Manual Database Creation

If you prefer to create the database manually, run:

```bash
psql -c "CREATE DATABASE spending_tracker;"
```

## Verifying the Database

To verify the database was created successfully:

```bash
psql -l | grep spending_tracker
```

Or connect to it directly:

```bash
psql spending_tracker
```
