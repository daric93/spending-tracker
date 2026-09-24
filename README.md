# Spending Tracker API

A RESTful API backend service for tracking personal spending, built with Rust and Axum. This project showcases modern Rust web development practices, including async programming, type-safe database queries, JWT authentication, and comprehensive testing.

## 🎯 Project Overview

The Spending Tracker API provides a backend service for managing personal finances. Users can:

- Create and manage spending entries with amounts, dates, and categories
- Organize expenses using predefined and custom categories
- Filter and analyze spending data by date ranges and categories
- Calculate spending totals with multi-currency support
- View category-based spending breakdowns for analytics
- Track recurring expenses (subscriptions, bills)

## 🛠️ Technology Stack

- **Framework:** [Axum](https://github.com/tokio-rs/axum) - Fast, ergonomic web framework
- **Database:** PostgreSQL with [SQLx](https://github.com/launchbadge/sqlx) - Compile-time checked queries
- **Authentication:** JWT tokens with bcrypt password hashing
- **Async Runtime:** [Tokio](https://tokio.rs/)
- **Serialization:** [Serde](https://serde.rs/)
- **Validation:** [Validator](https://github.com/Keats/validator)
- **API Documentation:** OpenAPI 3.0 with Swagger UI

## ✨ Key Features

### Architecture
- **Clean Architecture:** Separation of concerns with handlers, services, and repositories
- **Type Safety:** Leverages Rust's type system for compile-time guarantees
- **Async/Await:** Non-blocking I/O for high performance
- **Repository Pattern:** Abstraction layer for data access

### Security
- JWT-based authentication
- Bcrypt password hashing
- User data isolation
- Protected endpoints with middleware

### Data Management
- Multi-category support for spending entries
- Predefined categories (groceries, restaurant, travel, etc.)
- Custom user-defined categories
- Multi-currency support (ISO 4217 codes)
- Recurring expense tracking

### Analytics
- Date-based filtering (single date, date ranges)
- Category-based filtering
- Spending totals calculation with decimal precision
- Category breakdown for spending analysis

## 📚 API Documentation

The API includes auto-generated OpenAPI 3.0 documentation with interactive Swagger UI.

Once the server is running, access the documentation at:
- **Swagger UI:** `http://localhost:8080/api/docs`
- **OpenAPI Spec:** `http://localhost:8080/api/docs/openapi.json`

### Available Endpoints

#### Authentication
- `POST /api/auth/register` - Create new user account
- `POST /api/auth/login` - Authenticate and get JWT token

#### Spending Entries
- `POST /api/spending` - Create spending entry
- `GET /api/spending` - List spending entries (with filters)
- `GET /api/spending/{id}` - Get specific entry
- `PUT /api/spending/{id}` - Update spending entry
- `DELETE /api/spending/{id}` - Delete spending entry

#### Analytics
- `GET /api/spending/total` - Get spending totals (with filters)
- `GET /api/spending/chart` - Get category breakdown

#### Categories
- `GET /api/categories` - List all categories

## 🚀 Getting Started

### Prerequisites

- Rust 1.70+ ([Install Rust](https://rustup.rs/))
- PostgreSQL 14+ ([Install PostgreSQL](https://www.postgresql.org/download/))

### Installation

1. Clone the repository:
```bash
git clone https://github.com/daric93/spending-tracker.git
cd spending-tracker
```

2. Set up the database:
```bash
# Create databases
createdb spending_tracker
createdb spending_tracker_test

# Or use the setup script
./scripts/setup_db.sh
```

3. Configure environment variables:
```bash
cp .env.example .env
# Edit .env with your database credentials and JWT secret
```

4. Run database migrations:
```bash
cargo install sqlx-cli
sqlx migrate run
```

5. Build and run:
```bash
cargo run
```

The server will start on `http://localhost:8080`

## 🧪 Testing

The project includes comprehensive test coverage:

- **64 unit tests** - Testing business logic, services, and handlers
- **25 integration tests** - End-to-end API testing
- **Property-based tests** - Validation of correctness properties

Run all tests:
```bash
cargo test
```

Run specific test suites:
```bash
# Unit tests only
cargo test --lib

# Integration tests only
cargo test --test integration_tests
```

## 🔍 Code Quality

### Linting
```bash
cargo clippy -- -D warnings
```

### Formatting
```bash
cargo fmt --check
```

## 🔄 CI/CD Pipeline

The project uses GitHub Actions for continuous integration and deployment:

### Automated Checks
- ✅ Run all tests (unit + integration)
- ✅ Clippy linting with strict warnings
- ✅ Code formatting verification
- ✅ Build verification

### Docker Support
- Multi-stage Docker builds for optimized images
- Automatic image building on main branch
- Container registry integration

View the CI/CD configuration: [`.github/workflows/ci.yml`](.github/workflows/ci.yml)

## 📁 Project Structure

```
spending-tracker/
├── src/
│   ├── handlers/          # HTTP request handlers
│   ├── services/          # Business logic layer
│   ├── repositories/      # Data access layer
│   ├── models/            # Domain models and DTOs
│   ├── middleware/        # Authentication middleware
│   └── main.rs            # Application entry point
├── tests/
│   └── integration_tests.rs  # End-to-end API tests
├── migrations/            # Database migrations
├── scripts/               # Setup and utility scripts
├── .github/workflows/     # CI/CD configuration
└── Cargo.toml            # Project dependencies
```

## 🗄️ Database Schema

The application uses PostgreSQL with the following main tables:

- **users** - User accounts with authentication
- **categories** - Predefined and custom spending categories
- **spending_entries** - Individual spending transactions
- **spending_entry_categories** - Many-to-many relationship (junction table)

Migrations are managed with SQLx and located in the `migrations/` directory.

## 🔐 Environment Variables

Required environment variables (see `.env.example`):

```env
DATABASE_URL=postgresql://user:password@localhost/spending_tracker
JWT_SECRET=your-secret-key-here
HOST=127.0.0.1
PORT=8080
```

## 🎓 Learning Outcomes

This project demonstrates proficiency in:

- **Rust Programming:** Ownership, borrowing, lifetimes, traits, async/await
- **Web Development:** RESTful API design, HTTP, JSON, authentication
- **Database:** SQL, migrations, query optimization, transactions
- **Testing:** Unit tests, integration tests, property-based testing
- **DevOps:** CI/CD pipelines, Docker, automated testing
- **Software Architecture:** Clean architecture, separation of concerns, SOLID principles
- **Documentation:** OpenAPI/Swagger, inline documentation, README

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 👤 Author

**Daria Korenieva**
- GitHub: [@daric93](https://github.com/daric93)
- Email: daric2612@gmail.com

## 🙏 Acknowledgments

Built as a learning project to explore Rust's ecosystem for backend development, with inspiration from modern web API best practices.
