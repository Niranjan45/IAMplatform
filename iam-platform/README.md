# Enterprise Identity & Access Management (IAM) Platform

A production-ready IAM platform built with **Java 21** and **Spring Boot 3.3**, providing
authentication, authorization (RBAC), MFA, session management, and admin APIs.

## Features

- User registration with email verification
- JWT access tokens + persisted, revocable opaque refresh tokens (rotation on every refresh)
- Role-Based Access Control (RBAC) with fine-grained permissions
- Password reset flow (email-based, time-limited, single-use tokens)
- Account lockout after repeated failed login attempts, with auto-unlock after a cooldown
- TOTP-based Multi-Factor Authentication (compatible with Google Authenticator / Authy), including QR code setup
- Redis-backed IP rate limiting on the login endpoint
- Audit logging of all security-relevant events (async, non-blocking)
- Session management: list/revoke active sessions, force logout on password change
- Admin APIs for user, role and permission management
- OpenAPI/Swagger documentation
- Global exception handling with consistent JSON error responses
- Flyway-managed schema migrations
- Dockerized with Docker Compose (Postgres + Redis + app)

## Tech Stack

| Concern            | Technology                          |
|---------------------|--------------------------------------|
| Language / Runtime  | Java 21                             |
| Framework           | Spring Boot 3.3, Spring Security     |
| Persistence         | PostgreSQL, Spring Data JPA, Flyway  |
| Caching             | Redis (rate limiting)                |
| Tokens              | JWT (jjwt) + opaque refresh tokens   |
| MFA                 | TOTP (RFC 6238) + ZXing QR codes     |
| API Docs            | springdoc-openapi / Swagger UI       |
| Testing             | JUnit 5, Mockito                     |
| Containerization    | Docker, Docker Compose               |

## Project Structure

```
iam-platform/
├── pom.xml
├── Dockerfile
├── docker-compose.yml
├── src/
│   ├── main/
│   │   ├── java/com/enterprise/iam/
│   │   │   ├── IamApplication.java
│   │   │   ├── config/         # Security, Redis, OpenAPI, Async config
│   │   │   ├── security/       # JWT, filters, UserDetails, current-user resolver
│   │   │   ├── entity/         # JPA entities
│   │   │   ├── repository/     # Spring Data repositories
│   │   │   ├── dto/            # request/ and response/ records
│   │   │   ├── service/        # Business logic
│   │   │   ├── controller/     # REST controllers
│   │   │   ├── exception/      # Custom exceptions + global handler
│   │   │   └── util/           # TOTP, QR code, token generation helpers
│   │   └── resources/
│   │       ├── application.yml
│   │       └── db/migration/   # Flyway SQL migrations (schema + seed data)
│   └── test/
│       └── java/com/enterprise/iam/  # Unit tests (service, security, util)
```

## Getting Started

### Prerequisites
- Java 21 (JDK)
- Maven 3.9+
- Docker & Docker Compose (for containerized run)

### Option 1: Run with Docker Compose (recommended)

```bash
docker compose up --build
```

This starts PostgreSQL, Redis, and the application. On first boot, Flyway automatically
creates the schema and seeds default roles/permissions plus a default admin account:

- **Email:** `admin@enterprise-iam.com`
- **Username:** `admin`
- **Password:** `Admin@123`

> Change this password immediately in any non-local environment.

The API is available at `http://localhost:8080`, and Swagger UI at
`http://localhost:8080/swagger-ui.html`.

### Option 2: Run locally with Maven

1. Start Postgres and Redis (e.g. via `docker compose up postgres redis`, or your own local instances).
2. Set the following environment variables (or edit `application.yml` directly):

   ```bash
   export DB_HOST=localhost
   export DB_PORT=5432
   export DB_NAME=iam_db
   export DB_USER=iam_user
   export DB_PASSWORD=iam_password
   export REDIS_HOST=localhost
   export REDIS_PORT=6379
   export JWT_SECRET=c3VwZXItc2VjcmV0LWtleS1mb3ItaWFtLXBsYXRmb3JtLWNoYW5nZS1pbi1wcm9kLTIwMjY=
   ```

3. Run:

   ```bash
   mvn spring-boot:run
   ```

### Running Tests

```bash
mvn test
```

Tests run against an in-memory H2 database and do not require Postgres/Redis to be running.

## Configuration Reference

Key settings live in `application.yml` and can be overridden via environment variables:

| Variable                 | Purpose                                       | Default |
|---------------------------|------------------------------------------------|---------|
| `JWT_SECRET`              | Base64 HMAC signing key for access tokens       | (dev key, override in prod) |
| `JWT_ACCESS_EXP`          | Access token lifetime (ms)                      | 900000 (15 min) |
| `JWT_REFRESH_EXP`         | Refresh token lifetime (ms)                     | 604800000 (7 days) |
| `app.security.max-failed-login-attempts` | Failed attempts before lockout | 5 |
| `app.security.account-lockout-duration-minutes` | Lockout duration | 30 |
| `MAIL_HOST` / `MAIL_PORT` / `MAIL_USERNAME` / `MAIL_PASSWORD` | SMTP settings for verification/reset emails | Mailtrap sandbox |
| `FRONTEND_URL`            | Base URL used to build email links              | http://localhost:3000 |
| `CORS_ORIGINS`            | Comma-separated allowed CORS origins            | http://localhost:3000 |

## API Overview

All endpoints are documented interactively in Swagger UI. Highlights:

### Auth (`/api/v1/auth`) — public
- `POST /register` — create account, sends verification email
- `GET /verify-email?token=...`
- `POST /login` — returns `mfaRequired: true` if MFA is enabled and no OTP was supplied
- `POST /refresh` — rotates refresh token
- `POST /logout`
- `POST /forgot-password`
- `POST /reset-password`

### Profile (`/api/v1/users/me`) — authenticated
- `GET /`, `PUT /`
- `POST /change-password`
- `POST /mfa/setup`, `POST /mfa/confirm`, `POST /mfa/disable`

### Admin (`/api/v1/admin/...`) — requires `ROLE_ADMIN` or the relevant permission
- `/users` — list, enable/disable, unlock, assign roles, delete
- `/roles` — CRUD + permission assignment
- `/permissions` — CRUD
- `/audit-logs` — query the audit trail

## Security Notes

- Passwords are hashed with BCrypt (strength 12).
- Refresh tokens are opaque, persisted, and rotated on every use — a stolen refresh
  token can be revoked immediately, unlike a self-contained JWT.
- The `forgot-password` endpoint always returns success regardless of whether the
  email exists, to prevent account enumeration.
- Method-level security (`@PreAuthorize`) enforces RBAC on every admin endpoint in
  addition to the global URL-based rules in `SecurityConfig`.
