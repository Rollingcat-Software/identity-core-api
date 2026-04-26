# Identity Core API

![Java](https://img.shields.io/badge/Java-21-orange.svg)
![Spring Boot](https://img.shields.io/badge/Spring%20Boot-3.4.7-green.svg)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-17%20%2B%20pgvector-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)

## Overview

Identity Core API is the authentication and identity management microservice for the **FIVUCSAS** biometric identity platform. Built with Spring Boot 3.4.7 on Java 21, it follows Hexagonal Architecture (ports & adapters) and provides:

- Ten composable authentication methods (password, email/SMS OTP, TOTP, QR code, face, voice, fingerprint, hardware key, NFC document) orchestrated through tenant-configured MFA flows
- A production-grade OAuth 2.0 / OIDC authorization server with hosted-first redirective login (`display=page` content negotiation), PKCE S256, JWKS, discovery, OIDC nonce validation, and RFC 8252-compliant loopback + custom-scheme redirect URIs
- Multi-tenant data isolation, RBAC, JWT access + refresh tokens, and rate-limited endpoints backed by Redis
- GDPR Art. 17 / Art. 20 compliance (user data export + flag-gated soft-delete purge with 30-day retention)

Engineering Project at **Marmara University's Computer Engineering Department** — CSE4297 / CSE4197.

## Table of Contents

- [Features](#features)
- [Architecture](#architecture)
- [Technology Stack](#technology-stack)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Configuration](#configuration)
- [Running the Application](#running-the-application)
- [API Documentation](#api-documentation)
- [Database Schema](#database-schema)
- [Security](#security)
- [Multi-Tenancy](#multi-tenancy)
- [Testing](#testing)
- [Deployment](#deployment)
- [Integration with Other Services](#integration-with-other-services)
- [Monitoring and Logging](#monitoring-and-logging)
- [Contributing](#contributing)
- [Roadmap](#roadmap)
- [License](#license)

## Features

### Core Functionality

- **Multi-Tenant Architecture**: Complete tenant isolation with row-level security in PostgreSQL
- **User Management**: Comprehensive CRUD operations for users with role-based access control
- **Authentication & Authorization**: JWT-based stateless authentication with refresh token support
- **Role-Based Access Control (RBAC)**: Fine-grained permission management system
- **Tenant Management**: Full lifecycle management for SaaS tenants
- **Security Policies**: Configurable authentication rules and access policies per tenant
- **Audit Logging**: Complete audit trail for all security-sensitive operations
- **API Gateway Integration**: RESTful API designed for microservices communication

### Advanced Features

- **Biometric Integration**: Seamless integration with Biometric Processor API
- **Event-Driven Architecture**: Redis-based message queue for asynchronous operations
- **Physical & Digital Access**: Unified identity for both door access and system login
- **Session Management**: Distributed session handling with Redis
- **Data Encryption**: AES-256 encryption for sensitive data at rest
- **TLS/SSL Support**: Secure communication channels
- **Rate Limiting**: Protection against brute force and DoS attacks
- **KVKK/GDPR Compliance**: Built-in compliance with data protection regulations

## Architecture

This service follows **Hexagonal Architecture** (Ports and Adapters) principles, ensuring clean separation of concerns
and testability.

```
identity-core-api/
├── src/
│   ├── main/
│   │   ├── java/
│   │   │   └── com/fivucsas/identity/
│   │   │       ├── domain/              # Business logic & entities
│   │   │       │   ├── model/           # Domain entities
│   │   │       │   ├── repository/      # Repository interfaces
│   │   │       │   ├── service/         # Domain services
│   │   │       │   └── exception/       # Domain exceptions
│   │   │       ├── application/         # Application services
│   │   │       │   ├── port/            # Input/Output ports
│   │   │       │   ├── usecase/         # Use case implementations
│   │   │       │   └── dto/             # Data transfer objects
│   │   │       ├── infrastructure/      # External adapters
│   │   │       │   ├── persistence/     # JPA implementations
│   │   │       │   ├── security/        # Security configurations
│   │   │       │   ├── messaging/       # Redis message queue
│   │   │       │   └── external/        # External API clients
│   │   │       └── adapter/             # API adapters
│   │   │           ├── rest/            # REST controllers
│   │   │           ├── graphql/         # GraphQL resolvers (future)
│   │   │           └── web/             # Web MVC controllers
│   │   └── resources/
│   │       ├── application.yml          # Main configuration
│   │       ├── application-dev.yml      # Development config
│   │       ├── application-prod.yml     # Production config
│   │       └── db/
│   │           └── migration/           # Flyway migrations
│   └── test/
│       ├── java/                        # Unit & Integration tests
│       └── resources/                   # Test resources
├── docker/
│   ├── Dockerfile                       # Multi-stage Docker build
│   └── docker-compose.yml               # Local development setup
├── docs/
│   ├── api/                             # API documentation
│   ├── architecture/                    # Architecture diagrams
│   └── deployment/                      # Deployment guides
├── .github/
│   └── workflows/                       # CI/CD pipelines
├── .mvn/                                # Maven wrapper
├── pom.xml                              # Build configuration
├── .gitignore
├── .env.example                         # Environment variables template
├── README.md
└── LICENSE
```

### Architecture Diagram

```
┌─────────────────────────────────────────────────────────────┐
│                     API Gateway (Future)                     │
└───────────────────────────┬─────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│                    Identity Core API                         │
│  ┌──────────────────────────────────────────────────────┐   │
│  │         REST Controllers (Adapter Layer)              │   │
│  └────────────────┬─────────────────────────────────────┘   │
│                   │                                          │
│  ┌────────────────▼─────────────────────────────────────┐   │
│  │      Application Services (Use Cases/Ports)           │   │
│  └────────────────┬─────────────────────────────────────┘   │
│                   │                                          │
│  ┌────────────────▼─────────────────────────────────────┐   │
│  │         Domain Services (Business Logic)              │   │
│  │  • UserService  • TenantService  • RoleService        │   │
│  └────────────────┬─────────────────────────────────────┘   │
│                   │                                          │
│  ┌────────────────▼─────────────────────────────────────┐   │
│  │            Infrastructure Layer                       │   │
│  │  • JPA Repositories  • Redis  • Message Queue         │   │
│  └───────────────────────────────────────────────────────┘   │
└─────────────┬───────────────────────────────┬───────────────┘
              │                               │
              ▼                               ▼
    ┌──────────────────┐          ┌────────────────────┐
    │   PostgreSQL     │          │  Redis (Cache &    │
    │   + pgvector     │          │  Message Queue)    │
    └──────────────────┘          └────────────────────┘
              │
              ▼
    ┌──────────────────┐
    │ Biometric         │
    │ Processor API     │
    └──────────────────┘
```

## Technology Stack

### Core Technologies

- **Java 21**: Latest LTS version with modern language features
- **Spring Boot 3.2+**: Enterprise-grade framework
- **Spring Security 6**: Authentication and authorization
- **Spring Data JPA**: Data persistence layer
- **PostgreSQL 16**: Primary relational database
- **pgvector**: Vector similarity search for biometric data
- **Redis 7**: Caching and message queue
- **Maven**: Build automation tool

### Libraries & Frameworks

- **Hibernate**: ORM implementation
- **Flyway**: Database migration management
- **Lombok**: Boilerplate code reduction
- **MapStruct**: DTO mapping
- **JWT (jjwt)**: Token-based authentication
- **SpringDoc OpenAPI**: API documentation
- **Resilience4j**: Circuit breaker and resilience patterns
- **Micrometer**: Application metrics
- **SLF4J + Logback**: Logging framework

### Development & Testing

- **JUnit 5**: Unit testing
- **Mockito**: Mocking framework
- **TestContainers**: Integration testing with Docker
- **RestAssured**: REST API testing
- **JaCoCo**: Code coverage
- **SonarQube**: Code quality analysis

### DevOps & Deployment

- **Docker**: Containerization
- **Docker Compose**: Multi-container orchestration
- **GitHub Actions**: CI/CD pipeline
- **Kubernetes** (Future): Production orchestration

## Prerequisites

Before setting up the project, ensure you have the following installed:

- **Java Development Kit (JDK) 21** or higher
- **Maven 3.9+** (or use the included Maven wrapper)
- **PostgreSQL 16+** with pgvector extension
- **Redis 7+**
- **Docker & Docker Compose** (for containerized deployment)
- **Git** for version control
- **IDE**: IntelliJ IDEA (recommended) or Eclipse

## Installation

### 1. Clone the Repository

```bash
git clone https://github.com/Rollingcat-Software/identity-core-api.git
cd identity-core-api
```

### 2. Set Up Environment Variables

Copy the example environment file and configure it:

```bash
cp .env.example .env
```

Edit `.env` with your configuration:

```env
# Application Configuration
SPRING_PROFILES_ACTIVE=dev
SERVER_PORT=8080

# Database Configuration
DB_HOST=localhost
DB_PORT=5432
DB_NAME=identity_core_db
DB_USERNAME=postgres
DB_PASSWORD=your_secure_password
DB_SCHEMA=public

# Redis Configuration
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_PASSWORD=

# JWT Configuration
JWT_SECRET=your-256-bit-secret-key-change-this-in-production
JWT_ACCESS_TOKEN_EXPIRATION=3600000        # 1 hour in milliseconds
JWT_REFRESH_TOKEN_EXPIRATION=604800000     # 7 days in milliseconds

# Biometric Processor API
BIOMETRIC_PROCESSOR_URL=http://localhost:8001
BIOMETRIC_PROCESSOR_API_KEY=your-api-key

# Security Configuration
CORS_ALLOWED_ORIGINS=http://localhost:3000,http://localhost:4200
ENCRYPTION_KEY=your-aes-256-encryption-key

# Logging
LOGGING_LEVEL_ROOT=INFO
LOGGING_LEVEL_APP=DEBUG

# Multi-tenancy
TENANT_ISOLATION_LEVEL=SCHEMA  # SCHEMA or ROW_LEVEL
```

### 3. Set Up the Database

#### Option A: Using Docker

```bash
# Start PostgreSQL with pgvector
docker-compose up -d postgres

# The database will be automatically initialized with Flyway migrations
```

#### Option B: Manual Setup

```bash
# Connect to PostgreSQL
psql -U postgres

# Create database
CREATE DATABASE identity_core_db;

# Connect to the database
\c identity_core_db

# Enable pgvector extension
CREATE EXTENSION IF NOT EXISTS vector;

# Exit psql
\q
```

### 4. Start Redis

```bash
# Using Docker
docker-compose up -d redis

# Or install locally on your system
# For Ubuntu/Debian:
sudo apt-get install redis-server
sudo systemctl start redis

# For macOS:
brew install redis
brew services start redis

# For Windows:
# Download from https://redis.io/download
```

### 5. Build the Application

```bash
# Using Maven (recommended)
mvn clean package

# Skip tests for faster build
mvn clean package -DskipTests
```

## Configuration

### Application Profiles

The application supports multiple profiles:

- **dev**: Development environment with detailed logging
- **test**: Testing environment with in-memory database
- **prod**: Production environment with optimized settings

Activate a profile:

```bash
# Via environment variable
export SPRING_PROFILES_ACTIVE=dev

# Via application argument
java -jar app.jar --spring.profiles.active=dev
```

### Multi-Tenancy Configuration

Configure tenant isolation in `application.yml`:

```yaml
fivucsas:
  multitenancy:
    enabled: true
    isolation-level: ROW_LEVEL  # or SCHEMA
    default-tenant: system
    tenant-header-name: X-Tenant-ID

security:
  jwt:
    secret: ${JWT_SECRET}
    access-token-expiration: ${JWT_ACCESS_TOKEN_EXPIRATION}
    refresh-token-expiration: ${JWT_REFRESH_TOKEN_EXPIRATION}

  encryption:
    algorithm: AES
    key-size: 256
    key: ${ENCRYPTION_KEY}
```

## Running the Application

### Development Mode

```bash
# Using Maven
mvn spring-boot:run -Dspring-boot.run.profiles=dev
```

### Using Docker

```bash
# Build and run all services
docker-compose up -d

# View logs
docker-compose logs -f identity-core-api

# Stop services
docker-compose down

# Rebuild after code changes
docker-compose up -d --build
```

### Production Mode

```bash
# Build the JAR
mvn clean package -DskipTests

# Run the JAR
java -jar target/identity-core-api-1.0.0-MVP.jar

# Or with custom JVM options
java -Xms512m -Xmx2048m -jar target/identity-core-api-1.0.0-MVP.jar
```

The API will be available at: `http://localhost:8080`

Swagger UI documentation: `http://localhost:8080/swagger-ui.html`

## API Documentation

### Base URL

```
http://localhost:8080/api/v1
```

### Authentication Endpoints

| Method | Endpoint                 | Description                         | Auth Required       |
|--------|--------------------------|-------------------------------------|---------------------|
| POST   | `/auth/register`         | Register a new user                 | No                  |
| POST   | `/auth/login`            | Authenticate and receive JWT tokens | No                  |
| POST   | `/auth/logout`           | Invalidate refresh token            | Yes                 |
| POST   | `/auth/refresh`          | Refresh access token                | Yes (Refresh Token) |
| POST   | `/auth/forgot-password`  | Request password reset              | No                  |
| POST   | `/auth/reset-password`   | Reset password with token           | No                  |
| POST   | `/auth/verify-email`     | Verify email address                | No                  |
| POST   | `/auth/verify-biometric` | Verify biometric authentication     | No                  |

### User Management Endpoints

| Method | Endpoint                               | Description                | Auth Required | Role       |
|--------|----------------------------------------|----------------------------|---------------|------------|
| GET    | `/users`                               | List all users (paginated) | Yes           | ADMIN      |
| GET    | `/users/{id}`                          | Get user by ID             | Yes           | ADMIN/SELF |
| POST   | `/users`                               | Create new user            | Yes           | ADMIN      |
| PUT    | `/users/{id}`                          | Update user                | Yes           | ADMIN/SELF |
| DELETE | `/users/{id}`                          | Delete user                | Yes           | ADMIN      |
| GET    | `/users/me`                            | Get current user profile   | Yes           | USER       |
| PUT    | `/users/me`                            | Update current user        | Yes           | USER       |
| GET    | `/users/{id}/biometrics`               | Get user biometric info    | Yes           | ADMIN/SELF |
| POST   | `/users/{id}/biometrics`               | Enroll biometric data      | Yes           | ADMIN/SELF |
| DELETE | `/users/{id}/biometrics/{biometricId}` | Delete biometric           | Yes           | ADMIN/SELF |

### Tenant Management Endpoints

| Method | Endpoint               | Description                 | Auth Required | Role         |
|--------|------------------------|-----------------------------|---------------|--------------|
| GET    | `/tenants`             | List all tenants            | Yes           | SUPER_ADMIN  |
| GET    | `/tenants/{id}`        | Get tenant by ID            | Yes           | TENANT_ADMIN |
| POST   | `/tenants`             | Create new tenant           | Yes           | SUPER_ADMIN  |
| PUT    | `/tenants/{id}`        | Update tenant               | Yes           | TENANT_ADMIN |
| DELETE | `/tenants/{id}`        | Delete tenant               | Yes           | SUPER_ADMIN  |
| GET    | `/tenants/{id}/users`  | Get tenant users            | Yes           | TENANT_ADMIN |
| POST   | `/tenants/{id}/config` | Update tenant configuration | Yes           | TENANT_ADMIN |

### Role & Permission Endpoints

| Method | Endpoint                                 | Description          | Auth Required | Role  |
|--------|------------------------------------------|----------------------|---------------|-------|
| GET    | `/roles`                                 | List all roles       | Yes           | ADMIN |
| GET    | `/roles/{id}`                            | Get role by ID       | Yes           | ADMIN |
| POST   | `/roles`                                 | Create new role      | Yes           | ADMIN |
| PUT    | `/roles/{id}`                            | Update role          | Yes           | ADMIN |
| DELETE | `/roles/{id}`                            | Delete role          | Yes           | ADMIN |
| GET    | `/roles/{id}/permissions`                | Get role permissions | Yes           | ADMIN |
| POST   | `/roles/{id}/permissions`                | Assign permissions   | Yes           | ADMIN |
| DELETE | `/roles/{id}/permissions/{permissionId}` | Remove permission    | Yes           | ADMIN |

### Example Requests

#### Register a New User

```bash
curl -X POST http://localhost:8080/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -H "X-Tenant-ID: tenant-123" \
  -d '{
    "email": "user@example.com",
    "password": "SecureP@ssw0rd",
    "firstName": "John",
    "lastName": "Doe",
    "phoneNumber": "+905551234567"
  }'
```

#### Login

```bash
curl -X POST http://localhost:8080/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -H "X-Tenant-ID: tenant-123" \
  -d '{
    "email": "user@example.com",
    "password": "SecureP@ssw0rd"
  }'
```

Response:

```json
{
  "accessToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refreshToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "tokenType": "Bearer",
  "expiresIn": 3600,
  "user": {
    "id": "uuid",
    "email": "user@example.com",
    "firstName": "John",
    "lastName": "Doe",
    "roles": ["USER"]
  }
}
```

#### Access Protected Endpoint

```bash
curl -X GET http://localhost:8080/api/v1/users/me \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." \
  -H "X-Tenant-ID: tenant-123"
```

For complete API documentation, visit the Swagger UI at `http://localhost:8080/swagger-ui.html` when the application is
running.

## Database Schema

### Core Tables

#### users

```sql
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id),
    email VARCHAR(255) NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    first_name VARCHAR(100) NOT NULL,
    last_name VARCHAR(100) NOT NULL,
    phone_number VARCHAR(20),
    email_verified BOOLEAN DEFAULT FALSE,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login_at TIMESTAMP,
    UNIQUE(tenant_id, email)
);

CREATE INDEX idx_users_tenant_id ON users(tenant_id);
CREATE INDEX idx_users_email ON users(email);
```

#### tenants

```sql
CREATE TABLE tenants (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL UNIQUE,
    domain VARCHAR(255),
    is_active BOOLEAN DEFAULT TRUE,
    subscription_plan VARCHAR(50),
    max_users INTEGER DEFAULT 100,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

#### roles

```sql
CREATE TABLE roles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID REFERENCES tenants(id),
    name VARCHAR(100) NOT NULL,
    description TEXT,
    is_system_role BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(tenant_id, name)
);
```

#### user_roles

```sql
CREATE TABLE user_roles (
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    role_id UUID REFERENCES roles(id) ON DELETE CASCADE,
    assigned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (user_id, role_id)
);
```

#### biometric_data

```sql
CREATE TABLE biometric_data (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    biometric_type VARCHAR(50) NOT NULL,
    embedding vector(2622),  -- pgvector for face embeddings
    quality_score FLOAT,
    enrolled_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    is_active BOOLEAN DEFAULT TRUE
);

CREATE INDEX idx_biometric_user ON biometric_data(user_id);
CREATE INDEX idx_biometric_embedding ON biometric_data USING ivfflat (embedding vector_cosine_ops);
```

### Entity Relationship Diagram

```
┌─────────────┐       ┌──────────────┐       ┌──────────────┐
│   tenants   │──────<│    users     │>──────│user_biometrics│
└─────────────┘       └──────────────┘       └──────────────┘
                            │ │
                            │ │
                      ┌─────┘ └─────┐
                      │              │
                      ▼              ▼
              ┌──────────────┐  ┌──────────────┐
              │ user_roles   │  │ audit_logs   │
              └──────────────┘  └──────────────┘
                      │
                      ▼
              ┌──────────────┐
              │    roles     │
              └──────────────┘
                      │
                      ▼
              ┌──────────────┐
              │ permissions  │
              └──────────────┘
```

## Security

### Authentication Flow

1. User submits credentials (email/password) or biometric data
2. System validates credentials and tenant association
3. JWT access token and refresh token are generated
4. Client stores tokens securely
5. Client includes access token in Authorization header for subsequent requests
6. When access token expires, client uses refresh token to obtain new tokens

### Security Features

#### Password Security

- Passwords hashed with **BCrypt** (work factor 12)
- Minimum password requirements enforced
- Password history to prevent reuse
- Account lockout after failed attempts

#### Token Security

- JWT tokens signed with HS512 algorithm
- Short-lived access tokens (1 hour)
- Refresh tokens with longer expiration (7 days)
- Token blacklisting for logout
- Refresh token rotation

#### Data Encryption

- Sensitive data encrypted at rest with AES-256
- TLS 1.3 for data in transit
- Biometric vectors stored encrypted
- Database connection encryption

#### Security Headers

```yaml
Security-Headers:
  X-Content-Type-Options: nosniff
  X-Frame-Options: DENY
  X-XSS-Protection: 1; mode=block
  Strict-Transport-Security: max-age=31536000; includeSubDomains
  Content-Security-Policy: default-src 'self'
```

#### Rate Limiting

- Login attempts: 5 per 15 minutes
- API calls: 100 per minute per user
- Biometric verification: 10 per minute

## Multi-Tenancy

### Tenant Isolation Strategies

#### Row-Level Security (RLS)

- All queries automatically filtered by tenant_id
- Implemented at application level with Hibernate filters
- Most efficient for shared database schema

```java
@Filter(name = "tenantFilter", condition = "tenant_id = :tenantId")
@Entity
public class User {
    // ...
}
```

#### Schema-Based Isolation

- Each tenant has a dedicated schema
- Complete data isolation
- Higher resource usage but maximum security

### Tenant Context

Tenant is identified via:

1. Custom HTTP header: `X-Tenant-ID`
2. Subdomain: `tenant-name.fivucsas.com`
3. JWT token claim: `tenantId`

## Testing

### Running Tests

```bash
# Run all tests
mvn test

# Run specific test class
mvn test -Dtest=UserServiceTest

# Run integration tests
mvn verify -Pfailsafe

# Run with coverage
mvn test jacoco:report
```

### Test Structure

```
src/test/
├── java/
│   ├── unit/                # Unit tests
│   │   ├── domain/
│   │   ├── service/
│   │   └── util/
│   ├── integration/         # Integration tests
│   │   ├── api/
│   │   ├── repository/
│   │   └── messaging/
│   └── e2e/                 # End-to-end tests
└── resources/
    ├── application-test.yml
    └── test-data/
```

### Test Coverage Goals

- Unit tests: > 80%
- Integration tests: > 70%
- Overall coverage: > 75%

## Deployment

### Docker Deployment

```bash
# Build Docker image
docker build -t fivucsas/identity-core-api:latest .

# Run with Docker Compose
docker-compose -f docker/docker-compose.yml up -d

# Check logs
docker-compose logs -f identity-core-api
```

### Environment-Specific Deployment

#### Development

```bash
docker-compose -f docker/docker-compose.dev.yml up
```

#### Production

```bash
docker-compose -f docker/docker-compose.prod.yml up -d
```

### Kubernetes (Future)

```yaml
# Example deployment configuration
apiVersion: apps/v1
kind: Deployment
metadata:
  name: identity-core-api
spec:
  replicas: 3
  selector:
    matchLabels:
      app: identity-core-api
  template:
    metadata:
      labels:
        app: identity-core-api
    spec:
      containers:
      - name: identity-core-api
        image: fivucsas/identity-core-api:latest
        ports:
        - containerPort: 8080
        env:
        - name: SPRING_PROFILES_ACTIVE
          value: "prod"
```

## Integration with Other Services

### Biometric Processor API

Communication via REST API and Redis message queue:

```java
// Synchronous call
BiometricVerificationResult result = biometricProcessorClient
    .verifyFace(userId, imageData);

// Asynchronous message
redisMessagePublisher.publish(
    "biometric.enrollment.request",
    enrollmentRequest
);
```

### Message Queue Topics

- `biometric.enrollment.request`: User biometric enrollment
- `biometric.verification.request`: Identity verification request
- `biometric.verification.result`: Verification result
- `user.created`: New user created event
- `user.updated`: User updated event
- `tenant.created`: New tenant created event

## Monitoring and Logging

### Logging Configuration

```yaml
logging:
  level:
    root: INFO
    com.fivucsas: DEBUG
    org.springframework.security: DEBUG
  pattern:
    console: "%d{yyyy-MM-dd HH:mm:ss} - %msg%n"
  file:
    name: logs/identity-core-api.log
    max-size: 10MB
    max-history: 30
```

### Metrics

Exposed via Spring Boot Actuator:

```bash
# Health check
curl http://localhost:8080/actuator/health

# Metrics
curl http://localhost:8080/actuator/metrics

# Prometheus endpoint
curl http://localhost:8080/actuator/prometheus
```

### Health Checks

- Database connectivity
- Redis connectivity
- External service availability
- Disk space
- Memory usage

## Contributing

We welcome contributions from the team! Please follow these guidelines:

### Development Workflow

1. **Create a feature branch**
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Make your changes**
    - Follow SOLID principles
    - Adhere to Hexagonal Architecture
    - Write unit tests
    - Update documentation

3. **Commit your changes**
   ```bash
   git commit -m "feat: add user biometric enrollment feature"
   ```
   Follow [Conventional Commits](https://www.conventionalcommits.org/)

4. **Push to GitHub**
   ```bash
   git push origin feature/your-feature-name
   ```

5. **Create Pull Request**
    - Describe changes clearly
    - Reference related issues
    - Ensure CI passes

### Code Standards

- **Java Style**: Follow Google Java Style Guide
- **Naming**: Use descriptive names (DRY, KISS, YAGNI)
- **Comments**: JavaDoc for public APIs
- **Testing**: Minimum 80% coverage for new code

### Commit Message Format

```
<type>(<scope>): <subject>

<body>

<footer>
```

Types: `feat`, `fix`, `docs`, `style`, `refactor`, `test`, `chore`

## Auth Method Support Status

The system supports 10 authentication methods via pluggable handlers. **All 10 are working** as of April 2026.

| Auth Method | Handler | Status | Notes |
|---|---|---|---|
| PASSWORD | PasswordAuthHandler | Working | BCrypt with password history |
| EMAIL_OTP | EmailOtpAuthHandler | Working | 6-digit OTP via SMTP |
| SMS_OTP | SmsOtpAuthHandler | Working | Twilio ready, NoOpSmsService active |
| TOTP | TotpAuthHandler | Working | Authenticator app codes |
| QR_CODE | QrCodeAuthHandler | Working | Token-based QR scanning |
| FACE | FaceAuthHandler | Working | Via biometric-processor DeepFace |
| FINGERPRINT | FingerprintAuthHandler | Working | WebAuthn platform authenticator |
| VOICE | VoiceAuthHandler | Working | Resemblyzer 256-dim via biometric-processor |
| NFC_DOCUMENT | NfcDocumentAuthHandler | Working | Backend logic complete, mobile client needed |
| HARDWARE_KEY | HardwareKeyAuthHandler | Working | WebAuthn/FIDO2 cross-platform |

## Roadmap

### Completed (April 2026)

- [x] User authentication with JWT
- [x] Multi-tenant architecture with row-level security
- [x] Role-based access control (RBAC)
- [x] All 10 auth method handlers working
- [x] Multi-step auth flow engine
- [x] WebAuthn/FIDO2 support (fingerprint + hardware key)
- [x] OAuth 2.0 / OpenID Connect endpoints
- [x] Identity Verification Pipeline (9 step types, 7 templates)
- [x] Audit logging with comprehensive action tracking
- [x] Embeddable auth widget SDK
- [x] 528 tests passing, CI/CD on self-hosted runner
- [x] Security audit and remediation

### Future

- [ ] Social authentication (Google). (Sign in with Apple dropped 2026-04-26 — requires Apple Developer Program enrollment, no Apple hardware/account available.)
- [ ] Risk-based adaptive authentication
- [ ] Kubernetes deployment
- [ ] Production penetration test

## Troubleshooting

### Common Issues

#### Database Connection Failed

```bash
# Check PostgreSQL is running
docker-compose ps postgres

# Verify connection
psql -h localhost -U postgres -d identity_core_db
```

#### Redis Connection Failed

```bash
# Check Redis is running
docker-compose ps redis

# Test connection
redis-cli ping
```

#### Port Already in Use

```bash
# Find process using port 8080
lsof -i :8080

# Kill the process
kill -9 <PID>
```

## License

This project is part of the **FIVUCSAS** platform developed as an Engineering Project at Marmara University, Faculty of
Engineering, Computer Engineering Department.

Copyright © 2025 FIVUCSAS Team. All rights reserved.

Licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Support & Contact

- **Project Lead**: Ahmet Abdullah Gultekin
- **Advisor**: Assoc. Prof. Dr. Mustafa Agaoglu
- **GitHub Issues**: [Repository Issues](https://github.com/Rollingcat-Software/identity-core-api/issues)

## Acknowledgments

- Marmara University Computer Engineering Department
- Open Source Libraries: Spring Framework, PostgreSQL, Redis, and the entire Java ecosystem
- Inspiration from industry leaders: Okta, Auth0, Azure AD

---

**Built with passion for security and innovation** | Marmara University 2025-2026
