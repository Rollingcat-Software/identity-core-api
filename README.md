# Identity Core API

A robust and scalable identity and authentication service API built for modern applications.

## Overview

Identity Core API provides a comprehensive solution for managing user authentication, authorization, and identity management. This service is designed to be the central authentication and identity provider for your application ecosystem.

## Features

- **User Authentication**: Secure user authentication with multiple strategies
- **Identity Management**: Complete user profile and identity lifecycle management
- **Token Management**: JWT-based token generation and validation
- **Role-Based Access Control (RBAC)**: Fine-grained permission and role management
- **Multi-Factor Authentication (MFA)**: Enhanced security with 2FA/MFA support
- **OAuth 2.0 / OpenID Connect**: Industry-standard authentication protocols
- **Session Management**: Secure session handling and persistence
- **API Security**: Built-in security features including rate limiting and CSRF protection

## Getting Started

### Prerequisites

Before you begin, ensure you have the following installed:
- Node.js (v18 or higher) / .NET 8.0+ / Python 3.11+ (depending on implementation)
- Database (PostgreSQL, MySQL, or MongoDB)
- Redis (for session management and caching)

### Installation

```bash
# Clone the repository
git clone https://github.com/Rollingcat-Software/identity-core-api.git

# Navigate to the project directory
cd identity-core-api

# Install dependencies
npm install
# or
dotnet restore
# or
pip install -r requirements.txt

# Set up environment variables
cp .env.example .env
# Edit .env with your configuration
```

### Configuration

Configure the application by setting the following environment variables:

```env
# Database Configuration
DATABASE_URL=postgresql://user:password@localhost:5432/identity_db

# Redis Configuration
REDIS_URL=redis://localhost:6379

# JWT Configuration
JWT_SECRET=your-secret-key
JWT_EXPIRATION=3600

# Server Configuration
PORT=3000
NODE_ENV=development
```

### Running the Application

```bash
# Development mode
npm run dev
# or
dotnet run
# or
python main.py

# Production mode
npm start
# or
dotnet run --configuration Release
# or
gunicorn main:app
```

The API will be available at `http://localhost:3000` (or your configured port).

## API Documentation

### Authentication Endpoints

```
POST   /api/auth/register        - Register a new user
POST   /api/auth/login           - Authenticate user and get token
POST   /api/auth/logout          - Invalidate user session
POST   /api/auth/refresh         - Refresh access token
POST   /api/auth/forgot-password - Request password reset
POST   /api/auth/reset-password  - Reset password with token
```

### User Management Endpoints

```
GET    /api/users                - Get all users (admin)
GET    /api/users/:id            - Get user by ID
PUT    /api/users/:id            - Update user information
DELETE /api/users/:id            - Delete user (admin)
GET    /api/users/me             - Get current user profile
PUT    /api/users/me             - Update current user profile
```

### Role & Permission Endpoints

```
GET    /api/roles                - Get all roles
POST   /api/roles                - Create a new role
GET    /api/roles/:id            - Get role by ID
PUT    /api/roles/:id            - Update role
DELETE /api/roles/:id            - Delete role
POST   /api/roles/:id/permissions - Assign permissions to role
```

For detailed API documentation, visit `/api/docs` when the server is running (Swagger/OpenAPI documentation).

## Architecture

```
identity-core-api/
├── src/
│   ├── controllers/      # Request handlers
│   ├── models/          # Data models
│   ├── services/        # Business logic
│   ├── middleware/      # Custom middleware
│   ├── routes/          # API routes
│   ├── utils/           # Utility functions
│   └── config/          # Configuration files
├── tests/               # Test files
├── docs/                # Additional documentation
└── migrations/          # Database migrations
```

## Security

This API implements several security best practices:

- **Password Hashing**: Uses bcrypt/Argon2 for secure password storage
- **JWT Tokens**: Stateless authentication with signed tokens
- **Rate Limiting**: Protection against brute force attacks
- **Input Validation**: Comprehensive request validation
- **CORS**: Configurable Cross-Origin Resource Sharing
- **Helmet**: Security headers middleware
- **SQL Injection Prevention**: Parameterized queries
- **XSS Protection**: Input sanitization and output encoding

## Testing

```bash
# Run all tests
npm test
# or
dotnet test
# or
pytest

# Run tests with coverage
npm run test:coverage
# or
dotnet test /p:CollectCoverage=true
# or
pytest --cov

# Run integration tests
npm run test:integration
```

## Deployment

### Docker

```bash
# Build the Docker image
docker build -t identity-core-api .

# Run the container
docker run -p 3000:3000 --env-file .env identity-core-api
```

### Docker Compose

```bash
# Start all services (API, database, Redis)
docker-compose up -d

# Stop all services
docker-compose down
```

## Contributing

We welcome contributions! Please see our [Contributing Guidelines](CONTRIBUTING.md) for details.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Support

For support, please:
- Open an issue in the GitHub repository
- Contact the maintainers at support@rollingcat-software.com
- Check the [documentation](docs/) for detailed guides

## Roadmap

- [ ] Social authentication (Google, Facebook, GitHub)
- [ ] Passwordless authentication
- [ ] Biometric authentication support
- [ ] Advanced audit logging
- [ ] User activity monitoring
- [ ] API key management
- [ ] Webhook support for events
- [ ] Multi-tenancy support

## Acknowledgments

- Built with modern web technologies
- Inspired by industry best practices
- Community contributions and feedback

---

**Rollingcat Software** © 2025