# 🔐 Auth-as-a-Service with Fraud Detection

A production-ready authentication service with ML-powered fraud detection using FastAPI, PostgreSQL, Redis, and scikit-learn.

## 🎯 Features

- ✅ **User Authentication**: Registration, multi-device login with Sanctum-style opaque tokens
- 🤖 **ML Fraud Detection**: Enhanced Isolation Forest algorithm with deterministic IP hashing and refined scoring
- 📊 **Business Observability**: Prometheus-ready metrics for monitoring logins, fraud rates, and more
- ⏳ **Async Training**: Background model training using FastAPI BackgroundTasks
- 🚦 **Rate Limiting**: Redis-backed rate limiting to prevent brute-force attacks
- 🔒 **Security**: Password hashing with bcrypt, SHA-256 token hashing, granular revocation
- 🐳 **Docker Ready**: Modern containerized setup with Docker Compose
- ✅ **Tested**: Comprehensive test suite with pytest and structural improvements

## 🏗️ Architecture

```text
User Request → FastAPI Endpoint → Service Layer → CRUD Layer → Database
                      ↓                      ↓
                 ML Fraud Detector      Business Metrics
                      ↓                      ↓
                 Redis (Rate Limit)     Prometheus (Exporter)
                      ↓
                 BackgroundTasks (Async ML Training)
```

## 🚀 Quick Start

### Prerequisites
- Python 3.12+
- [uv](https://github.com/astral-sh/uv) (package manager)
- Docker & Docker Compose (optional)

### Local Development

```bash
# Clone repository
git clone <your-repo>
cd auth-service

# Install dependencies
uv sync

# Setup environment
cp .env.example .env
# Edit .env with your settings

# Start services (PostgreSQL + Redis)
docker-compose up postgres redis -d

# Run migrations
uv run alembic upgrade head

# Start development server
uv run fastapi dev src/main.py
```

Visit: http://localhost:8000/api/v1/docs

### Docker (Full Stack)

```bash
# Start all services
docker-compose up -d

# Run migrations
docker-compose exec api uv run alembic upgrade head

# View logs
docker-compose logs -f api
```

## 📚 API Endpoints

### Authentication

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v1/auth/register` | Register new user |
| POST | `/api/v1/auth/login` | Login and get an opaque access token |

### Tokens (Device Management)

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/tokens/` | List all active tokens (devices) for current user |
| DELETE | `/api/v1/tokens/{id}` | Revoke a specific token (logout from one device) |
| DELETE | `/api/v1/tokens/` | Revoke all tokens (logout everywhere) |

### Fraud Detection

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v1/fraud/predict` | Predict fraud probability (manual check) |
| POST | `/api/v1/fraud/train` | Trigger background model training |
| GET | `/api/v1/fraud/status` | Get model health and status |

### Metrics (Observability)

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/metrics/` | Prometheus format metrics |
| GET | `/api/v1/metrics/stats` | JSON summary statistics |

## 🧪 Testing

```bash
# Run all tests
uv run pytest

# Run with coverage
uv run pytest --cov=src tests/

# Run specific test file
uv run pytest tests/test_improvements.py -v
```

## 🤖 ML Fraud Detection

The service uses **Isolation Forest** to detect anomalous login patterns. Recent improvements include:
- **Deterministic IP Hashing**: Stable representation of IP addresses as numerical features.
- **Refined Scoring**: Better thresholding for high-risk attempts.
- **Background Training**: Zero-downtime model updates via asynchronous tasks.

## 📊 Database Schema

### Users Table
- `id`, `email`, `hashed_password`, `is_active`, `is_verified`
- `created_at`, `updated_at`, `deleted_at`

### Login Attempts Table
- `id`, `user_id`, `email`, `ip_address`, `user_agent`, `success`
- `hour_of_day`, `day_of_week`: ML features
- `fraud_score`: ML prediction
- `attempted_at`: Timestamp, indexed

### Personal Access Tokens Table (Sanctum-style)
- `id`, `user_id`, `name`, `token` (SHA-256 hashed)
- `abilities` (JSON scopes), `last_used_at`, `expires_at`, `created_at`

## 📈 Roadmap

- [ ] Email verification & MFA
- [ ] Refresh tokens support
- [ ] OAuth2 providers (Google, GitHub)
- [x] Prometheus & Grafana Integration
- [x] Async Model Training
- [ ] Kubernetes manifestation files
- [ ] Advanced device fingerprinting

## 👤 Author

Daniel Palomeque - [GitHub](https://github.com/danielpcar9)

---

Built with ❤️ using FastAPI, scikit-learn, and modern Python practices.

Built with ❤️ using FastAPI, scikit-learn, and modern Python practices.