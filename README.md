# 🔐 Auth-as-a-Service with Fraud Detection

A production-ready authentication service with ML-powered fraud detection using FastAPI, PostgreSQL, Redis, and scikit-learn.

## 🎯 Features

- ✅ **User Authentication**: Registration, login with JWT tokens
- 🤖 **ML Fraud Detection**: Isolation Forest algorithm detects suspicious login patterns
- 🚦 **Rate Limiting**: Prevents brute-force attacks
- 📊 **Login Tracking**: Comprehensive logging of all authentication attempts
- 🔒 **Security**: Password hashing with bcrypt, JWT tokens
- 🐳 **Docker Ready**: Complete docker-compose setup
- ✅ **Tested**: Comprehensive test suite with pytest

## 🏗️ Architecture

```text
User Request → FastAPI Endpoint → Service Layer → CRUD Layer → Database
                      ↓
                 ML Fraud Detector (Isolation Forest)
                      ↓
                 Redis (Rate Limiting)
```

## 🚀 Quick Start

### Prerequisites
- Python 3.12+
- uv (package manager)
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
| POST | `/api/v1/auth/login` | Login and get JWT token |
| GET | `/api/v1/auth/me` | Get current user (protected) |

### Fraud Detection

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v1/fraud/predict` | Predict fraud probability |
| POST | `/api/v1/fraud/train` | Train ML model with historical data |
| GET | `/api/v1/fraud/status` | Get model status |

## 🧪 Testing

```bash
# Run all tests
uv run pytest

# Run with coverage
uv run pytest --cov=src tests/

# Run specific test file
uv run pytest tests/test_auth.py -v
```

## 🤖 ML Fraud Detection

The service uses **Isolation Forest** to detect anomalous login patterns.

### Features Used:
- Hour of day
- Day of week
- Is weekend
- Is night time
- Email length
- IP address (numeric hash)
- User agent presence

### Training:
```bash
# Register some users and perform logins
# Then train the model
curl -X POST http://localhost:8000/api/v1/fraud/train
```

### Prediction:
The model automatically predicts fraud probability on every login attempt. If `fraud_score > 0.7`, the login is blocked.

## 📊 Database Schema

### Users Table
- `id`: Primary key
- `email`: Unique, indexed
- `hashed_password`: bcrypt hashed
- `is_active`: Boolean
- `is_verified`: Boolean
- `created_at`, `updated_at`, `deleted_at`: Timestamps

### Login Attempts Table
- `id`: Primary key
- `user_id`: Foreign key (nullable)
- `email`: Indexed
- `ip_address`: Client IP
- `user_agent`: Browser/client info
- `success`: Boolean
- `hour_of_day`, `day_of_week`: ML features
- `fraud_score`: ML prediction
- `attempted_at`: Timestamp, indexed

## 🔧 Configuration

Key environment variables:

```env
SECRET_KEY=<your-secret-key>
DATABASE_URL=postgresql://user:pass@host:port/db
REDIS_URL=redis://host:port/0
FRAUD_THRESHOLD=0.7
MAX_LOGIN_ATTEMPTS=5
```

## 📈 Roadmap

- [ ] Email verification
- [ ] Refresh tokens
- [ ] OAuth2 providers (Google, GitHub)
- [ ] 2FA support
- [ ] Advanced ML features (device fingerprinting)
- [ ] Kubernetes deployment
- [ ] Prometheus metrics

## 🤝 Contributing

1. Fork the repository
2. Create feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open Pull Request

## 📝 License

MIT License - see LICENSE file

## 👤 Author

Daniel Palomeque - [GitHub](https://github.com/danielpcar9)

---

Built with ❤️ using FastAPI, scikit-learn, and modern Python practices.