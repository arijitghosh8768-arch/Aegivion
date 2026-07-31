# Production Deployment Guide

## Prerequisites
- Docker 20.10+
- Docker Compose v2.0+

## Production Deployment Steps

### 1. Configure Env
```bash
cp .env.example .env
# Edit production keys in .env
```

### 2. Build Services
```bash
docker-compose -f docker-compose.prod.yml build
```

### 3. Startup Stack
```bash
docker-compose -f docker-compose.prod.yml up -d
```

### 4. Verify Health
```bash
curl http://localhost:8000/health
```
