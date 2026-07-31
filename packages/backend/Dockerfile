FROM python:3.11-slim

WORKDIR /app

COPY packages/backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY packages/backend .
COPY packages/security /security
COPY packages/ai /ai

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]
