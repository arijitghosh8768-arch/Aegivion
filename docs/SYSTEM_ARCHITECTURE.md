# System Architecture

The Aegivion platform utilizes a modern, decoupled microservices architecture optimized for scalability, real-time graph analysis, and AI-driven insights.

## High-Level Data Flow

1. **Client / Frontend (React + Vite)**
   - The user interacts with the React-based Single Page Application (SPA).
   - Handles graph visualization (Cytoscape/D3), dashboards, and the AI Chat UI.
   - Communicates with the backend via REST APIs and WebSockets.

2. **Reverse Proxy & Load Balancer (Nginx)**
   - Acts as the entry point for all incoming HTTP/HTTPS traffic.
   - Routes `/api/*` requests to the FastAPI backend.
   - Serves static frontend assets.
   - Terminates SSL/TLS connections.

3. **Backend Service (FastAPI / Python)**
   - **API Layer**: Handles routing, authentication (JWT), and request validation.
   - **Business Logic**: Processes findings, handles cloud account integrations, and orchestrates the AI explanation features.
   - **Workers**: Interfaces with Celery for asynchronous tasks (e.g., cloud asset ingestion, compliance scanning).

4. **Data Storage & Caching Layer**
   - **PostgreSQL**: The primary relational database. Stores Users, Organizations, Cloud Accounts, Assets, and Findings. Ensures ACID compliance for critical state.
   - **Redis**: Used as an in-memory cache for fast session lookups and frequently accessed API responses. Also serves as the message broker for Celery background tasks.
   - **Qdrant**: Vector database powering the AI Chat and Explain features. Stores embeddings of cloud architectures and security policies, enabling rapid RAG (Retrieval-Augmented Generation) queries to identify contextually relevant attack paths.

## Flow Example: Attack Path Detection & Explanation
1. Celery worker ingests AWS metadata -> stored in **PostgreSQL**.
2. Security engine identifies a misconfiguration -> creates a `Finding`.
3. Finding metadata is vectorized and stored in **Qdrant**.
4. User clicks "Explain Risk" in the **React Frontend**.
5. Request hits **Nginx** -> routed to **FastAPI**.
6. FastAPI queries **Qdrant** for context, queries the LLM, and returns a plain-English explanation to the frontend.
