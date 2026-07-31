import os
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(
    title="Aegivion Security Engine",
    version="0.1.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mocked rules loaded
RULES = [
    "aws_s3_bucket_public_access",
    "azure_vm_ssh_open",
    "gcp_k8s_private_nodes"
]

@app.get("/")
def read_root():
    return {"service": "security-engine", "status": "running"}

@app.get("/health")
def health():
    return {
        "status": "operational",
        "rules_loaded": len(RULES),
        "engine": "ready",
        "service": "security"
    }
