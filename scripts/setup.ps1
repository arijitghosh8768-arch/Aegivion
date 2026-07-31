Write-Host "Setting up development environments..." -ForegroundColor Green

# Backend setup
Write-Host "Setting up Backend..."
cd packages/backend
python -m venv .venv
& .venv/Scripts/Activate.ps1
pip install -r requirements.txt
cd ../..

# Security setup
Write-Host "Setting up Security..."
cd packages/security
python -m venv .venv
& .venv/Scripts/Activate.ps1
pip install -r requirements.txt
cd ../..

# AI setup
Write-Host "Setting up AI..."
cd packages/ai
python -m venv .venv
& .venv/Scripts/Activate.ps1
pip install -r requirements.txt
cd ../..

# Frontend setup
Write-Host "Setting up Frontend..."
cd packages/frontend
npm install
cd ../..

Write-Host "Setup complete!" -ForegroundColor Green
