import re

with open('packages/backend/app/main.py', 'r', encoding='utf-8') as f:
    content = f.read()

lifespan_logic = '''
from contextlib import asynccontextmanager
import asyncio

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: Start the automation worker
    from app.workers.automation_worker import automation_worker_loop
    worker_task = asyncio.create_task(automation_worker_loop())
    yield
    # Shutdown: Cancel the worker
    worker_task.cancel()

app = FastAPI(
    title="Aegivion API",
    description="Backend API for Aegivion Security Platform",
    version="0.1.0",
    lifespan=lifespan
)
'''

content = re.sub(r'app = FastAPI\([\s\S]*?version="0\.1\.0"\n\)', lifespan_logic, content)

with open('packages/backend/app/main.py', 'w', encoding='utf-8') as f:
    f.write(content)
print("Main patched with worker lifespan!")
