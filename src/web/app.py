from fastapi import FastAPI
from src.web.routes import router
from src.web.middleware import RateLimitMiddleware

app = FastAPI(title="DepShield")
app.add_middleware(RateLimitMiddleware, max_requests=10, window_seconds=60)
app.include_router(router)
