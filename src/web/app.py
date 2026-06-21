from fastapi import FastAPI

from src.web.routes import router

app = FastAPI(title="DepShield")
app.include_router(router)
