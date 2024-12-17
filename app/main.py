from fastapi import FastAPI
from app.routers import test
from app.db.base import engine, Base
from app.routers import users

Base.metadata.create_all(bind=engine)

app = FastAPI()

app.include_router(test.router, tags=["test"])
app.include_router(users.router, prefix="/api")