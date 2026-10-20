from fastapi import APIRouter

from app.modules.identity.routes.auth_router import router as auth_router
from app.modules.identity.routes.users_router import router as users_router

router = APIRouter()
router.include_router(auth_router)
router.include_router(users_router)
