from fastapi import APIRouter

from app.api.v1 import auth, permissions, roles, users, resource_types, action_types

api_router = APIRouter()
api_router.include_router(auth.router, prefix="/auth", tags=["认证"])
api_router.include_router(users.router, prefix="/users", tags=["用户管理"])
api_router.include_router(roles.router, prefix="/roles", tags=["角色管理"])
api_router.include_router(permissions.router, prefix="/permissions", tags=["权限管理"])
api_router.include_router(resource_types.router, prefix="/resource-types", tags=["资源类型管理"])
api_router.include_router(action_types.router, prefix="/action-types", tags=["操作类型管理"])
