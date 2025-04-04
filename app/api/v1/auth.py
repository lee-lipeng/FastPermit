"""
认证模块

此模块提供了用户认证相关的API，包括登录、重置密码等功能。
"""

from datetime import timedelta, datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm

from app.core.config import settings
from app.core.security import create_access_token, get_password_hash, verify_password
from app.models.user import User
from app.schemas.token import Token
from app.core.logger import logger
from app.core.permissions import permission_required, get_current_active_user
from app.core.exceptions import APIException, AuthenticationError

router = APIRouter()


@router.post("/login", response_model=Token)
async def login_access_token(
        form_data: OAuth2PasswordRequestForm = Depends(),
) -> Any:
    """
    OAuth2 兼容的令牌登录，获取访问令牌
    
    Args:
        form_data: OAuth2表单数据，包含username和password
        
    Returns:
        Token: 包含访问令牌和令牌类型的对象
        
    Raises:
        HTTPException: 认证失败或用户未激活时抛出
    """
    # 查找用户
    user = await User.get_or_none(username=form_data.username)

    # 用户不存在
    if user is None:
        logger.warning(f"登录失败: 用户 {form_data.username} 不存在")
        raise AuthenticationError(message="用户名或密码错误")

    # 密码错误
    if not verify_password(form_data.password, user.hashed_password):
        logger.warning(f"登录失败: 用户 {user.username} 密码错误")
        raise AuthenticationError(message="用户名或密码错误")

    # 用户未激活
    if not user.is_active:
        logger.warning(f"登录失败: 用户 {user.username} 未激活")
        raise APIException(message="用户未激活，请联系管理员")

    # 更新最后登录时间
    user.last_login = datetime.now()
    await user.save()

    # 创建访问令牌
    access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        subject=user.id, expires_delta=access_token_expires
    )
    logger.info(f"登录成功: 用户 {user.username} (ID: {user.id})")

    return {
        "access_token": access_token,
        "token_type": "bearer",
    }


@router.post("/reset-password", status_code=status.HTTP_200_OK)
async def reset_password(
        old_password: str,
        new_password: str,
        current_user: User = Depends(get_current_active_user),
) -> dict:
    """
    自己重置密码
    
    Args:
        old_password: 旧密码
        new_password: 新密码
        current_user: 当前用户
        
    Returns:
        dict: 包含操作结果消息的字典
        
    Raises:
        HTTPException: 用户不存在或原密码错误时抛出
    """

    # 原密码错误
    if not verify_password(old_password, current_user.hashed_password):
        logger.warning(f"重置密码失败: 用户 {current_user.username} 原密码错误")
        raise APIException(message="原密码错误")

    # 更新密码
    current_user.hashed_password = get_password_hash(new_password)
    await current_user.save()

    logger.info(f"重置密码成功: 用户 {current_user.username} (ID: {current_user.id})")

    return {"message": "密码已重置"}


@router.get("/test-permission")
@permission_required(("user", "read"), allow_super_admin=False)
async def test_permission(current_user: User = None):
    """
    测试权限系统
    
    此路由需要 user:read 权限才能访问，且超级管理员也不能绕过
    """
    logger.info(f"用户 {current_user.id} 成功访问了需要权限的测试路由")

    return {
        "user_id": current_user.id,
        "username": current_user.username
    }


@router.post("/clear-permission-cache")
@permission_required(("permission", "update"))
async def clear_permission_cache(current_user: User = None):
    """
    清除所有权限缓存
    
    此路由需要 permission:update 权限才能访问
    """
    from app.core.permissions import clear_all_permissions_cache

    await clear_all_permissions_cache()

    return {"message": "所有权限缓存已清除"}


@router.get("/my-permissions")
async def get_my_permissions(current_user: User = Depends(get_current_active_user)):
    """
    获取当前用户的角色和权限信息
    """
    from app.core.permissions import PermissionChecker

    # 获取用户角色
    await current_user.fetch_related("roles")
    roles = [{"id": role.id, "name": role.name} for role in current_user.roles]

    # 获取用户直接权限
    await current_user.fetch_related("permissions")
    direct_permissions = [{"id": perm.id, "name": perm.name} for perm in current_user.permissions]

    # 获取用户所有权限（包括角色继承的）
    checker = PermissionChecker()
    all_permissions = await checker.get_user_permissions(current_user.id)
    all_permissions_list = [f"{p[0]}:{p[1]}" for p in all_permissions]

    # 检查是否为超级管理员
    is_superadmin = await current_user.is_superadmin()

    return {
        "user_id": current_user.id,
        "username": current_user.username,
        "is_superadmin": is_superadmin,
        "roles": roles,
        "direct_permissions": direct_permissions,
        "all_permissions": all_permissions_list,
        "permissions_count": len(all_permissions_list)
    }
