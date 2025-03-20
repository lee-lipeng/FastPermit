"""
依赖项工具模块

此模块提供了FastAPI的依赖项函数，用于在API路由中进行用户认证和授权。
这些依赖项可以被注入到路由函数中，以确保只有授权用户才能访问特定的API端点。
"""
from fastapi import Depends, HTTPException, status
from jose import jwt, JWTError
from pydantic import ValidationError
from tortoise.exceptions import DoesNotExist

from app.core.config import settings
from app.core.security import oauth2_scheme
from app.models.user import User
from app.schemas.token import TokenPayload


async def get_current_user(token: str = Depends(oauth2_scheme)) -> User:
    """
    获取当前用户
    
    从请求中提取JWT令牌，验证并返回对应的用户对象。
    
    Args:
        token: JWT令牌，由依赖项自动提取
        
    Returns:
        User: 当前用户对象
        
    Raises:
        HTTPException: 如果令牌无效或用户不存在
    """
    try:
        payload = jwt.decode(
            token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM]
        )
        token_data = TokenPayload(**payload)
    except (JWTError, ValidationError):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="无法验证凭据",
        )

    try:
        user = await User.get(id=token_data.sub)
    except DoesNotExist:
        raise HTTPException(status_code=404, detail="用户不存在")

    return user


async def get_current_active_user(current_user: User = Depends(get_current_user)) -> User:
    """
    获取当前活跃用户
    
    检查用户是否处于活跃状态，如果是则返回用户对象。
    此依赖项通常用于需要用户登录且账号处于活跃状态的API端点。
    
    Args:
        current_user: 当前用户对象，由get_current_user依赖项提供
        
    Returns:
        User: 当前活跃用户对象
        
    Raises:
        HTTPException: 如果用户未激活
    """
    if not current_user.is_active:
        raise HTTPException(status_code=400, detail="用户未激活")
    return current_user
