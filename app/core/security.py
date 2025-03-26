"""
安全相关功能模块

此模块提供了与安全相关的功能，包括密码哈希、JWT令牌生成和验证、
用户认证等功能。主要用于实现API的安全访问控制。
"""
import pytz
from datetime import datetime, timedelta
from typing import Any, Optional, Union

import bcrypt
from fastapi import Depends
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt, ExpiredSignatureError
from pydantic import ValidationError
from app.core.config import settings
from app.models.user import User
from app.schemas.token import TokenPayload
from app.core.exceptions import AuthenticationError, NotFound, APIException

# OAuth2密码Bearer，用于从请求中提取JWT令牌
oauth2_scheme = OAuth2PasswordBearer(tokenUrl=f"{settings.API_V1_STR}/auth/login")


def create_access_token(subject: Union[str, Any], expires_delta: Optional[timedelta] = None) -> str:
    """
    创建JWT访问令牌
    
    Args:
        subject: 令牌主题，通常是用户ID
        expires_delta: 过期时间增量，如果为None则使用配置中的默认值
        
    Returns:
        str: 编码后的JWT令牌
    """
    if expires_delta:
        expire = datetime.now(pytz.timezone(settings.TIMEZONE)) + expires_delta
    else:
        expire = datetime.now(pytz.timezone(settings.TIMEZONE)) + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)

    to_encode = {"exp": expire, "sub": str(subject)}
    encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    return encoded_jwt


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    验证密码
    
    Args:
        plain_password: 明文密码
        hashed_password: 哈希后的密码
        
    Returns:
        bool: 密码是否匹配
    """
    # 将明文密码编码为bytes
    password_bytes = plain_password.encode('utf-8')
    # 将哈希密码字符串转换为bytes
    hashed_bytes = hashed_password.encode('utf-8')
    # 使用bcrypt验证密码
    return bcrypt.checkpw(password_bytes, hashed_bytes)


def get_password_hash(password: str) -> str:
    """
    获取密码哈希
    
    Args:
        password: 明文密码
        
    Returns:
        str: 哈希后的密码
    """
    # 将密码编码为bytes
    password_bytes = password.encode('utf-8')
    # 生成盐值
    salt = bcrypt.gensalt()
    # 使用盐值对密码进行哈希
    hashed_bytes = bcrypt.hashpw(password_bytes, salt)
    # 将哈希结果转换为字符串
    return hashed_bytes.decode('utf-8')


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
            token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM], options={"require_exp": True}
        )
        token_data = TokenPayload(**payload)
    except ExpiredSignatureError:
        raise AuthenticationError("令牌已过期")
    except (JWTError, ValidationError):
        raise AuthenticationError("令牌无效")

    user = await User.get_or_none(id=token_data.sub)

    if user is None:
        raise NotFound("用户不存在")

    return user


async def get_current_active_user(current_user: User = Depends(get_current_user)) -> User:
    """
    获取当前活跃用户
    
    检查用户是否处于活跃状态，如果是则返回用户对象。
    
    Args:
        current_user: 当前用户对象，由依赖项自动提取
        
    Returns:
        User: 当前活跃用户对象
        
    Raises:
        HTTPException: 如果用户未激活
    """
    if not current_user.is_active:
        raise APIException(message="用户未激活")
    return current_user
