"""
令牌模式模块

此模块定义了与JWT令牌相关的Pydantic模型，用于请求和响应的数据验证。
这些模型用于用户认证和授权过程中的数据交换。
"""

from typing import Optional

from pydantic import BaseModel


class Token(BaseModel):
    """
    令牌响应模型
    
    用于API响应中返回JWT令牌信息。
    """
    access_token: str  # 访问令牌
    token_type: str  # 令牌类型，通常为"bearer"


class TokenPayload(BaseModel):
    """
    令牌载荷模型
    
    定义JWT令牌中包含的数据结构。
    """
    sub: Optional[int] = None  # 主题，通常是用户ID
    exp: int  # 过期时间戳 