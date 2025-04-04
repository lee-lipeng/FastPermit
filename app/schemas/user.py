"""
用户模式模块

此模块定义了与用户相关的Pydantic模型，用于请求和响应的数据验证。
这些模型用于用户管理API中的数据交换和验证。
"""

from typing import List, Optional

from pydantic import BaseModel, EmailStr
from app.models.user import User_Pydantic


class UserBase(BaseModel):
    """
    用户基础模型
    
    包含用户的基本信息字段，作为其他用户相关模型的基类。
    """
    username: Optional[str] = None  # 用户名
    email: Optional[EmailStr] = None  # 邮箱
    phone: Optional[str] = None  # 手机号
    is_active: Optional[bool] = True  # 是否激活

    model_config = {
        "from_attributes": True
    }


class UserListResponse(BaseModel):
    """
    用户列表响应模型

    用于返回用户列表的响应数据验证。
    """
    items: List[User_Pydantic]
    total: int


class UserCreate(UserBase):
    """
    用户创建模型
    
    用于创建新用户时的请求数据验证。
    """
    username: str  # 用户名（必填）
    password: str  # 密码（必填）
    role_ids: Optional[List[int]] = None  # 角色ID列表（可选）


class UserUpdate(UserBase):
    """
    用户更新模型
    
    用于更新用户信息时的请求数据验证。
    """
    password: Optional[str] = None  # 密码（可选）
    role_ids: Optional[List[int]] = None  # 角色ID列表（可选）
