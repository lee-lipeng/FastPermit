"""
权限模式模块

此模块定义了与权限系统相关的Pydantic模型，用于请求和响应的数据验证。
"""

from typing import List, Optional
from datetime import datetime
from pydantic import BaseModel


class ResourceTypeBase(BaseModel):
    """
    资源类型基础模型
    """
    code: str
    name: str
    description: Optional[str] = None
    is_system: bool = False
    
    model_config = {
        "from_attributes": True
    }


class ResourceTypeCreate(ResourceTypeBase):
    """
    资源类型创建模型
    """
    pass


class ResourceTypeUpdate(BaseModel):
    """
    资源类型更新模型
    """
    name: Optional[str] = None
    description: Optional[str] = None
    is_system: Optional[bool] = None

    model_config = {
        "from_attributes": True
    }


class ResourceTypeResponse(ResourceTypeBase):
    """
    资源类型响应模型
    """
    id: int
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None


class ActionTypeBase(BaseModel):
    """
    操作类型基础模型
    """
    code: str
    name: str
    description: Optional[str] = None
    is_system: bool = False
    
    model_config = {
        "from_attributes": True
    }


class ActionTypeCreate(ActionTypeBase):
    """
    操作类型创建模型
    """
    pass


class ActionTypeUpdate(BaseModel):
    """
    操作类型更新模型
    """
    name: Optional[str] = None
    description: Optional[str] = None
    is_system: Optional[bool] = None

    model_config = {
        "from_attributes": True
    }


class ActionTypeResponse(ActionTypeBase):
    """
    操作类型响应模型
    """
    id: int
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None


class PermissionBase(BaseModel):
    """
    权限基础模型
    """
    resource_type_id: int
    action_type_id: int
    name: str
    description: Optional[str] = None
    
    model_config = {
        "from_attributes": True
    }


class PermissionCreate(PermissionBase):
    """
    权限创建模型
    """
    pass


class PermissionUpdate(BaseModel):
    """
    权限更新模型
    """
    name: Optional[str] = None
    description: Optional[str] = None

    model_config = {
        "from_attributes": True
    }


class PermissionResponse(BaseModel):
    """
    权限响应模型
    """
    id: int
    resource_type: ResourceTypeResponse
    action_type: ActionTypeResponse
    name: str
    description: Optional[str] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    model_config = {
        "from_attributes": True
    }


class RoleBase(BaseModel):
    """
    角色基础模型
    """
    name: str
    description: Optional[str] = None
    is_default: bool = False
    
    model_config = {
        "from_attributes": True
    }


class RoleCreate(RoleBase):
    """
    角色创建模型
    """
    permission_ids: Optional[List[int]] = None


class RoleUpdate(BaseModel):
    """
    角色更新模型
    """
    name: Optional[str] = None
    description: Optional[str] = None
    is_default: Optional[bool] = None
    permission_ids: Optional[List[int]] = None

    model_config = {
        "from_attributes": True
    }


class RoleResponse(RoleBase):
    """
    角色响应模型
    """
    id: int
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    model_config = {
        "from_attributes": True
    }


class RoleDetailResponse(RoleResponse):
    """
    角色详情响应模型
    """
    permissions: List[PermissionResponse] = [] 