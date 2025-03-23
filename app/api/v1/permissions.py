from typing import Any, List, Optional

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel
from tortoise.contrib.pydantic import pydantic_model_creator

from app.core.permissions import (
    permission_required,
    clear_all_permissions_cache,
    handle_role_permission_change,
)
from app.models.permission import Permission, ResourceType, ActionType

router = APIRouter()

# 创建Pydantic模型
Permission_Pydantic = pydantic_model_creator(Permission, name="Permission")


class PermissionIn_Pydantic(BaseModel):
    resource_type_id: int
    action_type_id: int
    name: str
    description: Optional[str] = None

    model_config = {
        "json_schema_extra": {
            "example": {
                "resource_type_id": 1,
                "action_type_id": 1,
                "name": "创建用户",
                "description": "允许创建新用户"
            }
        },
        "arbitrary_types_allowed": True
    }


class PermissionUpdate_Pydantic(BaseModel):
    resource_type_id: Optional[int] = None
    action_type_id: Optional[int] = None
    name: Optional[str] = None
    description: Optional[str] = None

    model_config = {
        "from_attributes": True,
        "arbitrary_types_allowed": True
    }


@router.get("/resources", response_model=List[dict])
@permission_required(("permission", "list"))
async def list_resources() -> Any:
    """
    获取所有资源类型
    """
    resources = await ResourceType.all()
    return [{"id": r.id, "code": r.code, "name": r.name} for r in resources]


@router.get("/actions", response_model=List[dict])
@permission_required(("permission", "list"))
async def list_actions() -> Any:
    """
    获取所有操作类型
    """
    actions = await ActionType.all()
    return [{"id": a.id, "code": a.code, "name": a.name} for a in actions]


@router.get("/", response_model=List[Permission_Pydantic])
@permission_required(("permission", "list"))
async def list_permissions(
    resource_type_id: Optional[int] = None,
    action_type_id: Optional[int] = None,
) -> Any:
    """
    获取权限列表
    """
    query = Permission.all().prefetch_related("resource_type", "action_type")
    
    if resource_type_id is not None:
        query = query.filter(resource_type_id=resource_type_id)
    if action_type_id is not None:
        query = query.filter(action_type_id=action_type_id)
        
    permissions = await query
    return permissions


@router.post("/", response_model=Permission_Pydantic)
@permission_required(("permission", "create"))
async def create_permission(
    permission_in: PermissionIn_Pydantic,
) -> Any:
    """
    创建权限
    """
    # 检查资源类型和操作类型是否存在
    resource_type = await ResourceType.get_or_none(id=permission_in.resource_type_id)
    if not resource_type:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="资源类型不存在",
        )
        
    action_type = await ActionType.get_or_none(id=permission_in.action_type_id)
    if not action_type:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="操作类型不存在",
        )
    
    # 检查权限是否已存在
    existing_permission = await Permission.filter(
        resource_type_id=permission_in.resource_type_id,
        action_type_id=permission_in.action_type_id
    ).first()
    
    if existing_permission:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="权限已存在",
        )
    
    # 创建权限
    permission = await Permission.create(
        resource_type_id=permission_in.resource_type_id,
        action_type_id=permission_in.action_type_id,
        name=permission_in.name,
        description=permission_in.description,
    )
    
    # 清除所有权限缓存
    await clear_all_permissions_cache()
    
    return permission


@router.get("/{permission_id}", response_model=Permission_Pydantic)
@permission_required(("permission", "read"))
async def read_permission(
    permission_id: int,
) -> Any:
    """
    获取权限详情
    """
    permission = await Permission.get_or_none(id=permission_id).prefetch_related("resource_type", "action_type")
    
    if permission is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="权限不存在",
        )
    
    return permission


@router.put("/{permission_id}", response_model=Permission_Pydantic)
@permission_required(("permission", "update"))
async def update_permission(
    permission_id: int,
    permission_in: PermissionUpdate_Pydantic,
) -> Any:
    """
    更新权限
    """
    permission = await Permission.get_or_none(id=permission_id)
    
    if permission is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="权限不存在",
        )
    
    # 检查资源类型和操作类型是否存在
    if permission_in.resource_type_id is not None:
        resource_type = await ResourceType.get_or_none(id=permission_in.resource_type_id)
        if not resource_type:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="资源类型不存在",
            )
            
    if permission_in.action_type_id is not None:
        action_type = await ActionType.get_or_none(id=permission_in.action_type_id)
        if not action_type:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="操作类型不存在",
            )
    
    # 检查资源和操作组合是否已存在
    if permission_in.resource_type_id is not None and permission_in.action_type_id is not None:
        existing_permission = await Permission.filter(
            resource_type_id=permission_in.resource_type_id,
            action_type_id=permission_in.action_type_id
        ).exclude(id=permission_id).first()
        
        if existing_permission:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="权限已存在",
            )
    
    # 更新权限
    update_data = permission_in.model_dump(exclude_unset=True)
    
    if update_data:
        await Permission.filter(id=permission_id).update(**update_data)
        
        # 获取使用此权限的所有角色
        roles = await permission.roles.all()
        
        # 清除相关角色的用户权限缓存
        for role in roles:
            await handle_role_permission_change(role.id)
    
    return await Permission.get(id=permission_id).prefetch_related("resource_type", "action_type")


@router.delete("/{permission_id}")
@permission_required(("permission", "delete"))
async def delete_permission(
    permission_id: int,
) -> dict:
    """
    删除权限
    """
    permission = await Permission.get_or_none(id=permission_id)
    
    if permission is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="权限不存在",
        )
    
    # 获取使用此权限的所有角色
    roles = await permission.roles.all()
    
    # 删除权限
    await permission.delete()
    
    # 清除相关角色的用户权限缓存
    for role in roles:
        await handle_role_permission_change(role.id)
    
    return {"message": "权限已删除"}