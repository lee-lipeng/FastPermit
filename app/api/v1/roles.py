from typing import Any, List, Optional

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel
from tortoise.contrib.pydantic import pydantic_model_creator

from app.core.permissions import (
    permission_required,
    handle_role_permission_change,
)
from app.models.permission import Permission, Role

router = APIRouter()

# 创建Pydantic模型
Role_Pydantic = pydantic_model_creator(Role, name="Role")


class RoleIn_Pydantic(BaseModel):
    name: str
    description: Optional[str] = None
    is_default: bool = False
    permission_ids: Optional[List[int]] = None

    model_config = {
        "json_schema_extra": {
            "example": {
                "name": "编辑角色",
                "description": "可以编辑内容的角色",
                "is_default": False,
                "permission_ids": [1, 2, 3]
            }
        }
    }


class RoleUpdate_Pydantic(BaseModel):
    name: str = None
    description: str = None
    is_default: bool = None

    model_config = {
        "from_attributes": True
    }


@router.get("/", response_model=List[Role_Pydantic])
@permission_required(("role", "list"))
async def list_roles(
) -> Any:
    """
    获取角色列表
    """
    roles = await Role.all()
    return roles


@router.post("/", response_model=Role_Pydantic)
@permission_required(("role", "create"))
async def create_role(
        role_in: RoleIn_Pydantic,
) -> Any:
    """
    创建角色
    """
    # 创建角色
    role = await Role.create(
        name=role_in.name,
        description=role_in.description,
        is_default=role_in.is_default,
    )

    # 如果提供了权限ID列表，则添加权限
    if role_in.permission_ids:
        permissions = await Permission.filter(id__in=role_in.permission_ids)
        await role.permissions.add(*permissions)

        # 清除相关用户的权限缓存
        await handle_role_permission_change(role.id)

    return role


@router.get("/{role_id}", response_model=Role_Pydantic)
@permission_required(("role", "read"))
async def read_role(
        role_id: int,
) -> Any:
    """
    获取角色详情
    """
    role = await Role.get_or_none(id=role_id)

    if role is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="角色不存在",
        )

    return role


@router.put("/{role_id}", response_model=Role_Pydantic)
@permission_required(("role", "update"))
async def update_role(
        role_id: int,
        role_in: RoleUpdate_Pydantic,
) -> Any:
    """
    更新角色
    """
    role = await Role.get_or_none(id=role_id)

    if role is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="角色不存在",
        )

    update_data = role_in.model_dump(exclude_unset=True)

    if update_data:
        # 更新角色
        await Role.filter(id=role_id).update(**update_data)

        # 清除相关用户的权限缓存
        await handle_role_permission_change(role_id)

    return await Role.get(id=role_id)


@router.delete("/{role_id}")
@permission_required(("role", "delete"))
async def delete_role(
        role_id: int,
) -> dict:
    """
    删除角色
    """
    role = await Role.get_or_none(id=role_id)

    if role is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="角色不存在",
        )

    # 默认角色不能删除
    if role.is_default:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="默认角色不能删除",
        )

    # 清除相关用户的权限缓存
    await handle_role_permission_change(role_id)

    # 删除角色
    await role.delete()

    return {"message": "角色已删除"}


@router.get("/{role_id}/permissions", response_model=List[int])
@permission_required(("role", "read"))
async def get_role_permissions(
        role_id: int,
) -> Any:
    """
    获取角色权限
    """
    role = await Role.get_or_none(id=role_id)

    if role is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="角色不存在",
        )

    permissions = await role.permissions.all()
    return [permission.id for permission in permissions]


@router.post("/{role_id}/permissions")
@permission_required(("role", "update"))
async def update_role_permissions(
        role_id: int,
        permission_ids: List[int],
) -> dict:
    """
    更新角色权限
    """
    role = await Role.get_or_none(id=role_id)

    if role is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="角色不存在",
        )

    # 清空现有权限
    await role.permissions.clear()

    # 添加新权限
    if permission_ids:
        permissions = await Permission.filter(id__in=permission_ids)
        await role.permissions.add(*permissions)

    # 清除相关用户的权限缓存
    await handle_role_permission_change(role_id)

    return {"message": "角色权限已更新"}
