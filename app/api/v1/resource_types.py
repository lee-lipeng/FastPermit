"""
资源类型API

提供资源类型的CRUD操作API。
"""

from typing import List, Optional

from fastapi import APIRouter, HTTPException, status
from tortoise.contrib.pydantic import pydantic_model_creator

from app.core.permissions import permission_required
from app.models.permission import ResourceType
from app.schemas.permission import ResourceTypeCreate, ResourceTypeResponse, ResourceTypeUpdate

router = APIRouter()

# 创建Pydantic模型
ResourceType_Pydantic = pydantic_model_creator(
    ResourceType, name="ResourceType", exclude=["permissions"]
)


@router.get("/", response_model=List[ResourceTypeResponse])
@permission_required(("resource_type", "list"))
async def list_resource_types(
        code: Optional[str] = None,
        name: Optional[str] = None,
        is_system: Optional[bool] = None,
) -> List[ResourceTypeResponse]:
    """
    获取资源类型列表，支持按代码、名称和系统标志过滤
    
    需要resource_type:list权限
    """
    query = ResourceType.all()

    # 构建过滤条件
    if code:
        query = query.filter(code__icontains=code)
    if name:
        query = query.filter(name__icontains=name)
    if is_system is not None:
        query = query.filter(is_system=is_system)

    resource_types = await query.order_by('id')

    return [await ResourceType_Pydantic.from_tortoise_orm(rt) for rt in resource_types]


@router.post("/", response_model=ResourceTypeResponse, status_code=status.HTTP_201_CREATED)
@permission_required(("resource_type", "create"))
async def create_resource_type(
        resource_type_in: ResourceTypeCreate,
) -> ResourceTypeResponse:
    """
    创建资源类型
    
    需要resource_type:create权限
    """
    # 检查代码是否已存在
    existing = await ResourceType.filter(code=resource_type_in.code).first()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"代码 '{resource_type_in.code}' 已存在",
        )

    # 创建资源类型
    resource_type = await ResourceType.create(**resource_type_in.model_dump())

    return await ResourceType_Pydantic.from_tortoise_orm(resource_type)


@router.get("/{resource_type_id}", response_model=ResourceTypeResponse)
@permission_required(("resource_type", "read"))
async def read_resource_type(
        resource_type_id: int,
) -> ResourceTypeResponse:
    """
    获取资源类型详情
    
    需要resource_type:read权限
    """
    resource_type = await ResourceType.get_or_none(id=resource_type_id)
    if not resource_type:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="资源类型不存在",
        )

    return await ResourceType_Pydantic.from_tortoise_orm(resource_type)


@router.put("/{resource_type_id}", response_model=ResourceTypeResponse)
@permission_required(("resource_type", "update"))
async def update_resource_type(
        resource_type_id: int,
        resource_type_in: ResourceTypeUpdate,
) -> ResourceTypeResponse:
    """
    更新资源类型
    
    需要resource_type:update权限
    系统内置的资源类型不能修改code属性
    """
    resource_type = await ResourceType.get_or_none(id=resource_type_id)
    if not resource_type:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="资源类型不存在",
        )

    # 系统内置的资源类型不能修改is_system属性
    if resource_type.is_system and resource_type_in.is_system is False:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="不能修改系统内置资源类型的系统标志",
        )

    # 更新资源类型
    update_data = resource_type_in.model_dump(exclude_unset=True)
    await resource_type.update_from_dict(update_data).save()

    return await ResourceType_Pydantic.from_tortoise_orm(resource_type)


@router.delete("/{resource_type_id}", status_code=status.HTTP_204_NO_CONTENT)
@permission_required(("resource_type", "delete"))
async def delete_resource_type(
        resource_type_id: int,
) -> None:
    """
    删除资源类型
    
    需要resource_type:delete权限
    系统内置的资源类型不能删除
    有关联权限的资源类型不能删除
    """
    resource_type = await ResourceType.get_or_none(id=resource_type_id)
    if not resource_type:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="资源类型不存在",
        )

    # 系统内置的资源类型不能删除
    if resource_type.is_system:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="不能删除系统内置资源类型",
        )

    # 检查是否有关联的权限
    await resource_type.fetch_related("permissions")
    if await resource_type.permissions.all().count() > 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="该资源类型已关联权限，不能删除",
        )

    # 删除资源类型
    await resource_type.delete()
