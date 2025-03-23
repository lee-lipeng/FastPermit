"""
操作类型API

提供操作类型的CRUD操作API。
"""

from typing import List, Optional

from fastapi import APIRouter, HTTPException, status
from tortoise.contrib.pydantic import pydantic_model_creator

from app.core.permissions import permission_required
from app.models.permission import ActionType
from app.schemas.permission import ActionTypeCreate, ActionTypeResponse, ActionTypeUpdate

router = APIRouter()

# 创建Pydantic模型
ActionType_Pydantic = pydantic_model_creator(
    ActionType, name="ActionType", exclude=["permissions"]
)


@router.get("/", response_model=List[ActionTypeResponse])
@permission_required(("action_type", "list"))
async def list_action_types(
    code: Optional[str] = None,
    name: Optional[str] = None,
    is_system: Optional[bool] = None,
) -> List[ActionTypeResponse]:
    """
    获取操作类型列表，支持按代码、名称和系统标志过滤
    
    需要action_type:list权限
    """
    query = ActionType.all()
    
    # 构建过滤条件
    if code:
        query = query.filter(code__icontains=code)
    if name:
        query = query.filter(name__icontains=name)
    if is_system is not None:
        query = query.filter(is_system=is_system)
    
    action_types = await query.order_by('id')
    
    return [await ActionType_Pydantic.from_tortoise_orm(at) for at in action_types]


@router.post("/", response_model=ActionTypeResponse, status_code=status.HTTP_201_CREATED)
@permission_required(("action_type", "create"))
async def create_action_type(
    action_type_in: ActionTypeCreate,
) -> ActionTypeResponse:
    """
    创建操作类型
    
    需要action_type:create权限
    """
    # 检查代码是否已存在
    existing = await ActionType.filter(code=action_type_in.code).first()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"代码 '{action_type_in.code}' 已存在",
        )
    
    # 创建操作类型
    action_type = await ActionType.create(**action_type_in.model_dump())
    
    return await ActionType_Pydantic.from_tortoise_orm(action_type)


@router.get("/{action_type_id}", response_model=ActionTypeResponse)
@permission_required(("action_type", "read"))
async def read_action_type(
    action_type_id: int,
) -> ActionTypeResponse:
    """
    获取操作类型详情
    
    需要action_type:read权限
    """
    action_type = await ActionType.get_or_none(id=action_type_id)
    if not action_type:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="操作类型不存在",
        )
    
    return await ActionType_Pydantic.from_tortoise_orm(action_type)


@router.put("/{action_type_id}", response_model=ActionTypeResponse)
@permission_required(("action_type", "update"))
async def update_action_type(
    action_type_id: int,
    action_type_in: ActionTypeUpdate,
) -> ActionTypeResponse:
    """
    更新操作类型
    
    需要action_type:update权限
    系统内置的操作类型不能修改code属性
    """
    action_type = await ActionType.get_or_none(id=action_type_id)
    if not action_type:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="操作类型不存在",
        )
    
    # 系统内置的操作类型不能修改is_system属性
    if action_type.is_system and action_type_in.is_system is False:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="不能修改系统内置操作类型的系统标志",
        )
    
    # 更新操作类型
    update_data = action_type_in.model_dump(exclude_unset=True)
    await action_type.update_from_dict(update_data).save()
    
    return await ActionType_Pydantic.from_tortoise_orm(action_type)


@router.delete("/{action_type_id}", status_code=status.HTTP_204_NO_CONTENT)
@permission_required(("action_type", "delete"))
async def delete_action_type(
    action_type_id: int,
) -> None:
    """
    删除操作类型
    
    需要action_type:delete权限
    系统内置的操作类型不能删除
    有关联权限的操作类型不能删除
    """
    action_type = await ActionType.get_or_none(id=action_type_id)
    if not action_type:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="操作类型不存在",
        )
    
    # 系统内置的操作类型不能删除
    if action_type.is_system:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="不能删除系统内置操作类型",
        )
    
    # 检查是否有关联的权限
    await action_type.fetch_related("permissions")
    if await action_type.permissions.all().count() > 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="该操作类型已关联权限，不能删除",
        )
    
    # 删除操作类型
    await action_type.delete()