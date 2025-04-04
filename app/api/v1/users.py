from typing import Any, List, Optional

from fastapi import APIRouter, Depends
from tortoise.expressions import Q
from loguru import logger

from app.models.permission import Role
from app.models.user import User, User_Pydantic
from app.schemas.user import UserCreate, UserUpdate, UserListResponse
from app.core.security import get_current_active_user, get_password_hash
from app.core.permissions import permission_required, clear_user_permissions_cache
from app.core.exceptions import (
    APIException,
    NotFound,
    PermissionDenied
)

router = APIRouter()


@router.get("", response_model=UserListResponse, summary="获取用户列表")
@permission_required(("user", "list"))
async def list_users(
        username: Optional[str] = None,
        phone: Optional[str] = None,
        skip: int = 0,
        limit: int = 10,
        current_user: User = None,
) -> Any:
    """
    获取用户列表，支持按用户名、手机号筛选和分页

    需要user:list权限
    """
    query = User.all()

    # 构建查询条件
    filters = Q()
    if username:
        filters &= Q(username__icontains=username)

    if phone:
        filters &= Q(phone__icontains=phone)

    # 应用过滤条件
    if filters:
        query = query.filter(filters)

        # 先计算总数 (在应用分页前)
        total = await query.count()

        # 应用分页
        users_query = query.offset(skip).limit(limit)
        users = await users_query

        # 转换数据为 Pydantic 模型
        user_items = [await User_Pydantic.from_tortoise_orm(user) for user in users]

        logger.info(f"管理员 {current_user.id} 查看了用户列表 (skip={skip}, limit={limit}, filters={{'username': '{username}', 'phone': '{phone}'}})")

        # 返回分页结果
        return UserListResponse(items=user_items, total=total)


@router.post("", response_model=User_Pydantic, summary="创建用户")
@permission_required(("user", "create"))
async def create_user(
        user_in: UserCreate,
) -> Any:
    """
    创建用户, 密码使用bcrypt加密

    需要user:create权限
    """
    # 检查用户名是否已存在
    existing_user = await User.filter(username=user_in.username).first()
    if existing_user:
        raise APIException(message="用户名已存在")

    # 检查手机号是否已存在
    if user_in.phone:
        existing_phone = await User.filter(phone=user_in.phone).first()

        if existing_phone:
            raise APIException(message="手机号已存在")

    # 创建用户
    user_data = user_in.model_dump(exclude={"password", "role_ids"})
    user_data["hashed_password"] = get_password_hash(user_in.password)

    user = await User.create(**user_data)

    # 添加角色
    if user_in.role_ids:
        roles = await Role.filter(id__in=user_in.role_ids)
        await user.roles.add(*roles)

        # 清除用户权限缓存
        await clear_user_permissions_cache(user.id)

    return await User_Pydantic.from_tortoise_orm(user)


@router.get("/me", response_model=User_Pydantic, summary="获取当前用户信息")
async def read_user_me(
        current_user: User = Depends(get_current_active_user),
) -> Any:
    """
    获取当前用户信息
    """
    return await User_Pydantic.from_tortoise_orm(current_user)


@router.put("/me", response_model=User_Pydantic, summary="更新当前用户信息")
async def update_user_me(
        user_in: UserUpdate,
        current_user: User = Depends(get_current_active_user),
) -> Any:
    """
    更新当前用户信息

    普通用户可以更新自己的基本信息，但不能修改角色
    """
    # 不允许修改角色
    user_data = user_in.model_dump(
        exclude={"password", "role_ids"},
        exclude_unset=True,
    )

    # 如果更新密码
    if user_in.password:
        user_data["hashed_password"] = get_password_hash(user_in.password)

    # 更新用户
    await User.filter(id=current_user.id).update(**user_data)

    logger.info(f"用户 {current_user.id} 更新了自己的信息")

    return await User.get(id=current_user.id)


@router.get("/{user_id}", response_model=User_Pydantic, summary="获取用户信息")
@permission_required(("user", "read"))
async def read_user(
        user_id: int
) -> Any:
    """
    获取用户信息

    需要user:read权限
    """
    user = await User.get_or_none(id=user_id)

    if user is None:
        raise NotFound(message="用户不存在")

    return await User_Pydantic.from_tortoise_orm(user)


@router.put("/{user_id}", response_model=User_Pydantic, summary="更新用户信息")
@permission_required(("user", "update"))
async def update_user(
        user_id: int,
        user_in: UserUpdate,
        current_user: User = None,
) -> Any:
    """
    更新用户信息

    需要user:update权限
    """
    user = await User.get_or_none(id=user_id)

    if user is None:
        raise NotFound(message="用户不存在")

    # 超级管理员只能由其他超级管理员修改
    is_target_superadmin = await user.is_superadmin()
    is_current_superadmin = await current_user.is_superadmin()

    if is_target_superadmin and not is_current_superadmin:
        raise PermissionDenied(message="无权修改超级管理员")

    # 准备更新数据
    user_data = user_in.model_dump(exclude={"password", "role_ids"}, exclude_unset=True)

    # 如果更新密码
    if user_in.password:
        user_data["hashed_password"] = get_password_hash(user_in.password)

    # 更新用户
    await User.filter(id=user_id).update(**user_data)

    logger.info(f"管理员 {current_user.id} 更新了用户 {user_id} 的信息")

    # 如果更新角色
    if user_in.role_ids is not None:
        # 清空现有角色
        await user.roles.clear()

        # 添加新角色
        if user_in.role_ids:
            roles = await Role.filter(id__in=user_in.role_ids)
            await user.roles.add(*roles)

        # 清除用户权限缓存
        await clear_user_permissions_cache(user_id)

        logger.info(f"管理员 {current_user.id} 更新了用户 {user_id} 的角色")

    return await User.get(id=user_id)


@router.delete("/{user_id}", summary="删除用户")
@permission_required(("user", "delete"))
async def delete_user(user_id: int) -> dict:
    """
    删除用户

    需要user:delete权限
    """
    user = await User.get_or_none(id=user_id)

    if user is None:
        raise NotFound(message="用户不存在")

    # 超级管理员不能删除
    if await user.is_superadmin():
        raise APIException(message="超级管理员不能删除")

    # 清除用户权限缓存
    await clear_user_permissions_cache(user_id)

    # 删除用户
    await user.delete()

    return {"message": "用户已删除"}


@router.get("/{user_id}/roles", response_model=List[int], summary="获取用户角色")
@permission_required(("user", "read"))
async def get_user_roles(
        user_id: int,
        current_user: User = None,
) -> Any:
    """
    获取用户角色

    需要user:read权限
    """
    user = await User.get_or_none(id=user_id)

    if user is None:
        raise NotFound(message="用户不存在")

    roles = await user.roles.all()
    logger.info(f"管理员 {current_user.id} 查看了用户 {user_id} 的角色")
    return [role.id for role in roles]


@router.post("/{user_id}/roles", summary="更新用户角色")
@permission_required(("user", "update"))
async def update_user_roles(
        user_id: int,
        role_ids: List[int],
        current_user: User = None,
) -> dict:
    """
    更新用户角色

    需要user:update权限
    """
    user = await User.get_or_none(id=user_id)

    if user is None:
        raise NotFound(message="用户不存在")

    # 超级管理员角色不能修改
    if await user.is_superadmin():
        raise APIException(message="超级管理员角色不能修改")

    # 清空现有角色
    await user.roles.clear()

    # 添加新角色
    if role_ids:
        roles = await Role.filter(id__in=role_ids)
        await user.roles.add(*roles)

    # 清除用户权限缓存
    await clear_user_permissions_cache(user_id)

    logger.info(f"管理员 {current_user.id} 更新了用户 {user_id} 的角色")

    return {"message": "用户角色已更新"}


@router.get("/{user_id}/permissions", response_model=List[int], summary="获取用户直接权限")
@permission_required(("user", "read"))
async def get_user_permissions(
        user_id: int,
        current_user: User = None,
) -> Any:
    """
    获取用户直接关联的权限

    需要user:read权限
    """
    user = await User.get_or_none(id=user_id)

    if user is None:
        raise NotFound(message="用户不存在")

    permissions = await user.permissions.all()
    logger.info(f"管理员 {current_user.id} 查看了用户 {user_id} 的直接权限")
    return [permission.id for permission in permissions]


@router.post("/{user_id}/permissions", summary="更新用户直接权限")
@permission_required(("user", "update"))
async def update_user_permissions(
        user_id: int,
        permission_ids: List[int],
        current_user: User = None,
) -> dict:
    """
    更新用户直接关联的权限

    需要user:update权限
    """
    user = await User.get_or_none(id=user_id)

    if user is None:
        raise NotFound(message="用户不存在")

    # 超级管理员权限不能修改
    if await user.is_superadmin():
        raise APIException(message="超级管理员权限不能修改")

    # 清空现有直接权限
    await user.permissions.clear()

    # 添加新权限
    if permission_ids:
        from app.models.permission import Permission
        permissions = await Permission.filter(id__in=permission_ids)
        await user.permissions.add(*permissions)

    # 清除用户权限缓存
    await clear_user_permissions_cache(user_id)

    logger.info(f"管理员 {current_user.id} 更新了用户 {user_id} 的直接权限")

    return {"message": "用户权限已更新"}
