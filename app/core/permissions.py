"""
权限模块

此模块提供了权限管理相关的功能，包括权限检查、权限缓存管理等。
"""

from typing import Set, Union, Callable, Dict, Tuple
from functools import wraps
import inspect

from fastapi import Depends

from app.core.security import get_current_active_user
from app.models.permission import Role
from app.models.user import User
from app.core.exceptions import PermissionDenied
from app.core.logger import logger
from app.core.redis import redis_client

# 缓存相关常量
PERMISSION_CACHE_PREFIX = "user_permissions:"  # 用户权限缓存前缀
PERMISSION_CACHE_EXPIRE = 60 * 60 * 24  # 缓存过期时间：24小时

# 已装饰函数集合，避免重复装饰
_decorated_functions = set()


class PermissionChecker:
    """
    权限检查器类
    
    用于检查用户是否具有指定的权限。
    
    支持两种权限格式：
    1. 元组格式：(resource_code, action_code)
    2. 字典格式：{"resource": resource_code, "action": action_code}
    
    Attributes:
        permissions: 需要检查的权限列表
        allow_super_admin: 是否允许超级管理员绕过权限检查
    """

    def __init__(
            self,
            *permissions: Union[Tuple[str, str], Dict[str, str]],
            allow_super_admin: bool = True,
    ):
        """
        初始化权限检查器
        
        Args:
            *permissions: 权限列表，每个权限可以是元组或字典格式
            allow_super_admin: 是否允许超级管理员绕过权限检查
        
        Raises:
            ValueError: 权限格式不正确时抛出
        """
        # 统一权限格式
        self.permissions = []

        for permission in permissions:
            # 处理元组格式 (resource_code, action_code)
            if isinstance(permission, tuple):
                resource_code, action_code = permission
            # 处理字典格式 {"resource": resource_code, "action": action_code}
            elif isinstance(permission, dict):
                if "resource" not in permission or "action" not in permission:
                    raise ValueError("权限字典必须包含'resource'和'action'键")
                resource_code = permission["resource"]
                action_code = permission["action"]
            else:
                raise ValueError("权限必须是元组或字典格式")

            # 确保都是字符串
            if not isinstance(resource_code, str) or not isinstance(action_code, str):
                raise ValueError("资源代码和操作代码必须是字符串")

            self.permissions.append((resource_code, action_code))

        self.allow_super_admin = allow_super_admin

    async def get_user_permissions(self, user_id: int) -> Set[Tuple[str, str]]:
        """
        获取用户权限，优先从缓存获取
        
        Args:
            user_id: 用户ID
            
        Returns:
            Set[Tuple[str, str]]: 用户权限集合，每个权限是(resource_code, action_code)元组
        """
        # 尝试从缓存获取
        cache_key = f"{PERMISSION_CACHE_PREFIX}{user_id}"
        cached_permissions = await redis_client.get(cache_key)

        if cached_permissions is not None:
            logger.debug(f"从缓存获取用户权限: {user_id}, 权限数量: {len(cached_permissions)}")
            return cached_permissions

        # 缓存未命中，从数据库获取
        logger.debug(f"缓存未命中，从数据库获取用户权限: {user_id}")
        permissions = await self._get_permissions_from_db(user_id)

        # 存入缓存
        await redis_client.set(cache_key, permissions, PERMISSION_CACHE_EXPIRE)
        logger.debug(f"用户权限已缓存: {user_id}, 权限数量: {len(permissions)}, 过期时间: {PERMISSION_CACHE_EXPIRE}秒")

        return permissions

    async def _get_permissions_from_db(self, user_id: int) -> Set[Tuple[str, str]]:
        """
        从数据库获取用户权限

        此函数查询用户直接关联的权限和通过角色继承的权限。
        
        Args:
            user_id: 用户ID
            
        Returns:
            Set[Tuple[str, str]]: 用户权限集合，每个权限是(resource_code, action_code)元组
        """
        # 获取用户
        user = await User.get_or_none(id=user_id)
        if not user:
            logger.warning(f"获取权限失败: 用户 {user_id} 不存在")
            return set()

        # 确保用户已激活
        if not user.is_active:
            logger.warning(f"获取权限失败: 用户 {user_id} 未激活")
            return set()

        permissions = set()

        # 1. 获取用户直接关联的权限
        await user.fetch_related("permissions")
        user_direct_permissions = await user.permissions.all().prefetch_related("resource_type", "action_type")

        # 添加直接权限到结果集
        for permission in user_direct_permissions:
            await permission.fetch_related("resource_type", "action_type")
            resource_type = permission.resource_type
            action_type = permission.action_type
            if resource_type and action_type:
                permissions.add((resource_type.code, action_type.code))

        # 2. 获取用户角色关联的权限
        await user.fetch_related("roles")
        user_roles = await user.roles.all()

        for role in user_roles:
            await role.fetch_related("permissions")
            role_permissions = await role.permissions.all().prefetch_related("resource_type", "action_type")

            for permission in role_permissions:
                await permission.fetch_related("resource_type", "action_type")
                resource_type = permission.resource_type
                action_type = permission.action_type
                if resource_type and action_type:
                    permissions.add((resource_type.code, action_type.code))

        logger.debug(f"从数据库获取到用户 {user_id} 的权限: {len(permissions)} 个")
        return permissions

    async def check_permissions(self, user: User) -> bool:
        """
        检查用户是否有权限
        
        Args:
            user: 用户对象
            
        Returns:
            bool: 是否有权限
        """
        required_permissions = [f"{p[0]}:{p[1]}" for p in self.permissions]
        logger.debug(f"检查用户 {user.id} 的权限: {required_permissions}")

        # 超级管理员拥有所有权限
        is_superadmin = await user.is_superadmin()

        if self.allow_super_admin and is_superadmin:
            logger.debug(f"用户 {user.id} 是超级管理员，自动通过权限检查")
            return True

        # 获取用户权限
        user_permissions = await self.get_user_permissions(user.id)
        logger.debug(f"用户 {user.id} 的权限集合: {user_permissions}")

        # 检查是否有所有需要的权限
        has_permission = True
        for permission in self.permissions:
            if permission not in user_permissions:
                has_permission = False
                logger.warning(
                    f"权限检查失败: 用户 {user.id} 缺少权限 {permission[0]}:{permission[1]}",
                    extra={
                        "user_id": user.id,
                        "username": user.username,
                        "required_permission": f"{permission[0]}:{permission[1]}",
                    }
                )
                break

        return has_permission


async def clear_user_permissions_cache(user_id: int) -> None:
    """
    清除用户权限缓存
    
    Args:
        user_id: 用户ID
    """
    cache_key = f"{PERMISSION_CACHE_PREFIX}{user_id}"
    success = await redis_client.delete(cache_key)
    logger.info(f"清除用户权限缓存: {user_id}, 结果: {'成功' if success else '失败'}")


async def clear_all_permissions_cache() -> None:
    """
    清除所有用户权限缓存
    """
    pattern = f"{PERMISSION_CACHE_PREFIX}*"
    count = await redis_client.delete_pattern(pattern)
    logger.info(f"清除所有用户权限缓存: {count} 个")


async def handle_role_permission_change(role_id: int) -> None:
    """
    处理角色权限变更，清除相关用户的权限缓存
    
    Args:
        role_id: 角色ID
    """
    # 获取角色
    role = await Role.get_or_none(id=role_id)
    if not role:
        logger.warning(f"角色 {role_id} 不存在")
        return

    # 获取拥有该角色的所有用户
    users = await role.users.all()
    logger.debug(f"获取角色 {role_id} 的用户, 用户数量: {len(users)}")

    if not users:
        logger.info(f"角色 {role_id} 没有关联用户，无需清除缓存")
        return

    # 清除这些用户的权限缓存
    count = 0
    for user in users:
        await clear_user_permissions_cache(user.id)
        count += 1

    logger.info(f"角色 {role_id} 权限变更，已清除 {count} 个用户的权限缓存")


class PermissionRequired:
    """
    权限检查依赖类
    
    用于FastAPI的依赖注入系统，检查用户是否具有指定权限。
    """

    def __init__(
            self,
            *permissions: Union[Tuple[str, str], Dict[str, str]],
            allow_super_admin: bool = True
    ):
        """
        初始化权限检查依赖
        
        Args:
            *permissions: 权限列表
            allow_super_admin: 是否允许超级管理员绕过权限检查
        """
        self.checker = PermissionChecker(*permissions, allow_super_admin=allow_super_admin)
        self.permissions = permissions

    async def __call__(self, current_user: User = Depends(get_current_active_user)) -> User:
        """
        检查用户是否有权限
        
        Args:
            current_user: 当前用户，由FastAPI依赖注入
            
        Returns:
            User: 当前用户对象
            
        Raises:
            PermissionDenied: 权限不足时抛出
        """
        if not await self.checker.check_permissions(current_user):
            required_permissions = [f"{p[0]}:{p[1]}" for p in self.checker.permissions]
            logger.warning(
                f"权限检查失败: 用户 {current_user.id} 权限不足",
                extra={
                    "user_id": current_user.id,
                    "username": current_user.username,
                    "required_permissions": required_permissions,
                }
            )
            raise PermissionDenied(
                message="权限不足",
                details={
                    "required_permissions": required_permissions,
                    "user_id": current_user.id,
                    "username": current_user.username,
                }
            )

        logger.debug(f"权限检查通过: 用户 {current_user.id}")
        return current_user


def permission_required(
        *permissions: Union[Tuple[str, str], Dict[str, str]],
        allow_super_admin: bool = True
) -> Callable:
    """
    权限装饰器工厂函数

    用于创建检查用户权限的装饰器，可应用于API路由函数。
    权限格式为 (resource_type, action_type) 或 {"resource": resource_type, "action": action_type}。

    示例：
        @permission_required(("user", "create"), ("role", "read"))
        async def create_user_with_role():
            # 需要具有创建用户和读取角色权限
            pass

        @permission_required({"resource": "user", "action": "delete"})
        async def delete_user():
            # 需要具有删除用户权限
            pass
    
    Args:
        *permissions: 权限列表，每个权限可以是元组或字典
        allow_super_admin: 是否允许超级管理员绕过权限检查，默认为True
        
    Returns:
        Callable: 装饰器函数
    """
    logger.debug(f"创建权限检查装饰器: {permissions}, allow_super_admin={allow_super_admin}")

    # 获取权限检查依赖项
    permission_dependency = Depends(PermissionRequired(*permissions, allow_super_admin=allow_super_admin))

    def decorator(func: Callable) -> Callable:
        """
        权限检查装饰器
        
        Args:
            func: 要装饰的函数
            
        Returns:
            Callable: 装饰后的函数
        """
        # 检查函数是否已被装饰过
        func_id = id(func)
        if func_id in _decorated_functions:
            logger.debug(f"函数 {func.__name__} 已被装饰过，跳过重复装饰")
            return func

        logger.debug(f"应用权限检查装饰器到函数: {func.__name__}")

        # 获取原始函数的签名并转换为参数列表
        sig = inspect.signature(func)
        parameters = list(sig.parameters.values())

        # 检查是否已有 current_user 参数，并更新签名
        has_current_user = any(p.name == 'current_user' for p in parameters)
        logger.debug(f"函数 {func.__name__} 是否已有current_user参数: {has_current_user}")

        if has_current_user:
            # 替换已有 current_user 参数的默认值
            for i, param in enumerate(parameters):
                if param.name == 'current_user':
                    parameters[i] = param.replace(default=permission_dependency)
                    logger.debug(f"替换函数 {func.__name__} 的current_user参数默认值")
        else:
            # 添加新的 current_user 参数
            parameters.append(
                inspect.Parameter(
                    name='current_user',
                    kind=inspect.Parameter.KEYWORD_ONLY,
                    default=permission_dependency,
                    annotation=User
                )
            )
            logger.debug(f"为函数 {func.__name__} 添加current_user参数")

        # 创建新的签名
        new_sig = sig.replace(parameters=parameters)

        @wraps(func)
        async def wrapper(*args, **kwargs):
            """
            包装函数
            
            Args:
                *args: 位置参数
                **kwargs: 关键字参数
                
            Returns:
                Any: 原始函数的返回值
            """
            # 记录函数调用
            func_name = func.__name__
            logger.debug(f"调用需要权限的函数: {func_name}, 权限: {permissions}")

            # FastAPI 会根据签名自动注入 current_user，直接调用原始函数
            # 如果原始函数没有 current_user 参数，移除 kwargs 中的 current_user
            if not has_current_user:
                current_user = kwargs.pop('current_user', None)
                logger.debug(f"从kwargs中移除current_user参数: {current_user.id if current_user else None}")

            # 调用原始函数
            result = await func(*args, **kwargs)
            return result

        # 设置包装函数的签名
        wrapper.__signature__ = new_sig

        # 将函数标记为已装饰
        _decorated_functions.add(id(wrapper))

        return wrapper

    return decorator


# ========== 权限辅助函数 ==========

def has_permission(resource: str, action: str, allow_super_admin: bool = True) -> Callable:
    """
    创建权限检查依赖
    
    在FastAPI路由参数中使用，例如：
    ```python
    @app.get("/users")
    async def list_users(user: User = Depends(has_permission("user", "list"))):
        return {"message": "有权限访问"}
    ```
    
    Args:
        resource: 资源代码
        action: 操作代码
        allow_super_admin: 是否允许超级管理员绕过权限检查
        
    Returns:
        Callable: 权限检查依赖项函数
    """
    return Depends(PermissionRequired((resource, action), allow_super_admin=allow_super_admin))


# ========== 用户权限函数 ==========

def has_user_create() -> Callable:
    """检查是否有创建用户的权限"""
    return has_permission("user", "create")


def has_user_read() -> Callable:
    """检查是否有读取用户的权限"""
    return has_permission("user", "read")


def has_user_update() -> Callable:
    """检查是否有更新用户的权限"""
    return has_permission("user", "update")


def has_user_delete() -> Callable:
    """检查是否有删除用户的权限"""
    return has_permission("user", "delete")


def has_user_list() -> Callable:
    """检查是否有列出用户的权限"""
    return has_permission("user", "list")


# ========== 角色权限函数 ==========

def has_role_create() -> Callable:
    """检查是否有创建角色的权限"""
    return has_permission("role", "create")


def has_role_read() -> Callable:
    """检查是否有读取角色的权限"""
    return has_permission("role", "read")


def has_role_update() -> Callable:
    """检查是否有更新角色的权限"""
    return has_permission("role", "update")


def has_role_delete() -> Callable:
    """检查是否有删除角色的权限"""
    return has_permission("role", "delete")


def has_role_list() -> Callable:
    """检查是否有列出角色的权限"""
    return has_permission("role", "list")


# ========== 权限资源函数 ==========

def has_permission_create() -> Callable:
    """检查是否有创建权限配置的权限"""
    return has_permission("permission", "create")


def has_permission_read() -> Callable:
    """检查是否有读取权限配置的权限"""
    return has_permission("permission", "read")


def has_permission_update() -> Callable:
    """检查是否有更新权限配置的权限"""
    return has_permission("permission", "update")


def has_permission_delete() -> Callable:
    """检查是否有删除权限配置的权限"""
    return has_permission("permission", "delete")


def has_permission_list() -> Callable:
    """检查是否有列出权限配置的权限"""
    return has_permission("permission", "list")


# ========== 系统权限函数 ==========

def has_system_create() -> Callable:
    """检查是否有创建系统配置的权限"""
    return has_permission("system", "create")


def has_system_read() -> Callable:
    """检查是否有读取系统配置的权限"""
    return has_permission("system", "read")


def has_system_update() -> Callable:
    """检查是否有更新系统配置的权限"""
    return has_permission("system", "update")


def has_system_delete() -> Callable:
    """检查是否有删除系统配置的权限"""
    return has_permission("system", "delete")


def has_system_list() -> Callable:
    """检查是否有列出系统配置的权限"""
    return has_permission("system", "list")


# ========== 日志权限函数 ==========

def has_log_read() -> Callable:
    """检查是否有读取日志的权限"""
    return has_permission("log", "read")


def has_log_list() -> Callable:
    """检查是否有列出日志的权限"""
    return has_permission("log", "list")


def has_log_export() -> Callable:
    """检查是否有导出日志的权限"""
    return has_permission("log", "export")
