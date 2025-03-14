"""
数据库初始化模块

此模块负责数据库的初始化工作，包括初始化权限、角色和超级用户。
在应用首次启动或需要重置数据库时使用。
注意：表结构由Aerich管理，此模块只负责初始化基础数据。
"""

import asyncio
from loguru import logger
from tortoise import Tortoise

from app.core.security import get_password_hash
from app.db.config import TORTOISE_ORM
from app.models.permission import ActionType, Permission, ResourceType, Role
from app.models.user import User


async def init_db() -> None:
    """
    初始化数据库基础数据
    
    此函数负责初始化数据库连接，并调用其他初始化函数
    来设置基本的权限、角色和超级用户。
    注意：此函数不创建表结构，表结构应该通过Aerich命令创建。
    """
    # 注册模型
    await Tortoise.init(config=TORTOISE_ORM)

    # 检查是否已经初始化过数据
    if not await _is_db_empty():
        logger.info("数据库已初始化，跳过初始化过程")
        return

    # 初始化权限
    await init_permissions()

    # 初始化角色
    await init_roles()

    # 初始化超级管理员
    await init_superuser()
    
    logger.info("数据库基础数据初始化完成")


async def _is_db_empty() -> bool:
    """
    检查数据库是否为空
    
    Returns:
        bool: 如果数据库为空返回True，否则返回False
    """
    try:
        # 检查是否有用户
        user_count = await User.all().count()
        if user_count > 0:
            return False
            
        # 检查是否有角色
        role_count = await Role.all().count()
        if role_count > 0:
            return False
            
        # 检查是否有权限
        permission_count = await Permission.all().count()
        if permission_count > 0:
            return False
            
        return True
    except Exception as e:
        logger.error(f"检查数据库是否为空时出错: {e}")
        # 如果出错，假设数据库未初始化
        return True


async def init_permissions() -> None:
    """
    初始化权限
    """
    try:
        # 检查是否已有权限
        permissions_count = await Permission.all().count()

        if permissions_count > 0:
            logger.info("权限已存在，跳过初始化")
            return

        # 创建所有资源的所有操作权限
        permissions_to_create = []

        for resource in ResourceType:
            for action in ActionType:
                # 跳过一些不合理的组合
                if resource == ResourceType.PERMISSION and action in [ActionType.APPROVE]:
                    continue

                if resource == ResourceType.ROLE and action in [ActionType.APPROVE]:
                    continue

                if resource == ResourceType.USER and action in [ActionType.APPROVE]:
                    continue

                if resource == ResourceType.SYSTEM and action in [ActionType.APPROVE]:
                    continue

                # 创建权限
                permission = Permission(
                    resource=resource,
                    action=action,
                    name=f"{resource.value}:{action.value}",
                    description=f"{resource.value} {action.value} 权限",
                )

                permissions_to_create.append(permission)

        # 批量创建权限
        await Permission.bulk_create(permissions_to_create)
        logger.info(f"已创建 {len(permissions_to_create)} 个权限")
    except Exception as e:
        logger.error(f"初始化权限时出错: {e}")


async def init_roles() -> None:
    """
    初始化角色
    """
    try:
        # 检查是否已有角色
        roles_count = await Role.all().count()

        if roles_count > 0:
            logger.info("角色已存在，跳过初始化")
            return

        # 创建超级管理员角色
        super_admin_role = await Role.create(
            name="超级管理员",
            description="拥有所有权限的超级管理员",
            is_default=True,
        )

        # 为超级管理员角色添加所有权限
        all_permissions = await Permission.all()
        await super_admin_role.permissions.add(*all_permissions)

        # 创建管理员角色
        admin_role = await Role.create(
            name="管理员",
            description="拥有大部分权限的管理员",
            is_default=True,
        )

        # 为管理员角色添加部分权限
        admin_permissions = []
        admin_permissions.extend(await Permission.filter(resource=ResourceType.USER))
        admin_permissions.extend(await Permission.filter(resource=ResourceType.ROLE, action__in=[ActionType.READ, ActionType.LIST]))
        admin_permissions.extend(await Permission.filter(resource=ResourceType.PERMISSION, action__in=[ActionType.READ, ActionType.LIST]))
        admin_permissions.extend(await Permission.filter(resource=ResourceType.SYSTEM, action__in=[ActionType.READ, ActionType.LIST]))
        admin_permissions.extend(await Permission.filter(resource=ResourceType.LOG))

        await admin_role.permissions.add(*admin_permissions)

        # 创建普通用户角色
        user_role = await Role.create(
            name="普通用户",
            description="只能查看自己信息的普通用户",
            is_default=True,
        )

        # 普通用户不分配任何系统权限，只能通过API访问自己的信息
        # 注意：普通用户访问自己信息的权限是通过API路由逻辑控制的，不需要在RBAC中设置
        logger.info("已创建普通用户角色（无系统权限）")
    except Exception as e:
        logger.error(f"初始化角色时出错: {e}")


async def init_superuser() -> None:
    """
    初始化超级管理员
    """
    try:
        # 检查是否已有超级管理员
        # 通过查询是否有用户关联了超级管理员角色来判断
        super_admin_role = await Role.filter(name="超级管理员").first()
        if not super_admin_role:
            logger.warning("超级管理员角色不存在，无法创建超级管理员用户")
            return
            
        superuser_exists = await super_admin_role.users.all().exists()
        if superuser_exists:
            logger.info("超级管理员已存在，跳过初始化")
            return

        # 创建超级管理员
        superuser = await User.create(
            username="admin",
            hashed_password=get_password_hash("admin123"),
            is_active=True,
        )

        # 为超级管理员添加超级管理员角色
        await superuser.roles.add(super_admin_role)

        logger.info("已创建超级管理员")
    except Exception as e:
        logger.error(f"初始化超级管理员时出错: {e}")


if __name__ == "__main__":
    """
    直接运行此模块时，初始化数据库基础数据
    注意：在运行此脚本前，应确保已通过Aerich创建了表结构
    """
    asyncio.run(init_db())
