"""
用户模型模块

此模块定义了与用户相关的数据模型，包括用户基本信息、角色关联等。
这些模型是系统中用户管理和权限控制的基础。
"""

from tortoise import fields, models
from typing import TYPE_CHECKING
from app.core.logger import logger

if TYPE_CHECKING:
    from app.models.permission import Role, Permission


class User(models.Model):
    """
    用户模型
    
    存储用户的基本信息、认证信息和状态信息。
    通过与Role模型的多对多关系实现基于角色的权限控制。
    """
    id = fields.IntField(pk=True)
    username = fields.CharField(max_length=50, unique=True, description="用户名")
    email = fields.CharField(max_length=100, unique=True, null=True, description="邮箱")
    phone = fields.CharField(max_length=20, null=True)  # 手机号
    hashed_password = fields.CharField(max_length=200, description="哈希密码")
    is_active = fields.BooleanField(default=True, description="是否激活")
    # 关联角色（多对多）
    roles = fields.ManyToManyField(
        "models.Role", related_name="users", through="user_role"
    )
    created_at = fields.DatetimeField(auto_now_add=True, description="创建时间")
    updated_at = fields.DatetimeField(auto_now=True, description="更新时间")
    last_login = fields.DatetimeField(null=True)  # 最后登录时间

    # 关联权限（多对多）
    permissions = fields.ManyToManyField(
        "models.Permission", related_name="users", through="user_permission"
    )

    class Meta:
        table = "users"
        ordering = ["-created_at"]

    def __str__(self):
        return self.username

    async def is_superadmin(self) -> bool:
        """检查用户是否为超级管理员"""
        await self.fetch_related("roles")
        logger.debug(f"用户 {self.id} 的角色数量: {len(self.roles)}")

        for role in self.roles:
            logger.debug(f"检查角色: {role.name}")
            if role.name == "超级管理员":
                logger.debug(f"用户 {self.id} 是超级管理员")
                return True

        logger.debug(f"用户 {self.id} 不是超级管理员")
        return False

    async def is_admin(self) -> bool:
        """检查用户是否为管理员"""
        await self.fetch_related("roles")
        for role in self.roles:
            if role.name == "管理员" or role.name == "超级管理员":
                return True
        return False
