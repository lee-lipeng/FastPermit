"""
权限模型模块

此模块定义了与权限系统相关的数据模型，包括资源类型、操作类型、权限、角色等。
这些模型是实现基于角色的访问控制(RBAC)的基础。
"""

from tortoise import fields, models


class ResourceType(models.Model):
    """
    资源类型模型
    
    存储系统中可被访问和操作的资源类型。
    每种资源类型对应系统中的一个功能模块或数据实体。
    """
    id = fields.IntField(pk=True)
    code = fields.CharField(max_length=50, unique=True, description="资源类型代码")
    name = fields.CharField(max_length=100, description="资源类型名称")
    description = fields.CharField(max_length=200, null=True, description="资源类型描述")
    is_system = fields.BooleanField(default=False, description="是否为系统内置类型")
    created_at = fields.DatetimeField(auto_now_add=True)
    updated_at = fields.DatetimeField(auto_now=True)

    class Meta:
        table = "resource_types"

    def __str__(self):
        return self.code


class ActionType(models.Model):
    """
    操作类型模型
    
    存储对资源可执行的操作类型。
    这些操作类型与REST API的CRUD操作相对应，并可扩展特殊操作。
    """
    id = fields.IntField(pk=True)
    code = fields.CharField(max_length=50, unique=True, description="操作类型代码")
    name = fields.CharField(max_length=100, description="操作类型名称")
    description = fields.CharField(max_length=200, null=True, description="操作类型描述")
    is_system = fields.BooleanField(default=False, description="是否为系统内置类型")
    created_at = fields.DatetimeField(auto_now_add=True)
    updated_at = fields.DatetimeField(auto_now=True)

    class Meta:
        table = "action_types"

    def __str__(self):
        return self.code


class Permission(models.Model):
    """
    权限模型
    
    定义系统中的权限，每个权限是资源类型和操作类型的组合。
    例如：用户创建(user:create)、角色读取(role:read)等。
    """
    id = fields.IntField(pk=True)
    resource_type = fields.ForeignKeyField("models.ResourceType", related_name="permissions", description="资源类型")
    action_type = fields.ForeignKeyField("models.ActionType", related_name="permissions", description="操作类型")
    name = fields.CharField(max_length=100, unique=True, description="权限名称")
    description = fields.CharField(max_length=200, null=True, description="权限描述")
    created_at = fields.DatetimeField(auto_now_add=True)
    updated_at = fields.DatetimeField(auto_now=True)

    class Meta:
        table = "permissions"
        unique_together = (("resource_type", "action_type"),)

    def __str__(self):
        return f"{self.resource_type}:{self.action_type}"


class Role(models.Model):
    """
    角色模型
    
    定义系统中的角色，每个角色可以拥有多个权限。
    用户通过被分配角色来获得相应的权限。
    """
    id = fields.IntField(pk=True)
    name = fields.CharField(max_length=50, unique=True, description="角色名称")
    description = fields.CharField(max_length=200, null=True, description="角色描述")
    is_default = fields.BooleanField(default=False, description="是否为默认角色")
    permissions = fields.ManyToManyField(
        "models.Permission", related_name="roles"
    )  # 角色拥有的权限
    created_at = fields.DatetimeField(auto_now_add=True)
    updated_at = fields.DatetimeField(auto_now=True)

    class Meta:
        table = "roles"

    def __str__(self):
        return self.name
