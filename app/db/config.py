"""
数据库配置模块

此模块定义了Tortoise ORM的配置，用于数据库连接和迁移。
"""

from app.core.config import settings

# Tortoise ORM配置
TORTOISE_ORM = {
    "connections": {
        "default": str(settings.DATABASE_URI)
    },
    "apps": {
        "models": {
            "models": ["app.models", "aerich.models"],
            "default_connection": "default",
        }
    },
    "use_tz": False,
    "timezone": settings.TIMEZONE
}
