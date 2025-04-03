"""
主应用模块

此模块是应用程序的入口点，负责创建FastAPI应用实例、配置中间件、
注册路由、设置数据库连接以及启动应用服务器。
"""

from contextlib import asynccontextmanager

import uvicorn
from fastapi import FastAPI
from tortoise.contrib.fastapi import register_tortoise

from app.api.v1 import api_router
from app.core.config import settings
from app.db.init_db import init_db
from app.db.config import TORTOISE_ORM
from app.core.exceptions import setup_exception_handlers
from app.core.logger import logger_config, logger
from app.core.middleware import setup_middlewares
from app.core.redis import redis_client


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    应用生命周期管理
    
    处理应用启动和关闭时的资源初始化和清理工作。
    
    Args:
        app: FastAPI应用实例
    """
    # 初始化 Redis 连接
    await redis_client.init()

    # 初始化基础数据（不创建表结构，表结构由Aerich管理）
    # 注意：表结构应该在应用启动前通过aerich命令创建
    await init_db()

    yield

    # 关闭 Redis 连接
    try:
        await redis_client.close()
    except Exception as e:
        logger.error(f"关闭Redis连接时出错: {e}")


def create_application() -> FastAPI:
    """
    创建FastAPI应用实例

    配置应用设置、中间件、路由和数据库连接。

    Returns:
        FastAPI: 配置好的FastAPI应用实例
    """
    # 日志配置
    logger_config.setup()

    # 创建应用
    application = FastAPI(
        title=settings.PROJECT_NAME,
        description="基于 FastAPI 和 PostgreSQL 的基础权限管理系统",
        version="1.0.0",
        # openapi_url=f"{settings.API_V1_STR}/openapi.json",
        # docs_url=f"{settings.API_V1_STR}/docs",
        # redoc_url=f"{settings.API_V1_STR}/redoc",
        lifespan=lifespan,
    )

    # 设置中间件
    setup_middlewares(application)

    # 设置异常处理器
    setup_exception_handlers(application)

    # 注册路由
    application.include_router(api_router)

    # 注册Tortoise-ORM
    register_tortoise(
        application,
        config=TORTOISE_ORM,
        generate_schemas=False,  # 不自动生成表结构，使用Aerich管理迁移
        add_exception_handlers=True,
    )

    return application


if __name__ == "__main__":
    """
    应用入口点
    
    当直接运行此模块时，启动uvicorn服务器。
    """

    uvicorn.run(
        "main:create_application",
        host="0.0.0.0",
        port=8000,
        lifespan="on",
        factory=True,
        # reload=True
    )
