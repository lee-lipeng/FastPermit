"""
应用配置模块

此模块包含应用的配置类 Settings，用于管理应用的各种配置项。
配置项可以通过环境变量进行设置。
"""

import os
import secrets
from typing import Any, List, Optional, Union

from pydantic import AnyHttpUrl, PostgresDsn, field_validator, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict
from dotenv import load_dotenv, set_key

# 加载 .env 文件
load_dotenv()

# 检查环境变量中是否已存在 SECRET_KEY
if not os.getenv("SECRET_KEY"):
    # 如果不存在，生成一个新的密钥
    new_secret_key = secrets.token_urlsafe(32)
    # 将密钥写入 .env 文件
    set_key(".env", "SECRET_KEY", new_secret_key)
    # 重新加载 .env 文件，确保新密钥生效
    load_dotenv()


class Settings(BaseSettings):
    """
    应用配置类

    所有配置项都可以通过环境变量设置。
    """
    # 日志配置
    LOG_LEVEL: str = "INFO"  # 日志级别

    # API配置
    API_V1_STR: str = "/api/v1"  # API V1的路径前缀
    PROJECT_NAME: str = "FastPermit"  # 项目名称

    # 安全配置
    SECRET_KEY: str = None  # 应用的密钥
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24 * 8  # 访问令牌过期时间，单位：分钟（8天）
    ALGORITHM: str = "HS256"  # JWT加密算法

    # CORS配置
    CORS_ALLOW_ORIGINS: Union[List[str], List[AnyHttpUrl]] = ["*"]  # 允许的CORS来源列表
    CORS_ALLOW_CREDENTIALS: bool = True  # 是否允许携带凭据（cookies）
    CORS_ALLOW_METHODS: list = ["*"]  # 允许的HTTP方法列表
    CORS_ALLOW_HEADERS: list = ["*"]  # 允许的HTTP头列表

    @field_validator("CORS_ALLOW_ORIGINS", mode="before")
    def assemble_cors_origins(cls, v: Union[str, List[str]]) -> Union[List[str], str]:
        """
        组装CORS来源列表

        此函数用于处理 CORS_ALLOW_ORIGINS 字段的值。
        如果传入的是字符串且不以 "[" 开头，则按逗号分隔并去除前后空格，返回列表。
        如果传入的是列表或以 "[" 开头的字符串（可能是JSON），则直接返回。
        否则，抛出 ValueError。

        :param v: 传入的 CORS_ALLOW_ORIGINS 值
        :return: 处理后的CORS来源列表或字符串
        :raises ValueError: 如果 v 的类型不符合预期
        """
        if isinstance(v, str) and not v.startswith("["):
            return [i.strip() for i in v.split(",")]
        elif isinstance(v, (list, str)):
            return v
        raise ValueError(v)

    # 数据库配置
    POSTGRES_SERVER: str  # PostgreSQL服务器地址
    POSTGRES_USER: str  # PostgreSQL用户名
    POSTGRES_PASSWORD: SecretStr  # PostgreSQL密码（使用SecretStr保护）
    POSTGRES_DB: str  # PostgreSQL数据库名
    POSTGRES_PORT: str  # PostgreSQL端口
    DATABASE_URI: Optional[PostgresDsn] = None  # 数据库连接URI
    TIMEZONE: str = "Asia/Shanghai"  # 时区设置

    @field_validator("DATABASE_URI", mode="before")
    def assemble_db_connection(cls, v: Optional[str], info: Any) -> Any:
        """
        组装数据库连接URI

        此函数用于处理 DATABASE_URI 字段的值。
        如果传入的是字符串，则直接返回。
        否则，从 info.data 中获取 POSTGRES_USER、POSTGRES_PASSWORD、POSTGRES_SERVER、
        POSTGRES_PORT 和 POSTGRES_DB，构造 PostgreSQL 的 DSN 字符串并返回。

        :param v: 传入的 DATABASE_URI 值
        :param info: 包含配置数据的对象
        :return: 处理后的数据库连接URI
        """
        if isinstance(v, str):
            return v

        data = info.data
        password = data.get('POSTGRES_PASSWORD')
        password_str = password.get_secret_value() if isinstance(password, SecretStr) else password

        postgres_dsn = f"postgres://{data.get('POSTGRES_USER')}:{password_str}@{data.get('POSTGRES_SERVER')}:{data.get('POSTGRES_PORT')}/{data.get('POSTGRES_DB')}"
        return postgres_dsn

    # Redis配置
    REDIS_HOST: str  # Redis服务器地址
    REDIS_PORT: int  # Redis端口
    REDIS_DB: int = 0  # Redis数据库编号
    REDIS_PASSWORD: Optional[SecretStr] = None  # Redis密码（可选）

    # Pydantic配置
    model_config = SettingsConfigDict(
        case_sensitive=True,  # 环境变量区分大小写
        env_file=".env",  # 环境变量文件
        env_file_encoding="utf-8",  # 环境变量文件编码
        extra="ignore"  # 忽略多余的环境变量
    )


settings = Settings()
