"""
日志配置模块

此模块基于 loguru 提供日志配置功能，支持控制台日志和文件日志的设置。
支持自定义日志级别、格式、轮转策略等，并提供敏感数据过滤功能。
"""

import sys
import logging
from pathlib import Path
from typing import Dict, Any, Optional, List
import re

from loguru import logger
from app.core.config import settings


# 创建拦截器类，用于将标准日志库的日志重定向到loguru
class InterceptHandler(logging.Handler):
    """
    拦截标准日志库的日志处理器
    
    将标准日志库的日志重定向到loguru，用于整合uvicorn等使用标准日志库的组件。
    """

    def emit(self, record: logging.LogRecord) -> None:
        """
        发送日志记录
        
        Args:
            record: 标准日志库的日志记录
        """
        # 获取对应的loguru级别
        try:
            level = logger.level(record.levelname).name
        except ValueError:
            level = record.levelno

        # 查找调用者
        frame, depth = logging.currentframe(), 2
        while frame and frame.f_code.co_filename == logging.__file__:
            frame = frame.f_back
            depth += 1

        # 使用loguru记录日志
        logger.opt(depth=depth, exception=record.exc_info).log(
            level, record.getMessage()
        )


class LoggerConfig:
    """
    日志配置类

    用于配置和管理应用的日志系统，支持控制台日志和文件日志。
    """

    def __init__(
            self, log_dir: str = "logs", level: str = "INFO", format: Optional[str] = None,
            retention: str = "7 days", rotation: str = "10 MB", compression: str = "zip",
            sensitive_keys: Optional[List[str]] = None
    ):
        """
        初始化日志配置

        Args:
            log_dir (str): 日志文件存储目录，默认为 "logs"
            level (str): 日志级别，默认为 "INFO"
            format (Optional[str]): 日志格式，默认为 None（使用内置格式）
            retention (str): 日志保留策略，默认为 "7 days"
            rotation (str): 日志轮转策略，默认为 "10 MB"
            compression (str): 日志压缩格式，默认为 "zip"
            sensitive_keys (Optional[List[str]]): 敏感信息关键字列表，默认为常见敏感字段
        """
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(exist_ok=True, parents=True)

        self.level = level.upper()
        self.format = format or (
            "<green>{time:YYYY-MM-DD HH:mm:ss.SSS}</green> | "
            "<level>{level: <8}</level> | "
            "process [<cyan>{process}</cyan>]:<cyan>{thread}</cyan> | "
            "<cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> - "
            "<level>{message}</level>"
        )
        self.retention = retention
        self.rotation = rotation
        self.compression = compression
        self.sensitive_keys = sensitive_keys or [
            "password", "token", "secret", "auth",
        ]

    def setup(self) -> None:
        """
        设置日志系统

        配置控制台日志和文件日志，并添加敏感数据过滤器。
        """
        try:
            # 移除默认处理器
            logger.remove()

            # 添加控制台处理器
            logger.add(
                sys.stderr,
                level=self.level,
                format=self.format,
                colorize=True,
                backtrace=True,
                diagnose=True,
                filter=self._filter_sensitive_data,
            )

            # 添加文件处理器 - 所有日志
            logger.add(
                self.log_dir / "{time:YYYY-MM-DD}.log",
                level=self.level,
                format=self.format,
                rotation=self.rotation,
                retention=self.retention,
                compression=self.compression,
                backtrace=True,
                diagnose=True,
                enqueue=True,
                filter=self._filter_sensitive_data,
            )

            # 添加文件处理器 - 错误日志
            logger.add(
                self.log_dir / "{time:YYYY-MM-DD}_error.log",
                level="ERROR",
                format=self.format,
                rotation=self.rotation,
                retention=self.retention,
                compression=self.compression,
                backtrace=True,
                diagnose=True,
                enqueue=True,
                filter=self._filter_sensitive_data,
            )

            # 添加文件处理器 - 访问日志
            logger.add(
                self.log_dir / "{time:YYYY-MM-DD}_access.log",
                level="INFO",
                format=self.format,
                rotation=self.rotation,
                retention=self.retention,
                compression=self.compression,
                filter=lambda record: record["extra"].get("access_log") is True,
                enqueue=True,
            )

            # 配置uvicorn和其他使用标准日志库的日志
            self._setup_standard_library_loggers()

            logger.info("日志系统已初始化")
        except Exception as e:
            print(f"日志配置失败: {e}")
            raise

    def _setup_standard_library_loggers(self) -> None:
        """
        配置标准日志库
        
        将标准日志库的日志重定向到loguru，用于整合uvicorn等使用标准日志库的组件。
        """
        # 配置标准日志库的根日志器
        logging.basicConfig(handlers=[InterceptHandler()], level=0, force=True)

        # 配置uvicorn日志
        for logger_name in [
            "uvicorn",
            "uvicorn.error",
            "uvicorn.access",
            "fastapi",
            "tortoise",
            "asyncpg",
        ]:
            logging_logger = logging.getLogger(logger_name)
            logging_logger.handlers = [InterceptHandler()]
            logging_logger.propagate = False  # 禁止日志信息向上传播

        # 设置uvicorn访问日志格式
        logging.getLogger("uvicorn.access").handlers = [InterceptHandler()]

    def _filter_sensitive_data(self, record: Dict[str, Any]) -> bool:
        """
        过滤敏感数据

        在日志记录前处理敏感数据，将其替换为 "***"。

        Args:
            record: 日志记录对象

        Returns:
            bool: 始终返回 True，表示记录该日志
        """
        if isinstance(record["message"], str):
            for key in self.sensitive_keys:
                # 匹配形如 "password": "123456" 或 password=123456 的模式
                patterns = [
                    rf'"{key}":\s*"[^"]*"',
                    rf"'{key}':\s*'[^']*'",
                    rf"{key}=\S+",
                ]
                for pattern in patterns:
                    record["message"] = re.sub(pattern, f"{key}=***", record["message"])
        return True


# 创建全局日志配置实例
logger_config = LoggerConfig(level=settings.LOG_LEVEL)