"""
中间件模块

此模块提供了FastAPI应用的中间件，包括请求日志、请求ID、CORS等中间件。
"""

import time
import uuid
from typing import Callable

from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp

from app.core.config import settings
from app.core.logger import logger


class RequestIdMiddleware(BaseHTTPMiddleware):
    """
    请求ID中间件
    
    为每个请求生成唯一ID，方便跟踪和调试。
    """

    def __init__(self, app: ASGIApp):
        """初始化中间件"""
        super().__init__(app)

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """为每个请求添加唯一ID"""
        request_id = str(uuid.uuid4())
        request.state.request_id = request_id

        # 处理请求
        try:
            response = await call_next(request)
            # 在响应头中添加请求ID
            response.headers["X-Request-ID"] = request_id
            return response
        except Exception as e:
            logger.exception(f"请求 {request_id} 处理失败: {e}")
            raise


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    """
    请求日志中间件
    
    记录所有HTTP请求的日志，包括请求方法、路径、状态码、处理时间等信息。
    """

    def __init__(self, app: ASGIApp, log_request_body: bool = False):
        """
        初始化中间件
        
        Args:
            app: ASGI应用
            log_request_body: 是否记录请求体内容，默认为False（生产环境不建议开启）
        """
        super().__init__(app)
        self.log_request_body = log_request_body

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """
        处理请求
        
        记录请求开始和结束的日志，计算处理时间，并捕获异常。
        
        Args:
            request: FastAPI请求对象
            call_next: 下一个中间件或路由处理函数
            
        Returns:
            Response: FastAPI响应对象
        """
        # 记录请求开始时间
        start_time = time.time()

        # 获取请求信息
        request_id = getattr(request.state, "request_id", "unknown")
        method = request.method
        url = request.url.path
        query_params = str(request.query_params) if request.query_params else ""
        client_host = request.client.host if request.client else "unknown"

        # 记录请求开始日志
        logger.info(f"请求 [{request_id}] {client_host} {method} {url}{query_params}")

        # 记录请求体（如果启用）
        if self.log_request_body and method in ["POST", "PUT", "PATCH"]:
            try:
                body = await request.body()
                if body:
                    # 限制记录的请求体大小，避免日志过大
                    max_body_log_size = 1000  # 最大记录1000字节
                    body_str = body.decode('utf-8', errors='replace')
                    if len(body_str) > max_body_log_size:
                        body_str = body_str[:max_body_log_size] + "... [截断]"
                    logger.debug(f"请求体 [{request_id}]: {body_str}")
            except Exception as e:
                logger.warning(f"无法读取请求体 [{request_id}]: {e}")

        # 处理请求
        try:
            response = await call_next(request)

            # 计算处理时间
            process_time = time.time() - start_time
            process_time_ms = round(process_time * 1000, 2)

            # 添加处理时间响应头
            response.headers["X-Process-Time"] = f"{process_time_ms}ms"

            # 记录请求结束日志
            status_code = response.status_code
            logger.info(f"响应 [{request_id}] {method} {url} - 状态码: {status_code} - 用时: {process_time_ms}ms")

            # 记录慢请求
            if process_time > 1.0:  # 超过1秒的请求视为慢请求
                logger.warning(f"慢请求警告 [{request_id}] {method} {url} - 用时: {process_time_ms}ms")

            return response
        except Exception as e:
            # 计算处理时间（异常情况）
            process_time = time.time() - start_time
            process_time_ms = round(process_time * 1000, 2)

            logger.exception(f"请求失败 [{request_id}] {method} {url} - 错误: {e} - 用时: {process_time_ms}ms")
            raise


def setup_middlewares(app: FastAPI) -> None:
    """
    设置中间件

    中间件的执行顺序与添加顺序正好相反：
    请求处理时：后添加的中间件先执行
    响应处理时：先添加的中间件先执行
    
    Args:
        app: FastAPI应用实例
    """
    # 添加CORS中间件
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[str(origin) for origin in settings.CORS_ALLOW_ORIGINS],
        allow_credentials=settings.CORS_ALLOW_CREDENTIALS,
        allow_methods=settings.CORS_ALLOW_METHODS,
        allow_headers=settings.CORS_ALLOW_HEADERS,
    )

    # 添加请求日志中间件
    # app.add_middleware(RequestLoggingMiddleware)

    # 添加请求ID中间件
    # app.add_middleware(RequestIdMiddleware)

    logger.info("中间件已设置")
