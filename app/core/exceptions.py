"""
异常处理模块

此模块定义了应用程序的自定义异常类和全局异常处理器。
"""

from typing import Any, Optional, Union

from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import ValidationError
from tortoise.exceptions import DoesNotExist, IntegrityError

from app.core.logger import logger


class APIException(Exception):
    """
    API异常基类
    
    所有自定义API异常都应继承此类。
    
    Attributes:
        status_code: HTTP状态码
        code: 业务错误码
        message: 错误消息
        details: 错误详情
    """

    def __init__(
            self,
            status_code: int = status.HTTP_400_BAD_REQUEST,
            code: int = 400,
            message: str = "请求错误",
            details: Optional[Any] = None,
    ):
        """
        初始化API异常
        
        Args:
            status_code: HTTP状态码，默认为400
            code: 业务错误码，默认为400
            message: 错误消息，默认为"请求错误"
            details: 错误详情，默认为None
        """
        self.status_code = status_code
        self.code = code
        self.message = message
        self.details = details
        super().__init__(self.message)


class PermissionDenied(APIException):
    """
    权限拒绝异常
    
    当用户没有执行操作的权限时抛出。
    """

    def __init__(
            self,
            message: str = "权限不足",
            details: Optional[Any] = None,
    ):
        """
        初始化权限拒绝异常
        
        Args:
            message: 错误消息，默认为"权限不足"
            details: 错误详情，默认为None
        """
        super().__init__(
            status_code=status.HTTP_403_FORBIDDEN,
            code=403,
            message=message,
            details=details,
        )


class NotFound(APIException):
    """
    资源不存在异常
    
    当请求的资源不存在时抛出。
    """

    def __init__(
            self,
            message: str = "资源不存在",
            details: Optional[Any] = None,
    ):
        """
        初始化资源不存在异常
        
        Args:
            message: 错误消息，默认为"资源不存在"
            details: 错误详情，默认为None
        """
        super().__init__(
            status_code=status.HTTP_404_NOT_FOUND,
            code=404,
            message=message,
            details=details,
        )


class AuthenticationError(APIException):
    """
    认证错误异常
    
    当用户认证失败时抛出。
    """

    def __init__(
            self,
            message: str = "认证失败",
            details: Optional[Any] = None,
    ):
        """
        初始化认证错误异常
        
        Args:
            message: 错误消息，默认为"认证失败"
            details: 错误详情，默认为None
        """
        super().__init__(
            status_code=status.HTTP_401_UNAUTHORIZED,
            code=401,
            message=message,
            details=details,
        )


class BadRequest(APIException):
    """
    错误请求异常
    
    当请求参数错误时抛出。
    """

    def __init__(
            self,
            message: str = "请求参数错误",
            details: Optional[Any] = None,
    ):
        """
        初始化错误请求异常
        
        Args:
            message: 错误消息，默认为"请求参数错误"
            details: 错误详情，默认为None
        """
        super().__init__(
            status_code=status.HTTP_400_BAD_REQUEST,
            code=400,
            message=message,
            details=details,
        )


class DatabaseError(APIException):
    """
    数据库错误异常
    
    当数据库操作失败时抛出。
    """

    def __init__(
            self,
            message: str = "数据库操作失败",
            details: Optional[Any] = None,
    ):
        """
        初始化数据库错误异常
        
        Args:
            message: 错误消息，默认为"数据库操作失败"
            details: 错误详情，默认为None
        """
        super().__init__(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            code=500,
            message=message,
            details=details,
        )


async def api_exception_handler(request: Request, exc: APIException) -> JSONResponse:
    """
    API异常处理器
    
    处理所有继承自APIException的异常。
    
    Args:
        request: FastAPI请求对象
        exc: API异常对象
        
    Returns:
        JSONResponse: 包含错误信息的JSON响应
    """
    logger.error(
        f"API异常: {exc.code} - {exc.message}",
        extra={
            "status_code": exc.status_code,
            "code": exc.code,
            "details": exc.details,
            "path": request.url.path,
            "method": request.method,
        },
    )

    return JSONResponse(
        status_code=exc.status_code,
        content={
            "code": exc.code,
            "message": exc.message,
            "details": exc.details,
        },
    )


async def validation_exception_handler(
        request: Request, exc: Union[RequestValidationError, ValidationError]
) -> JSONResponse:
    """
    验证异常处理器
    
    处理请求参数验证错误。
    
    Args:
        request: FastAPI请求对象
        exc: 验证异常对象
        
    Returns:
        JSONResponse: 包含错误信息的JSON响应
    """
    errors = []
    for error in exc.errors():
        error_info = {
            "loc": error.get("loc", []),
            "msg": error.get("msg", ""),
            "type": error.get("type", ""),
        }
        errors.append(error_info)

    logger.warning(
        "请求参数验证失败",
        extra={
            "path": request.url.path,
            "method": request.method,
            "errors": errors,
        },
    )

    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={
            "code": 422,
            "message": "请求参数验证失败",
            "details": errors,
        },
    )


async def tortoise_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """
    Tortoise ORM异常处理器
    
    处理Tortoise ORM相关异常。
    
    Args:
        request: FastAPI请求对象
        exc: 异常对象
        
    Returns:
        JSONResponse: 包含错误信息的JSON响应
    """
    if isinstance(exc, DoesNotExist):
        logger.warning(
            f"资源不存在: {str(exc)}",
            extra={
                "path": request.url.path,
                "method": request.method,
            },
        )
        return JSONResponse(
            status_code=status.HTTP_404_NOT_FOUND,
            content={
                "code": 404,
                "message": "资源不存在",
                "details": str(exc),
            },
        )

    if isinstance(exc, IntegrityError):
        logger.error(
            f"数据完整性错误: {str(exc)}",
            extra={
                "path": request.url.path,
                "method": request.method,
            },
        )
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={
                "code": 400,
                "message": "数据完整性错误",
                "details": str(exc),
            },
        )

    # 其他Tortoise异常
    logger.error(
        f"数据库错误: {str(exc)}",
        extra={
            "path": request.url.path,
            "method": request.method,
            "exception_type": type(exc).__name__,
        },
    )
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "code": 500,
            "message": "数据库操作失败",
            "details": str(exc),
        },
    )


async def general_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """
    通用异常处理器
    
    处理所有未被其他处理器捕获的异常。
    
    Args:
        request: FastAPI请求对象
        exc: 异常对象
        
    Returns:
        JSONResponse: 包含错误信息的JSON响应
    """
    logger.exception(
        f"未处理的异常: {str(exc)}",
        extra={
            "path": request.url.path,
            "method": request.method,
            "exception_type": type(exc).__name__,
        },
    )

    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "code": 500,
            "message": "服务器内部错误",
            "details": str(exc) if str(exc) else None,
        },
    )


def setup_exception_handlers(app: FastAPI) -> None:
    """
    设置异常处理器
    
    为FastAPI应用添加全局异常处理器。
    
    Args:
        app: FastAPI应用实例
    """
    # API异常处理器
    app.add_exception_handler(APIException, api_exception_handler)

    # 验证异常处理器
    app.add_exception_handler(RequestValidationError, validation_exception_handler)
    app.add_exception_handler(ValidationError, validation_exception_handler)

    # Tortoise ORM异常处理器
    app.add_exception_handler(DoesNotExist, tortoise_exception_handler)
    app.add_exception_handler(IntegrityError, tortoise_exception_handler)

    # 通用异常处理器
    app.add_exception_handler(Exception, general_exception_handler)

    logger.info("异常处理器已设置")
