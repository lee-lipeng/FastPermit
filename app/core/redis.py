import pickle
import functools
from typing import Any, Callable, Optional, TypeVar, cast

from redis.asyncio import Redis, from_url

from app.core.config import settings
from app.core.logger import logger


class AsyncRedisClient:
    """
    异步Redis客户端封装
    
    提供异步Redis操作的封装，支持序列化和反序列化。
    """

    _instance = None
    _redis: Optional[Redis] = None

    def __new__(cls, *args, **kwargs):
        """
        单例模式实现
        
        Returns:
            AsyncRedisClient: 单例实例
        """
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    async def init(self) -> None:
        """
        初始化Redis连接
        """
        try:
            if self._redis is not None:
                logger.info("Redis客户端已初始化，跳过")
                return

            # 构建Redis连接URL
            redis_url = f"redis://"
            if settings.REDIS_PASSWORD:
                password = settings.REDIS_PASSWORD
                password_str = password.get_secret_value() if hasattr(password, 'get_secret_value') else password
                redis_url += f":{password_str}@"
            redis_url += f"{settings.REDIS_HOST}:{settings.REDIS_PORT}/{settings.REDIS_DB}"

            logger.debug(f"Redis连接URL: {redis_url}")

            # 创建Redis连接
            self._redis = await from_url(
                redis_url,
                encoding="utf-8",
                decode_responses=False  # 保持原始字节串
            )
            """
            为什么使用pickle序列化而不是自动解码
            1.数据类型的灵活性：
            Redis原生只支持字符串、列表、集合等基本数据类型
            使用pickle可以序列化几乎任何Python对象，包括复杂的数据结构、自定义类等
            在权限系统中，我们需要存储如Set[Tuple[ResourceType, ActionType]]这样的复杂数据类型
            2.保留Python对象的类型信息：
            自动解码只能处理简单的字符串转换
            pickle保留了对象的类型信息，反序列化后得到的是原始对象的精确副本
            这对于存储枚举类型（如ResourceType和ActionType）特别重要
            3.处理二进制数据：
            pickle序列化后的数据是二进制格式，可以直接存储在Redis中
            这避免了字符编码问题，特别是处理包含非ASCII字符的数据时"""
            # 测试连接
            pong = await self._redis.ping()
            if pong:
                logger.info("Redis连接成功")
            else:
                logger.error("Redis连接失败: ping命令未返回预期结果")

        except Exception as e:
            logger.error(f"Redis连接失败: {e}")
            # 如果连接失败，设置为None以便后续重试
            self._redis = None

    async def close(self):
        """
        关闭Redis连接
        
        Raises:
            RuntimeError: Redis客户端未初始化时抛出
        """
        if self._redis:
            await self._redis.close()
            self._redis = None
            logger.info("Redis连接已关闭")

    @property
    def redis(self) -> Redis:
        """
        获取原始Redis客户端
        
        Raises:
            RuntimeError: Redis客户端未初始化时抛出
        """
        if self._redis is None:
            raise RuntimeError("Redis客户端尚未初始化，请先调用init()方法")
        return self._redis

    async def get(self, key: str) -> Any:
        """
        获取缓存值
        
        Args:
            key: 缓存键
            
        Returns:
            Any: 缓存值，如果不存在则返回None
        """
        try:
            if not self._redis:
                logger.warning("Redis客户端未初始化")
                return None

            value = await self._redis.get(key)

            if value is None:
                logger.debug(f"缓存未命中: {key}")
                return None

            try:
                result = pickle.loads(value)
                logger.debug(f"从缓存获取到值: {key}, 类型: {type(result)}")
                return result
            except Exception as e:
                logger.error(f"反序列化缓存值失败: {key}, 错误: {e}")
                return None
        except Exception as e:
            logger.error(f"获取缓存值时出错: {key}, 错误: {e}")
            return None

    async def set(self, key: str, value: Any, expire: int = None) -> bool:
        """
        设置缓存数据
        
        Args:
            key: 缓存键
            value: 要缓存的值
            expire: 过期时间（秒），默认为None（不过期）
            
        Returns:
            bool: 操作是否成功
        """
        try:
            data = pickle.dumps(value)
            if expire:
                await self._redis.setex(key, expire, data)
            else:
                await self._redis.set(key, data)
            return True
        except Exception as e:
            logger.error(f"Redis设置数据失败: {e}")
            return False

    async def delete(self, key: str) -> bool:
        """
        删除缓存数据
        
        Args:
            key: 缓存键
            
        Returns:
            bool: 操作是否成功
        """
        try:
            await self._redis.delete(key)
            return True
        except Exception as e:
            logger.error(f"Redis删除数据失败: {e}")
            return False

    async def exists(self, key: str) -> bool:
        """
        检查键是否存在
        
        Args:
            key: 缓存键
            
        Returns:
            bool: 键是否存在
        """
        try:
            result = bool(await self._redis.exists(key))
            return result
        except Exception as e:
            logger.error(f"Redis检查键是否存在失败: {e}")
            return False

    async def delete_pattern(self, pattern: str) -> int:
        """
        删除匹配模式的所有键
        
        Args:
            pattern: 匹配模式
            
        Returns:
            int: 删除的键数量
        """
        deleted_count = 0
        try:
            # 使用 scan_iter 代替 keys 以避免阻塞
            cursor = b'0'
            keys_to_delete = []

            while cursor:
                cursor, keys = await self._redis.scan(cursor=cursor, match=pattern, count=100)
                if keys:
                    keys_to_delete.extend(keys)

                if cursor == b'0':
                    break

            if keys_to_delete:
                deleted_count = await self._redis.delete(*keys_to_delete)
                logger.debug(f"已删除 {deleted_count} 个匹配 '{pattern}' 的键")

            return deleted_count
        except Exception as e:
            logger.error(f"Redis删除匹配模式的键失败: {e}")
            return 0

    async def ttl(self, key: str) -> int:
        """
        获取键的剩余生存时间（秒）
        
        Args:
            key: 缓存键
            
        Returns:
            int: 剩余生存时间（秒），-1表示永不过期，-2表示键不存在
        """
        try:
            result = await self._redis.ttl(key)
            return result
        except Exception as e:
            logger.error(f"Redis获取键的剩余生存时间失败: {e}")
            return -2  # -2 表示键不存在

    async def incr(self, key: str, amount: int = 1) -> int:
        """
        增加计数器
        
        Args:
            key: 缓存键
            amount: 增加的数量，默认为1
            
        Returns:
            int: 增加后的值
        """
        try:
            result = await self._redis.incr(key, amount)
            return result
        except Exception as e:
            logger.error(f"Redis增加计数器失败: {e}")
            return 0

    async def hset(self, name: str, key: str, value: Any) -> bool:
        """
        设置哈希表字段的值
        
        Args:
            name: 哈希表名
            key: 字段名
            value: 字段值
            
        Returns:
            bool: 操作是否成功
        """
        try:
            data = pickle.dumps(value)
            # 确保 key 是字符串类型
            str_key = str(key) if not isinstance(key, str) else key
            # 显式转换为字典形式调用，避免类型问题
            await self._redis.hset(name=name, mapping={str_key: data})
            return True
        except Exception as e:
            logger.error(f"Redis设置哈希表字段的值失败: {e}")
            return False

    async def hget(self, name: str, key: str) -> Optional[Any]:
        """
        获取哈希表字段的值
        
        Args:
            name: 哈希表名
            key: 字段名
            
        Returns:
            Optional[Any]: 字段的值，如果不存在则返回None
        """
        try:
            # 确保 key 是字符串类型
            str_key = str(key) if not isinstance(key, str) else key
            data = await self._redis.hget(name, str_key)
            if data:
                # 确保 data 是字节类型
                if isinstance(data, str):
                    data = data.encode('utf-8')
                result = pickle.loads(data)
                return result
            return None
        except Exception as e:
            logger.error(f"Redis获取哈希表字段的值失败: {e}")
            return None

    async def hdel(self, name: str, *keys) -> bool:
        """
        删除哈希表字段
        
        Args:
            name: 哈希表名
            *keys: 要删除的字段名
            
        Returns:
            bool: 操作是否成功
        """
        try:
            await self._redis.hdel(name, *keys)
            return True
        except Exception as e:
            logger.error(f"Redis删除哈希表字段失败: {e}")
            return False

    async def hgetall(self, name: str) -> dict:
        """
        获取哈希表中所有的字段和值
        
        Args:
            name: 哈希表名
            
        Returns:
            dict: 包含所有字段和值的字典
        """
        try:
            data = await self._redis.hgetall(name)
            result = {}
            for key, value in data.items():
                try:
                    # 确保 value 是字节类型
                    if isinstance(value, str):
                        value = value.encode('utf-8')
                    result[key] = pickle.loads(value)
                except Exception as e:
                    logger.warning(f"反序列化哈希表值失败: {key}, 错误: {e}")
                    result[key] = value
            return result
        except Exception as e:
            logger.error(f"Redis获取哈希表中所有的字段和值失败: {e}")
            return {}


# 单例模式
redis_client = AsyncRedisClient()


# ================ 依赖注入方式 ================

async def get_redis_client() -> AsyncRedisClient:
    """
    获取Redis客户端的依赖注入
    
    Returns:
        AsyncRedisClient: Redis客户端实例
    """
    return redis_client


async def get_redis() -> Redis:
    """
    获取原始Redis客户端的依赖注入
    
    Returns:
        Redis: 原始Redis客户端实例
    """
    return redis_client.redis


# ================ 装饰器方式 ================

F = TypeVar('F', bound=Callable[..., Any])


def with_redis_client(func: F) -> F:
    """
    装饰器：注入Redis客户端
    
    Args:
        func: 要装饰的函数
        
    Returns:
        F: 装饰后的函数
    """

    @functools.wraps(func)
    async def wrapper(*args, **kwargs):
        return await func(redis_client, *args, **kwargs)

    return cast(F, wrapper)


def with_redis(func: F) -> F:
    """
    装饰器：注入原始Redis客户端
    
    Args:
        func: 要装饰的函数
        
    Returns:
        F: 装饰后的函数
    """

    @functools.wraps(func)
    async def wrapper(*args, **kwargs):
        return await func(redis_client.redis, *args, **kwargs)

    return cast(F, wrapper)


# ================ 缓存装饰器 ================

def redis_cache(key_prefix: str, expire: int = 3600):
    """
    Redis缓存装饰器
    
    Args:
        key_prefix: 缓存键前缀
        expire: 过期时间（秒），默认为3600秒（1小时）
        
    Returns:
        Callable: 装饰器函数
    """

    def decorator(func: Callable):
        @functools.wraps(func)
        async def wrapper(*args, **kwargs):
            # 生成缓存键
            key_parts = [key_prefix]

            # 添加位置参数
            key_parts.extend([str(arg) for arg in args])

            # 添加关键字参数（按键排序以确保一致性）
            for k, v in sorted(kwargs.items()):
                key_parts.append(f"{k}={v}")

            cache_key = ":".join(key_parts)

            # 尝试从缓存获取
            cached_result = await redis_client.get(cache_key)
            if cached_result is not None:
                logger.debug(f"缓存命中: {cache_key}")
                return cached_result

            # 缓存未命中，执行原始函数
            logger.debug(f"缓存未命中: {cache_key}")
            result = await func(*args, **kwargs)

            # 存入缓存
            await redis_client.set(cache_key, result, expire)

            return result

        return wrapper

    return decorator
