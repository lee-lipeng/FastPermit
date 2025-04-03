# FastPermit

基于 FastAPI 和 PostgreSQL 的基础权限管理系统。

<div align="center">
  <img src="https://img.shields.io/badge/Python-3.12-blue.svg" alt="Python 3.12">
  <img src="https://img.shields.io/badge/FastAPI-0.115-green.svg" alt="FastAPI 0.115">
  <img src="https://img.shields.io/badge/License-MIT-yellow.svg" alt="License: MIT">
</div>

## 功能特点

### 核心功能

- 基于 RBAC 的权限管理：资源、操作、权限、角色的完整管理
- 混合 RBAC 和 ABAC 的权限模型：支持用户直接关联权限和通过角色继承权限
- 用户管理：用户的增删改查、筛选查询
- 角色管理：角色的增删改查、权限分配
- 权限管理：权限的增删改查、资源和操作的组合管理

### 技术特性

- 基于 FastAPI 的现代 API 设计
- 完整的权限验证和授权系统
- 基于 Redis 的权限缓存机制
- 支持多种权限检查方式：装饰器、依赖注入
- 完善的错误处理和日志记录

## 技术栈

- **后端框架**：FastAPI
- **数据验证**：Pydantic 2
- **数据库**：PostgreSQL
- **ORM**：Tortoise-ORM
- **数据库迁移**：Aerich
- **缓存**：Redis
- **日志**：Loguru
- **JSON 处理**：orjson
- **认证**：python-jose + bcrypt
- **服务器**：Uvicorn

## 安装与运行

### 环境要求

- Python 3.8+（推荐 Python 3.12）
- PostgreSQL 12+
- Redis 6+

### 开发环境设置

#### 使用 Conda 创建虚拟环境

```bash
# 创建名为 fastpermit 的 Python 3.12 环境
conda create -n fastpermit python=3.12

# 激活环境
conda activate fastpermit
```

#### 使用 venv 创建虚拟环境

```bash
# 创建虚拟环境
python -m venv venv

# 在 Windows 上激活环境
venv\Scripts\activate

# 在 Linux/macOS 上激活环境
source venv/bin/activate
```

### 安装依赖

```bash
pip install -r requirements.txt
```

### 配置环境变量

创建`.env`文件，配置以下环境变量：

```
# 日志配置
LOG_LEVEL=INFO

# API配置
API_V1_STR=/api/v1
PROJECT_NAME=FastPermit

# 数据库配置
POSTGRES_SERVER=localhost
POSTGRES_USER=postgres
POSTGRES_PASSWORD=
POSTGRES_DB=fastpermit
POSTGRES_PORT=5432

# Redis配置
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_DB=0
REDIS_PASSWORD=

# 安全配置
ACCESS_TOKEN_EXPIRE_MINUTES=11520
ALGORITHM=HS256
SECRET_KEY=
```

### 数据库初始化与迁移

项目使用 Aerich 进行数据库迁移管理。首次运行前，需要按照以下步骤初始化数据库：

#### 1. 初始化 Aerich 配置

```bash
# 初始化 Aerich
aerich init -t app.db.config.TORTOISE_ORM
```

#### 2. 创建数据库表结构

```bash
# 创建初始迁移并应用（创建表结构）
aerich init-db
```

#### 3. 初始化基础数据

应用启动时会自动初始化基础数据（权限、角色、超级管理员账号等），但也可以手动执行：

```bash
# 手动初始化基础数据
python -m app.db.init_db
```

#### 4. 后续数据库模型变更

当模型发生变化时，可以创建新的迁移并应用：

```bash
# 创建新的迁移
aerich migrate --name "描述迁移的名称"

# 应用迁移
aerich upgrade
```

### 运行应用

```bash
# 开发模式
uvicorn main:create_application --factory --reload

# 生产模式
uvicorn main:create_application --factory --host 0.0.0.0 --port 8000
```

## API 文档

启动应用后，访问以下地址查看 API 文档：

- Swagger UI: http://localhost:8000/docs
- ReDoc: http://localhost:8000/redoc

## 项目结构

```
.
├── app/                    # 应用主目录
│   ├── api/                # API路由定义
│   │   └── v1/             # API v1版本
│   ├── core/               # 核心功能模块
│   │   ├── config.py       # 应用配置
│   │   ├── security.py     # 安全相关功能
│   │   ├── permissions.py  # 权限管理
│   │   ├── exceptions.py   # 异常处理
│   │   ├── logger.py       # 日志配置
│   │   ├── redis.py        # Redis客户端
│   │   ├── middleware.py   # 中间件
│   │   └── deps.py         # 依赖注入
│   ├── db/                 # 数据库相关
│   │   ├── config.py       # 数据库配置
│   │   └── init_db.py      # 数据库初始化
│   ├── models/             # 数据模型定义
│   │   ├── user.py         # 用户模型
│   │   └── permission.py   # 权限模型
│   ├── schemas/            # Pydantic模型/数据验证
│   │   ├── user.py         # 用户模式
│   │   ├── token.py        # 令牌模式
|   |   └── permission.py   # 权限模式
│   └── utils/              # 通用工具函数
├── logs/                   # 日志文件目录
├── migrations/             # 数据库迁移文件
├── static/                 # 静态文件
├── tests/                  # 测试代码
├── .env                    # 环境变量
├── main.py                 # 应用入口
├── pyproject.toml          # 项目配置，包含Aerich配置
├── LICENSE                 # MIT许可证
├── README.md               # 项目说明
└── requirements.txt        # 依赖包列表
```

## 初始账号

系统初始化时会创建一个超级管理员账号：

- 用户名：admin
- 密码：admin123

请在首次登录后修改密码。

## 权限系统使用说明

FastPermit 提供了灵活的权限验证系统，支持多种权限验证方式，可根据不同场景选择最合适的方法。

### 权限验证方式

系统提供了三种权限验证方式：

1. **装饰器方式**：适用于整个路由函数需要权限验证的场景
2. **依赖注入方式**：适用于需要在路由函数内部获取当前用户对象并验证权限的场景
3. **资源特定权限函数**：为常用资源提供的快捷权限验证函数

### 使用示例

#### 1. 使用装饰器方式

```python
from app.core.permissions import permission_required

@router.get("/users")
@permission_required(("user", "list"))
async def list_users():
    # 这里的代码只有在用户有 user:list 权限时才会执行
    users = await User.all()
    return users
```

#### 2. 依赖注入方式

##### 使用 `PermissionRequired` 类

```python
from app.core.permissions import PermissionRequired

@router.get("/users")
async def list_users(current_user: User = Depends(PermissionRequired(("user", "list")))):
    # 这里可以直接使用 current_user 对象
    # 如果权限检查失败，函数不会被调用
    users = await User.all()
    return {"users": users, "requested_by": current_user.username}
```

##### 使用 `has_permission` 函数

```python
from app.core.permissions import has_permission

@router.get("/users")
async def list_users(user: User = Depends(has_permission("user", "list"))):
    # 简化了依赖注入语法，更加清晰
    users = await User.all()
    return {"users": users, "requested_by": user.username}
```

#### 3. 使用资源特定权限函数

```python
from app.core.permissions import has_user_create

@router.post("/users")
async def create_user(
    user_data: UserCreate,
    current_user: User = Depends(has_user_create())
):
    # 使用特定权限函数更加直观
    new_user = await User.create(**user_data.dict())
    return new_user
```

#### 4. 组合多个权限检查

```python
@router.get("/reports")
@permission_required(("report", "list"), ("statistics", "read"))
async def list_reports():
    # 需要同时具有 report:list 和 statistics:read 权限
    return {"reports": [...]}
```

#### 5. 禁用超级管理员绕过

默认情况下，超级管理员可以绕过权限检查，但可以通过设置禁用此行为：

```python
@permission_required(("sensitive", "operation"), allow_super_admin=False)
async def perform_sensitive_operation():
    # 即使是超级管理员也需要具备特定权限
    pass
```

#### 6. 结合字典形式的权限规范

```python
@permission_required(
    {"resource": "user", "action": "update"},
    {"resource": "role", "action": "read"}
)
async def update_user_with_role():
    # 需要同时具有 user:update 和 role:read 权限
    pass
```

### 权限检查结果与处理

- 权限检查通过：路由函数正常执行
- 权限检查失败：抛出 `PermissionDenied` 异常（HTTP 403），并包含详细错误信息
- 认证失败：抛出 `AuthenticationError` 异常（HTTP 401）

### 权限来源

系统支持两种权限来源：

1. **角色继承权限**：用户通过所属角色继承该角色拥有的所有权限
2. **用户直接权限**：直接分配给用户的特定权限，不依赖于角色

这种混合模式（RBAC+ABAC）提供了更灵活的权限管理：

- 可以为用户分配特殊权限而不必创建新角色
- 可以临时授予或撤销某些权限
- 可以覆盖角色提供的某些权限

### 权限缓存与清理

权限系统使用 Redis 缓存用户权限，以提高性能：

```python
# 清除特定用户的权限缓存
from app.core.permissions import clear_user_permissions_cache
await clear_user_permissions_cache(user_id)

# 清除所有用户的权限缓存
from app.core.permissions import clear_all_permissions_cache
await clear_all_permissions_cache()

# 清除与特定角色相关的权限缓存
from app.core.permissions import handle_role_permission_change
await handle_role_permission_change(role_id)
```

## 部署

### Docker 部署

项目支持使用 Docker 和 Docker Compose 进行部署。项目包含以下 Docker 相关文件：

- `Dockerfile`: 定义 FastPermit 应用的容器镜像
- `docker-compose.yml`: 定义多容器应用编排
- `.dockerignore`: 指定构建镜像时要忽略的文件

#### 使用 Docker Compose 部署

1. 确保已安装 Docker 和 Docker Compose

```bash
# 检查 Docker 版本
docker --version

# 检查 Docker Compose 版本
docker-compose --version
```

2. 克隆项目并进入项目目录

```bash
git clone https://github.com/lee-lipeng/FastPermit.git
cd FastPermit
```

3. 启动所有服务

```bash
docker-compose up -d
```

此命令将启动三个容器：

- PostgreSQL 数据库 (`fastpermit-postgres`)
- Redis 缓存 (`fastpermit-redis`)
- FastPermit 应用 (`fastpermit-app`)

4. 查看容器状态

```bash
docker-compose ps
```

5. 查看应用日志

```bash
# 查看所有容器的日志
docker-compose logs

# 查看特定容器的日志
docker-compose logs app

# 实时查看日志
docker-compose logs -f app
```

6. 停止服务

```bash
# 停止所有服务但不删除容器
docker-compose stop

# 停止并删除容器和网络
docker-compose down

# 停止并删除容器、网络和数据卷（谨慎使用，会删除数据）
docker-compose down -v
```

#### 手动构建和运行 Docker 镜像

如果您想单独构建和运行 FastPermit 应用容器：

1. 构建镜像

```bash
docker build -t fastpermit:latest .
```

2. 运行容器

```bash
docker run -d --name fastpermit-app -p 8000:8000 \
  -e POSTGRES_SERVER=your-postgres-host \
  -e POSTGRES_USER=postgres \
  -e POSTGRES_PASSWORD=your-password \
  -e POSTGRES_DB=fastpermit \
  -e REDIS_HOST=your-redis-host \
  fastpermit:latest
```

#### Docker 环境变量配置

在 `docker-compose.yml` 中，已经为 FastPermit 应用配置了默认的环境变量。如需自定义，可以修改 `docker-compose.yml` 文件中的 `environment` 部分，或者创建 `.env` 文件供 Docker Compose 使用。

## 许可证

本项目采用 [MIT 许可证](LICENSE) 进行许可。
