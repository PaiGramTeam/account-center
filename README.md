# Paigram Account Center

用户中心系统，为 PaiGram 系列机器人提供集中的用户数据管理，同时为终端用户提供账号管理界面。

## 系统架构

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   BOT-1     │     │   BOT-2     │     │   BOT-N     │     │  Web用户    │
│  (RPC客户端) │     │  (RPC客户端) │     │  (RPC客户端) │     │  (浏览器)   │
└──────┬──────┘     └──────┬──────┘     └──────┬──────┘     └──────┬──────┘
       │                   │                   │                   │
       │    gRPC/HTTP      │    gRPC/HTTP      │                   │ HTTPS
       └───────────────────┼───────────────────┘                   │
                           │                                       │
                    ┌──────▼──────────────────────────────────────▼──────┐
                    │                    Paigram 用户中心                  │
                    │  ┌────────────┐  ┌────────────┐  ┌────────────┐   │
                    │  │  RPC服务   │  │  REST API  │  │  Web界面   │   │
                    │  └────────────┘  └────────────┘  └────────────┘   │
                    └─────────────────────────┬───────────────────────────┘
                                             │
                           ┌─────────────────┴─────────────────┐
                           │          数据存储层                │
                           │  ┌─────────┐      ┌─────────┐    │
                           │  │  MySQL  │      │  Redis  │    │
                           │  └─────────┘      └─────────┘    │
                           └───────────────────────────────────┘
```

## 功能特性

### 已实现功能
- ✅ **用户认证系统**
  - 邮箱注册/登录
  - OAuth 第三方登录
  - JWT Token 认证
  - 会话管理
  
- ✅ **用户管理**
  - 用户资料管理
  - 多邮箱绑定
  - 登录审计日志
  
- ✅ **Bot 认证系统**
  - Bot 注册和管理
  - API Key/Secret 认证
  - 访问令牌管理
  - 权限作用域控制
  
- ✅ **RPC 服务**
  - gRPC 高性能接口
  - Protocol Buffers 序列化
  - 认证拦截器
  - 多语言客户端支持
  
- ✅ **基础设施**
  - RESTful API
  - 数据库迁移
  - Redis 缓存
  - 结构化日志

### 开发中功能
- 🚧 **Web 管理界面** - 用户自助管理平台
- 🚧 **安全增强** - 2FA、异常检测、设备管理
- 🚧 **权限系统** - RBAC 细粒度权限控制

详细开发计划请查看 [DEVELOPMENT_PLAN.md](./DEVELOPMENT_PLAN.md)

## 快速开始

### 环境要求
- Go 1.24+
- MySQL 8.0+
- Redis 6.0+

### 安装运行

1. **克隆项目**
```bash
git clone https://github.com/yourusername/paigram.git
cd paigram
```

2. **配置数据库**
```bash
# 复制配置文件
cp config/config.example.yaml config/config.yaml
# 编辑配置文件，设置数据库连接等信息
```

3. **安装依赖**
```bash
go mod download
```

4. **运行数据库迁移**
```bash
go run main.go migrate up
```

5. **启动服务**
```bash
# 开发模式
go run main.go

# 生产模式
go build -tags release -o paigram main.go
./paigram
```

## API 文档

### REST API 端点

#### 认证相关
- `POST /api/v1/auth/register` - 用户注册
- `POST /api/v1/auth/login` - 用户登录
- `POST /api/v1/auth/refresh` - 刷新 Token
- `POST /api/v1/auth/logout` - 用户登出
- `POST /api/v1/auth/verify-email` - 邮箱验证
- `POST /api/v1/auth/oauth/:provider/init` - OAuth 认证初始化
- `POST /api/v1/auth/oauth/:provider/callback` - OAuth 回调处理

#### 用户管理
- `GET /api/v1/users` - 获取用户列表
- `GET /api/v1/users/:id` - 获取用户详情
- `GET /api/v1/profiles/:id` - 获取用户资料
- `PATCH /api/v1/profiles/:id` - 更新用户资料

### RPC 接口 (gRPC)
Paigram 提供高性能的 gRPC 接口用于 Bot 客户端调用。详细文档请查看 [gRPC API 文档](./docs/GRPC_API.md)

#### 主要服务
- **BotAuthService** - Bot 认证和令牌管理
- **UserService** - 用户数据访问

服务默认运行在 50051 端口。

## 开发指南

### 项目结构
```
paigram/
├── cmd/                # 命令行工具
├── config/             # 配置文件
├── docs/               # 文档
├── examples/           # 示例代码
│   └── grpc-client/   # gRPC 客户端示例
├── initialize/         # 初始化脚本
│   └── migrate/       # 数据库迁移
├── internal/          # 内部包
│   ├── cache/         # 缓存实现
│   ├── config/        # 配置管理
│   ├── database/      # 数据库连接
│   ├── grpc/          # gRPC 实现
│   │   ├── interceptor/ # 拦截器
│   │   ├── server/    # 服务器
│   │   └── service/   # 服务实现
│   ├── handler/       # HTTP 处理器
│   ├── logging/       # 日志系统
│   ├── model/         # 数据模型
│   ├── router/        # 路由定义
│   └── sessioncache/  # 会话缓存
├── pkg/               # 公共包
├── proto/             # Protocol Buffers 定义
│   └── paigram/v1/    # API v1 定义
└── web/               # Web 前端 (计划中)
```

### 开发规范
详细的开发规范请参考 [AGENTS.md](./AGENTS.md)

### 测试
```bash
# 运行所有测试
go test ./...

# 运行特定测试
go test -run TestFunctionName ./path/to/package

# 生成覆盖率报告
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out -o coverage.html
```