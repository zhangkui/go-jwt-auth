# go-jwt-auth

## 项目说明
`go-jwt-auth` 是一个基于 JWT 的用户认证服务，提供用户注册、登录、令牌刷新和基于角色的接口权限校验。用户数据保存在内存中，适合作为微服务环境中的独立认证服务示例。

服务默认监听 `:8080`，可通过 `ADDR` 配置监听地址，通过 `JWT_SECRET` 配置签名密钥。

主要接口：

- `GET /healthz`：健康检查
- `POST /register`：注册用户
- `POST /login`：登录并获取访问令牌与刷新令牌
- `POST /refresh`：刷新令牌
- `GET /me`：获取当前用户信息
- `GET /admin`：需要 `admin` 角色的示例接口

## 标准命令

```bash
go build ./...     # 编译
go test ./...      # 测试
go vet ./...       # 静态检查
go run ./cmd       # 启动
```

启动后可使用以下命令注册用户：

```bash
curl -X POST http://localhost:8080/register \
  -H "Content-Type: application/json" \
  -d '{"email":"user@example.com","password":"secret"}'
```

## Docker 命令

```bash
docker build -t <image_name> .
docker run -it <image_name>:latest
docker build --platform linux/arm64 -t <image_name> .
```

也可以使用脚本构建：

```bash
./benzhi.build_docker.sh <image_name> <platform>
```