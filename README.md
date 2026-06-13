# myip

IP 信息查询工具，基于 FastAPI 重写。支持多数据源聚合、自定义 Provider、BGP 拓扑可视化、后台管理面板。

## 功能

- **IP / 域名查询** — 输入 IP 或域名，返回地理位置、ASN、ISP 等信息
- **多数据源容灾** — 内置 ipapi.is / ipwho.is / ip-api.com / ipinfo.io 等 6 个 Provider，自动 fallback
- **自定义 Provider** — 后台添加任意 JSON API 数据源，自动扫描字段、绑定映射
- **BGP 拓扑** — 查询 ASN 上游拓扑，支持 vis-network 可视化
- **后台管理** — 完整的 Web 管理面板（`/admin`），配置 Provider、字段映射、缓存、限流等
- **Go 兼容** — API 响应格式兼容原 Go 版本

## 项目结构

```
app/
├── main.py                 # FastAPI 入口
├── api/
│   ├── ip.py               # GET /api/ip — IP 查询
│   ├── bgp.py              # GET /api/bgp — BGP 拓扑
│   ├── admin.py            # /api/admin/* — 后台管理 API
│   └── health.py           # GET /health
├── core/
│   └── config.py           # Settings / 环境变量
└── services/
    ├── ip_lookup.py        # 多 Provider 聚合查询
    ├── configured_ip_lookup.py  # 带配置的查询
    ├── custom_provider_preview.py  # 自定义 Provider 预览
    ├── bgp.py              # BGP 拓扑获取
    ├── target_ip.py        # DNS / DoH 解析
    ├── registry_lookup.py  # IP 注册归属查询
    ├── admin_config.py     # 管理配置持久化
    ├── admin_auth.py       # 管理员认证
    ├── rate_limit.py       # 限流
    ├── ttl_cache.py        # TTL 缓存
    ├── http_delivery.py    # GZip 中间件
    ├── local_ip.py         # 本地 IP 处理
    └── vis_network.py      # BGP 可视化数据

tests/                      # 176 个测试用例
static/
├── index.html              # 前端查询页面
└── admin.html              # 后台管理面板
```

## 部署

### Docker Run

```bash
# 构建镜像
docker build -t myip .

# 运行
docker run -d \
  --name myip \
  -p 8000:8000 \
  -e MYIP_CACHE_TTL_SECONDS=120 \
  myip
```

访问 `http://localhost:8000`（查询页面）或 `http://localhost:8000/admin`（管理面板）。

### Docker Compose

创建 `docker-compose.yml`：

```yaml
services:
  myip:
    build: .
    ports:
      - "8000:8000"
    environment:
      - MYIP_CACHE_TTL_SECONDS=120
      - MYIP_RATE_LIMIT_PER_MINUTE=60
    restart: unless-stopped
```

```bash
# 启动
docker compose up -d

# 查看日志
docker compose logs -f

# 停止
docker compose down
```

### 从 GHCR 拉取（CI 自动构建）

```bash
docker pull ghcr.io/chrimast/myip:latest
docker run -d -p 8000:8000 ghcr.io/chrimast/myip:latest
```

## 开发

```bash
# 安装依赖
pip install -e '.[dev]'

# 运行测试
python -m pytest tests/ -q

# 启动开发服务器（热重载）
uvicorn app.main:app --reload --port 8000
```

### Docker Compose 开发模式

```bash
docker compose -f docker-compose.dev.yml up --build
```

挂载本地代码，修改即生效。

## 环境变量

| 变量 | 默认值 | 说明 |
|---|---|---|
| `MYIP_DEBUG` | `false` | 调试模式 |
| `MYIP_CACHE_TTL_SECONDS` | `120` | IP 查询缓存 TTL |
| `MYIP_RATE_LIMIT_PER_MINUTE` | `60` | 每客户端每分钟请求限制 |
| `MYIP_PROVIDER_TIMEOUT_SECONDS` | `8.0` | Provider HTTP 超时 |
| `MYIP_DOH_TIMEOUT_SECONDS` | `5.0` | DoH HTTP 超时 |
| `MYIP_DOH_PROVIDERS` | `cloudflare,google,quad9` | DoH 提供商 |

## API

### IP 查询

```bash
GET /api/ip              # 查询请求者 IP
GET /api/ip?=8.8.8.8     # 查询指定 IP
GET /api/ip?example.com  # 查询域名
```

### BGP 拓扑

```bash
GET /api/bgp?AS15169           # 查询 ASN 上游
GET /api/bgp?AS15169&limit=5   # 限制上游数量
```

### 后台管理

```bash
GET  /admin                          # 管理面板页面
GET  /api/admin/providers            # Provider 列表
PUT  /api/admin/runtime-settings     # 更新运行时设置
POST /api/admin/custom-providers     # 添加自定义 Provider
POST /api/admin/custom-providers/preview  # 预览自定义 Provider
```

## License

MIT
