# myip Python/FastAPI 沙盒化迁移实施计划

> **For Hermes:** Use `subagent-driven-development` skill to implement this plan task-by-task. 所有实现任务必须遵循 `test-driven-development`：先写失败测试，再写最小实现，再重构。

**Goal:** 将当前 Go 单文件版 `chrimast/myip` 迁移为更适合当前主机沙盒调试的 Python/FastAPI 项目，并保持现有 IP 信息查询、风险评分、BGP 拓扑和单页前端的核心功能兼容。

**Architecture:** 第一阶段保留现有 `index.html` 的交互和 UI，重写后端为模块化 FastAPI 服务。所有开发、依赖安装、测试和运行优先在 Docker/Hermes 沙盒内完成，不直接污染主机 Python、系统包或全局环境。后端通过 provider adapter 聚合多个 IP 信息源，使用纯函数模块承载解析、合并、评分、缓存、限流和 BGP 逻辑。

**Tech Stack:** Python 3.11、FastAPI、Uvicorn、httpx、Pydantic v2、pytest、pytest-asyncio、respx、ruff、mypy 可选、Docker/Hermes Docker backend。前端初期保留原生 HTML/JS/Tailwind CDN，后期可选迁移 React/Vite。

---

## 0. 已知现状和约束

### 0.1 当前仓库结构

当前 Go 项目非常集中：

```text
myip/
  main.go       # 约 4680 行，后端 API、provider、缓存、评分、BGP 全在这里
  index.html    # 约 1486 行，单页前端
  README.md     # 仅标题
```

没有：

```text
go.mod
go.sum
Dockerfile
docker-compose.yml
.github/workflows/
*_test.go
```

### 0.2 当前 Go 版本主要 API

需要兼容的路由：

```text
GET /                  # 返回 index.html
GET /api/health        # 健康检查和配置状态
GET /api/ip            # IP/域名综合查询
GET /api/bgp           # BGP 拓扑查询
GET /vis-network.min.js # vis-network 兜底资源
```

`/api/ip` 支持的输入形式：

```text
/api/ip?=1.2.3.4
/api/ip?=example.com
/api/ip?1.2.3.4
```

`/api/bgp` 支持的输入形式：

```text
/api/bgp?asn=12345
/api/bgp?ip=1.2.3.4
/api/bgp?q=example.com
```

### 0.3 当前核心功能

- 本机 IP 检测
- IP / 域名查询
- DNS/DoH 解析和 CNAME 追踪
- IP 地理位置
- ASN / ASN owner
- ISP / org / org domain / ASN domain
- 注册局 / 注册地区
- IP 来源判断
- IP 属性判断：住宅、商业、机房、代理、VPN、TOR、移动网络等
- 风险评分
- 人机流量比估算
- BGP 拓扑图
- BGP 外部链接：bgp.tools、bgp.he.net
- 缓存、限流、gzip、安全 header、ETag
- debug 模式返回 provider errors 和字段来源信息

### 0.4 当前 provider / 外部数据源

现有 Go 版本涉及：

```text
ipapi.is
ipwho.is
ip-api.com
ipapi.org
ipinfo.io
ipdata.co
RIPEstat
RDAP
WHOIS
Cloudflare DoH
Google DoH
阿里 DoH
Quad9 DoH
DNSPod DoH 等
```

### 0.5 密钥处理要求

现有源码里出现过默认 API key/token 常量。迁移版必须改为：

- 不在代码中硬编码任何真实 key、token、password、secret。
- 提供 `.env.example`，只包含变量名和说明。
- 实际 `.env` 必须加入 `.gitignore`。
- `/api/health` 只能返回密钥是否配置，不能返回原文。
- 测试 fixture 和文档中如需示例密钥，统一使用 `[REDACTED]` 或 `dummy-test-token`。

环境变量名保持兼容：

```text
IPAPI_IS_KEY
IPAPI_ORG_KEY
IPINFO_TOKEN
IPDATA_KEY
```

### 0.6 当前主机和沙盒约束

当前主机资源足够开发此项目，但应避免污染主机：

- 约 3 核 CPU
- 约 3.8 GiB 内存
- Swap 约 3.9 GiB
- 根盘剩余约 34G
- 80 端口被 OpenResty 占用
- 建议开发端口：后端 `8000`，前端如以后使用 Vite 则 `5173`

---

## 1. 沙盒化开发方案

### 1.1 首选：Hermes Docker terminal backend

如果希望我后续直接在沙盒内创建和调试项目，推荐先启用 Hermes 的 Docker terminal backend：

```bash
hermes config set terminal.backend docker
hermes config set terminal.docker_image nikolaik/python-nodejs:python3.11-nodejs20
hermes config set terminal.container_cpu 2
hermes config set terminal.container_memory 2048
hermes config set terminal.container_disk 20480
hermes config set terminal.container_persistent true
hermes config set terminal.docker_mount_cwd_to_workspace false
```

启用后需要重启 gateway 或新开会话：

```text
/restart
```

或在 CLI 中退出后重新进入 Hermes。

验证命令：

```bash
printf 'backend=%s\n' "$TERMINAL_ENV"
uname -a
python3 --version
node --version
npm --version
pwd
```

期望：

```text
backend=docker
python >= 3.11
node >= 20
pwd 位于容器工作区，例如 /workspace
```

### 1.2 当前选择：项目级 Docker Compose 沙盒（方案 C）

用户已选择 C 方案：**不切换 Hermes 全局 Docker backend**，而是在 `myip` 迁移项目中加入项目级 Docker 文件。这样当前 Telegram/Hermes 仍保留主机视角，方便必要时管理宿主机；但 Python/FastAPI 的依赖安装、测试运行、开发服务都通过项目容器执行，避免污染主机 Python 和系统环境。

需要创建的文件：

```text
Dockerfile.dev
docker-compose.dev.yml
.dockerignore
```

推荐开发命令：

```bash
docker compose -f docker-compose.dev.yml build
docker compose -f docker-compose.dev.yml run --rm myip pytest -q
docker compose -f docker-compose.dev.yml up myip
```

运行后验证：

```bash
curl -s http://127.0.0.1:8000/api/health | python3 -m json.tool
```

此方案的安全边界：

- 代码文件仍位于主机项目目录中，由 Docker bind mount 到容器 `/app`。
- Python 包、运行时进程、pytest、uvicorn 在容器内执行。
- 不修改主机 Python site-packages。
- 不挂载主机 Hermes 配置、SSH key、系统目录。
- 不挂载 `/var/run/docker.sock`。
- 容器只能通过显式声明的端口暴露服务，开发阶段只映射 `8000:8000`。

这种方案适合需要浏览器直接访问映射端口时使用。注意：它仍会在主机 Docker 上创建镜像、容器和 Docker build cache，但不会把 Python 依赖安装进主机系统。

### 1.3 沙盒安全原则

必须遵守：

- 不挂载 `/var/run/docker.sock` 到容器。也就是说，不要把 Docker socket 暴露给开发容器，避免容器反过来控制宿主机 Docker。
- 不把 `/root/.hermes/config.yaml`、`/root/.hermes/.env`、`/root/.ssh` 挂进容器。
- 不默认传入真实 API keys。
- 开发阶段使用 mock provider 和 fixture。
- 只有需要真实联调 provider 时，才手动传入最小必要的环境变量。
- 容器内工作目录建议：

```text
/workspace/myip-py
```

### 1.4 端口策略

- FastAPI：`8000`
- 如果保留单 HTML：直接由 FastAPI 服务 `/`
- 如果后期使用 Vite：`5173`
- 不使用 `80`，避免影响 OpenResty。

启动命令：

```bash
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

验证：

```bash
curl -s http://127.0.0.1:8000/api/health | python -m json.tool
curl -s 'http://127.0.0.1:8000/api/ip?=1.1.1.1' | python -m json.tool
```

---

## 2. 目标项目结构

在新目录中实现，避免直接覆盖 Go 版本：

```text
myip-py/
  app/
    __init__.py
    main.py
    config.py
    models.py
    errors.py
    http_client.py
    cache.py
    rate_limit.py

    api/
      __init__.py
      health.py
      ip.py
      bgp.py

    core/
      __init__.py
      input_parser.py
      ip_utils.py
      dns_resolver.py
      merge.py
      scoring.py
      classification.py
      registry.py
      bgp.py

    providers/
      __init__.py
      base.py
      ipapi_is.py
      ipwho.py
      ip_api_com.py
      ipapi_org.py
      ipinfo.py
      ipdata.py
      ripestat.py
      rdap.py
      whois.py

    static/
      index.html
      vendor/
        vis-network.min.js  # 可选，本地兜底

  tests/
    conftest.py
    test_health.py
    test_input_parser.py
    test_ip_utils.py
    test_dns_resolver.py
    test_merge.py
    test_scoring.py
    test_classification.py
    test_rate_limit.py
    test_cache.py
    test_api_ip.py
    test_api_bgp.py
    test_providers/
      test_ipapi_is.py
      test_ipwho.py
      test_ip_api_com.py
      test_ipinfo.py
      test_ipdata.py
    fixtures/
      ipapi_is_1_1_1_1.json
      ipwho_1_1_1_1.json
      ip_api_com_1_1_1_1.json
      ripestat_as13335_overview.json
      ripestat_as13335_neighbours.json

  docs/
    migration-notes.md
    api-compat.md

  .env.example
  .gitignore
  pyproject.toml
  README.md
```

---

## 3. API 兼容模型

### 3.1 `APIResp`

Python/Pydantic 模型：

```python
class APIResp(BaseModel):
    ok: bool
    data: IPInfo = Field(default_factory=IPInfo)
    errors: list[str] | None = None
```

### 3.2 `IPInfo`

必须保持 JSON 字段名兼容：

```python
class IPInfo(BaseModel):
    ip: str = ""
    country: str = ""
    country_code: str = ""
    city: str = ""
    isp: str = ""
    asn: str = ""
    asn_owner: str = ""
    org: str = ""
    asn_domain: str = ""
    org_domain: str = ""
    registry: str = ""
    reg_region: str = ""
    ip_type: str = ""

    ip_source: str = ""
    ip_source_reason: str | None = None
    ip_property: str = ""
    ip_property_reason: str | None = None
    ip_property_scores: dict[str, int] | None = None

    risk_score: int = 0
    risk_reason: str | None = None
    risk_breakdown: dict[str, int] | None = None
    human_percent: float = 0
    bot_percent: float = 0
    humanbot_reason: str | None = None
    humanbot_breakdown: dict[str, int] | None = None
    risk_confidence: int | None = None
    humanbot_confidence: int | None = None

    lat: float = 0
    lon: float = 0
```

内部 provider 信号不要暴露给 JSON，可用单独 internal dataclass：

```python
@dataclass
class InternalSignals:
    hosting: Signal | None = None
    proxy: Signal | None = None
    mobile: Signal | None = None
    vpn: Signal | None = None
    tor: Signal | None = None
    threat: Signal | None = None
    known_attacker: Signal | None = None
    known_abuser: Signal | None = None
    company_type: str = ""
    asn_type: str = ""
```

### 3.3 `BGPTopology`

```python
class ASNNode(BaseModel):
    asn: int
    name: str | None = None
    country_code: str | None = None
    is_tier1: bool | None = None

class BGPTopology(BaseModel):
    asn: int
    name: str | None = None
    external_links: dict[str, str] | None = None
    prefix: str | None = None
    upstreams: list[ASNNode] = Field(default_factory=list)
```

---

## 4. Provider 优先级和合并规则

### 4.1 Provider 名称

保持稳定 key：

```python
PROVIDER_REGISTRY = "registry"
PROVIDER_IPAPI_IS = "ipapi.is"
PROVIDER_IPWHO = "ipwho.is"
PROVIDER_IP_API_COM = "ip-api.com"
PROVIDER_IPAPI_ORG = "ip-api.org"
PROVIDER_IPINFO = "ipinfo.io"
PROVIDER_IPDATA = "ipdata.co"
```

### 4.2 字段优先级

迁移 Go 版本当前逻辑：

```python
PROVIDER_PRIORITY_ORDER = {
    "geo": ["ipapi.is", "ipwho.is", "ip-api.com", "ip-api.org", "ipinfo.io", "ipdata.co"],
    "asn": ["ipapi.is", "ipinfo.io", "ipdata.co", "ipwho.is", "ip-api.com", "ip-api.org"],
    "org": ["ipapi.is", "ipinfo.io", "ipdata.co", "ipwho.is", "ip-api.com", "ip-api.org"],
    "isp": ["ipapi.is", "ipwho.is", "ipinfo.io", "ipdata.co", "ip-api.com", "ip-api.org"],
    "asn_domain": ["ipapi.is", "ipinfo.io", "ipdata.co"],
    "org_domain": ["ipapi.is", "ipwho.is"],
    "registry": ["registry", "ipapi.is"],
}
```

### 4.3 非空判断

以下值视为空：

```text
""
"-"
"n/a"
"unknown"
```

`registry = "Global Registry"` 视为 placeholder，不覆盖真实 registry。

### 4.4 合并测试必须先写

`tests/test_merge.py` 至少覆盖：

- 高优先级 provider 覆盖低优先级 provider。
- 低优先级 provider 不能覆盖已有高优先级字段。
- 空值不能覆盖非空值。
- `Global Registry` 不能覆盖真实 registry。
- `country_code` 和 `reg_region` 输出大写。
- ASN 统一规范为 `AS12345`。

---

## 5. 分阶段实施任务

## Phase A：沙盒和项目骨架

### Task A1: 创建沙盒内项目目录

**Objective:** 在沙盒工作区创建新项目，不修改原 Go 代码。

**Files:**

- Create directory: `/workspace/myip-py` 或当前沙盒等效目录

**Steps:**

```bash
mkdir -p /workspace/myip-py
cd /workspace/myip-py
git init
```

如果当前仍是主机 local backend，则先不要实施，直到确认是否启用 Docker backend。

**Verification:**

```bash
pwd
git status --short --branch
```

期望：路径位于 `/workspace` 或明确的容器目录中。

---

### Task A2: 创建 Python 项目元数据

**Objective:** 创建 `pyproject.toml`、`.gitignore`、`.env.example`。

**Files:**

- Create: `pyproject.toml`
- Create: `.gitignore`
- Create: `.env.example`

**Test first:** 配置文件本身可以不 TDD，但要有验证命令。

**`pyproject.toml` 初始内容:**

```toml
[project]
name = "myip-py"
version = "0.1.0"
description = "IP information query tool rewritten with FastAPI"
requires-python = ">=3.11"
dependencies = [
  "fastapi>=0.110",
  "uvicorn[standard]>=0.27",
  "httpx>=0.27",
  "pydantic>=2.6",
  "pydantic-settings>=2.2",
  "python-dotenv>=1.0",
]

[project.optional-dependencies]
dev = [
  "pytest>=8.0",
  "pytest-asyncio>=0.23",
  "respx>=0.21",
  "ruff>=0.4",
]

[tool.pytest.ini_options]
asyncio_mode = "auto"
testpaths = ["tests"]

[tool.ruff]
line-length = 100
```

**`.gitignore`:**

```gitignore
.env
.venv/
__pycache__/
.pytest_cache/
.ruff_cache/
.mypy_cache/
htmlcov/
.coverage
*.pyc
```

**`.env.example`:**

```dotenv
# Optional provider keys. Never commit real secrets.
IPAPI_IS_KEY=
IPAPI_ORG_KEY=
IPINFO_TOKEN=
IPDATA_KEY=

MYIP_DEBUG=false
MYIP_CACHE_TTL_SECONDS=120
MYIP_RATE_LIMIT_PER_MINUTE=60
```

**Verification:**

```bash
python -m venv .venv
. .venv/bin/activate
pip install -e '.[dev]'
python -c 'import fastapi, httpx, pydantic; print("ok")'
```

---

### Task A3: 创建 FastAPI 最小应用和 health endpoint

**Objective:** 让服务可启动，`/api/health` 返回兼容结构。

**Files:**

- Create: `app/__init__.py`
- Create: `app/main.py`
- Create: `app/config.py`
- Create: `app/api/__init__.py`
- Create: `app/api/health.py`
- Test: `tests/test_health.py`

**Step 1: Write failing test**

```python
from fastapi.testclient import TestClient
from app.main import app


def test_health_returns_ok_and_config_without_secret_values():
    client = TestClient(app)
    resp = client.get("/api/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["ok"] is True
    assert "time" in data
    assert "keys" in data
    assert "config" in data
    body = resp.text
    assert "IPAPI_IS_KEY" not in body
    assert "IPINFO_TOKEN" not in body
```

**Step 2: Run RED**

```bash
pytest tests/test_health.py::test_health_returns_ok_and_config_without_secret_values -v
```

Expected: FAIL because `app.main` does not exist.

**Step 3: Minimal implementation**

`app/main.py`:

```python
from fastapi import FastAPI
from app.api.health import router as health_router

app = FastAPI(title="myip-py")
app.include_router(health_router, prefix="/api")
```

`app/api/health.py`:

```python
from datetime import datetime, timezone
from fastapi import APIRouter
from app.config import settings

router = APIRouter()


def key_status(value: str | None) -> dict[str, object]:
    return {"configured": bool(value), "source": "env" if value else "missing"}


@router.get("/health")
def health() -> dict[str, object]:
    return {
        "ok": True,
        "time": datetime.now(timezone.utc).isoformat(),
        "keys": {
            "ipapi_is_key": key_status(settings.ipapi_is_key),
            "ipapi_org_key": key_status(settings.ipapi_org_key),
            "ipinfo_token": key_status(settings.ipinfo_token),
            "ipdata_key": key_status(settings.ipdata_key),
        },
        "config": {
            "cache_ttl_sec": settings.cache_ttl_seconds,
            "rate_limit_per_min": settings.rate_limit_per_minute,
        },
    }
```

`app/config.py`:

```python
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    ipapi_is_key: str = ""
    ipapi_org_key: str = ""
    ipinfo_token: str = ""
    ipdata_key: str = ""
    myip_debug: bool = False
    cache_ttl_seconds: int = 120
    rate_limit_per_minute: int = 60


settings = Settings()
```

**Step 4: Run GREEN**

```bash
pytest tests/test_health.py -v
```

**Step 5: Run service**

```bash
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

**Verification:**

```bash
curl -s http://127.0.0.1:8000/api/health | python -m json.tool
```

---

## Phase B：模型、输入解析和 IP 工具函数

### Task B1: 定义 Pydantic API 模型

**Objective:** 创建和 Go JSON schema 兼容的基础模型。

**Files:**

- Create: `app/models.py`
- Test: `tests/test_models.py`

**Tests:**

- `IPInfo().model_dump()` 包含 `ip`、`country_code`、`risk_score` 等字段。
- `APIResp(ok=True, data=IPInfo(ip="1.1.1.1"))` JSON 字段名兼容。
- `BGPTopology` 输出 `upstreams` list。

**Run:**

```bash
pytest tests/test_models.py -v
```

---

### Task B2: 输入解析函数

**Objective:** 兼容 `/api/ip?=...` 和 raw query 输入。

**Files:**

- Create: `app/core/input_parser.py`
- Test: `tests/test_input_parser.py`

**Test cases:**

```python
@pytest.mark.parametrize("raw_query,query_params,expected", [
    ("=1.1.1.1", {"": "1.1.1.1"}, "1.1.1.1"),
    ("example.com", {}, "example.com"),
    ("", {}, ""),
])
def test_extract_ip_query_input(raw_query, query_params, expected):
    ...
```

也要支持 `/api/bgp` 的 `asn`、`ip`、`q` 解析。

---

### Task B3: IP 规范化和公网判断

**Objective:** 迁移 `canonicalIPKey`、`isPublicIP`、`isLoopbackOrPrivate`、`normalizeASN`。

**Files:**

- Create: `app/core/ip_utils.py`
- Test: `tests/test_ip_utils.py`

**Required tests:**

- `canonical_ip_key(" 1.1.1.1 ") == "1.1.1.1"`
- IPv6 规范化。
- 无效 IP 返回原字符串 trim 后结果。
- 私有地址：`10.0.0.1`、`172.16.0.1`、`192.168.1.1`、`127.0.0.1` 不是 public。
- 公网地址：`1.1.1.1`、`8.8.8.8` 是 public。
- `normalize_asn("15169") == "AS15169"`
- `normalize_asn("AS15169") == "AS15169"`

---

## Phase C：缓存、限流、HTTP 客户端

### Task C1: TTL cache

**Objective:** 实现内存 TTL cache，用于 IP 查询、DNS、BGP。

**Files:**

- Create: `app/cache.py`
- Test: `tests/test_cache.py`

**Required tests:**

- set/get 未过期命中。
- 过期后 miss。
- key 不存在 miss。
- delete/clear 可选。

---

### Task C2: Rate limiter

**Objective:** 实现每客户端每分钟限流。

**Files:**

- Create: `app/rate_limit.py`
- Test: `tests/test_rate_limit.py`

**Required tests:**

- 同一 key 在 limit 内允许。
- 超过 limit 拒绝。
- 窗口过期后恢复。

---

### Task C3: HTTP client wrapper

**Objective:** 统一 httpx timeout、User-Agent、JSON 获取、错误规范。

**Files:**

- Create: `app/http_client.py`
- Test: `tests/test_http_client.py`

**Required tests using respx:**

- 200 JSON 返回 dict。
- 非 200 抛出 ProviderError。
- timeout 转换成 ProviderError。
- JSON decode error 转换成 ProviderError。

---

## Phase D：DNS/DoH 和目标解析

### Task D1: DoH provider adapter

**Objective:** 实现 DoH 查询 A/AAAA 记录。

**Files:**

- Create: `app/core/dns_resolver.py`
- Test: `tests/test_dns_resolver.py`

**Providers:**

```text
cloudflare: https://cloudflare-dns.com/dns-query?name={name}&type={type}
google: https://dns.google/resolve?name={name}&type={type}
```

初期只做 Cloudflare + Google，其他 DoH 作为后续增强。

**Required tests:**

- A 记录解析成功。
- 无记录返回错误。
- CNAME 追踪最多 6 层。
- DNS cache 命中不重复请求。

---

### Task D2: resolve target IP

**Objective:** 输入为空时取客户端 IP；输入 IP 时直接返回；输入域名时 DoH 解析。

**Files:**

- Create/Modify: `app/core/input_parser.py`
- Create/Modify: `app/core/dns_resolver.py`
- Test: `tests/test_resolve_target.py`

**Required tests:**

- 输入 `1.1.1.1` 返回自身。
- 输入 `https://example.com/path` 提取 host 并解析。
- 输入 `example.com` 调 DoH。
- 私有域名解析到私有 IP 时后续不调用 provider。
- 无效输入返回 400 兼容错误。

---

## Phase E：Provider adapter 迁移

### Task E1: Provider base protocol

**Objective:** 定义 provider 返回 patch 的统一接口。

**Files:**

- Create: `app/providers/base.py`
- Test: `tests/test_provider_base.py`

**Design:**

```python
class ProviderResult(BaseModel):
    provider: str
    info: IPInfo
    signals: InternalSignals = Field(default_factory=InternalSignals)

class Provider(Protocol):
    name: str
    async def fetch(self, ip: str) -> ProviderResult: ...
```

---

### Task E2: ipapi.is adapter

**Objective:** 迁移主 provider `ipapi.is`。

**Files:**

- Create: `app/providers/ipapi_is.py`
- Test: `tests/test_providers/test_ipapi_is.py`
- Fixture: `tests/fixtures/ipapi_is_1_1_1_1.json`

**Required parsed fields:**

- country / country_code / city
- lat / lon
- asn / asn_owner / asn_domain
- org / org_domain
- isp
- registry / reg_region
- company_type / asn_type
- hosting / proxy / vpn / tor / mobile 信号

**Testing rule:** fixture 测试不请求真实网络。

---

### Task E3: ipwho.is adapter

**Objective:** 迁移 `ipwho.is` fallback。

**Files:**

- Create: `app/providers/ipwho.py`
- Test: `tests/test_providers/test_ipwho.py`
- Fixture: `tests/fixtures/ipwho_1_1_1_1.json`

**Fields:**

- geo
- connection.asn
- connection.isp
- connection.org
- connection.domain
- security proxy/vpn/tor/hosting flags

---

### Task E4: ip-api.com adapter

**Objective:** 迁移免 key fallback provider。

**Files:**

- Create: `app/providers/ip_api_com.py`
- Test: `tests/test_providers/test_ip_api_com.py`

**Fields:**

- country/countryCode/city
- lat/lon
- isp/org
- as 字段解析为 ASN 和 owner
- proxy/hosting/mobile

---

### Task E5: optional keyed providers

**Objective:** 迁移 `ipapi.org`、`ipinfo.io`、`ipdata.co`，但无 key 时跳过。

**Files:**

- Create: `app/providers/ipapi_org.py`
- Create: `app/providers/ipinfo.py`
- Create: `app/providers/ipdata.py`
- Tests under: `tests/test_providers/`

**Required behavior:**

- 未配置 key 时返回 skip，不报 500。
- 配置 key 时 URL 包含 key，但日志、错误、health 不泄露 key。
- fixture 解析 domain 和 threat signals。

---

## Phase F：合并 pipeline 和 `/api/ip`

### Task F1: merge engine

**Objective:** 实现 provider priority merge。

**Files:**

- Create: `app/core/merge.py`
- Test: `tests/test_merge.py`

**Required tests:** 见第 4 节。

---

### Task F2: IP enrichment pipeline

**Objective:** 实现单次查询 pipeline，按条件调用 providers 并合并。

**Files:**

- Create: `app/core/enrichment.py`
- Test: `tests/test_enrichment.py`

**Initial provider order:**

```text
ipapi.is -> registry -> ipwho.is -> ip-api.com -> ipapi.org -> ipinfo.io -> ipdata.co
```

**Behavior:**

- 每个 provider 单独 timeout。
- provider 失败时收集 error，不中断整体。
- 非 debug 模式不返回 errors。
- debug 模式返回 errors。
- 私有 IP 快速返回，不请求外部 provider。

---

### Task F3: `/api/ip` endpoint

**Objective:** 让前端能查询核心 IP 信息。

**Files:**

- Create: `app/api/ip.py`
- Modify: `app/main.py`
- Test: `tests/test_api_ip.py`

**Required tests:**

- `GET /api/ip?=1.1.1.1` 返回 `ok=true`。
- provider mock 返回的字段出现在 `data`。
- 私有 IP 返回 `ok=true`，但 provider 未调用。
- 无效输入返回 400。
- 超过限流返回 429。
- cache 命中不重复调用 provider。

---

## Phase G：分类、评分、人机比例

### Task G1: IP source classification

**Objective:** 迁移 `calcIPSourceDetailed`。

**Files:**

- Create: `app/core/classification.py`
- Test: `tests/test_classification.py`

**Required tests:**

- 移动网络识别为移动/家宽倾向。
- 已知云厂商/IDC 识别为机房或商业。
- 缺少信息时返回 `未知` 或兼容 placeholder。

---

### Task G2: IP property classification

**Objective:** 迁移 `calcIPPropertyDetailed`。

**Files:**

- Modify: `app/core/classification.py`
- Test: `tests/test_classification.py`

**Required tests:**

- proxy/vpn/tor 信号优先体现。
- hosting 信号增加机房分。
- mobile 信号增加移动/住宅分。
- 多信号时返回最高分属性和 breakdown。

---

### Task G3: Human/Bot ratio

**Objective:** 迁移 `computeHumanBotDetailed` 和 confidence。

**Files:**

- Create: `app/core/scoring.py`
- Test: `tests/test_scoring.py`

**Required tests:**

- 住宅/移动网络 human 更高。
- 代理/VPN/TOR/bot-like IDC bot 更高。
- 输出 human + bot = 100 或非常接近 100。
- confidence 在 0-100。

---

### Task G4: Risk score

**Objective:** 迁移 `computeRiskScoreDetailed` 和 confidence。

**Files:**

- Modify: `app/core/scoring.py`
- Test: `tests/test_scoring.py`

**Required tests:**

- TOR 高风险。
- Known attacker/abuser 高风险。
- 住宅低风险。
- 云厂商/IDC 中高风险。
- 分数 clamp 到 0-100。
- reason 字符串包含主要信号。

---

### Task G5: Pipeline 注入派生字段

**Objective:** `/api/ip` 返回完整 UI 所需派生字段。

**Files:**

- Modify: `app/core/enrichment.py`
- Test: `tests/test_enrichment.py`
- Test: `tests/test_api_ip.py`

**Required fields:**

```text
ip_source
ip_source_reason
ip_property
ip_property_reason
ip_property_scores
risk_score
risk_reason
risk_breakdown
human_percent
bot_percent
humanbot_reason
humanbot_breakdown
risk_confidence
humanbot_confidence
```

---

## Phase H：Registry、RDAP、WHOIS

### Task H1: RDAP registry lookup

**Objective:** 查询 RIR 和注册地区。

**Files:**

- Create: `app/providers/rdap.py`
- Create: `app/core/registry.py`
- Test: `tests/test_registry.py`

**RDAP endpoints:**

```text
https://rdap.arin.net/registry/ip/{ip}
https://rdap.db.ripe.net/ip/{ip}
https://rdap.apnic.net/ip/{ip}
https://rdap.lacnic.net/rdap/ip/{ip}
https://rdap.afrinic.net/rdap/ip/{ip}
https://rdap.org/ip/{ip}
```

**Required tests:**

- 从 RDAP response 提取 country。
- 从 notices/links 判断 RIR。
- 失败时 fallback 到 placeholder。

---

### Task H2: WHOIS fallback

**Objective:** RDAP 不足时使用 WHOIS 提取 country/referral。

**Files:**

- Create: `app/providers/whois.py`
- Test: `tests/test_whois.py`

**Note:** WHOIS 网络测试必须 mock socket，不做真实 WHOIS。

---

## Phase I：BGP 拓扑

### Task I1: RIPEstat AS overview

**Objective:** 查询 ASN 名称。

**Files:**

- Create: `app/providers/ripestat.py`
- Test: `tests/test_providers/test_ripestat.py`

**Endpoint:**

```text
https://stat.ripe.net/data/as-overview/data.json?resource=AS{asn}
```

---

### Task I2: RIPEstat neighbours

**Objective:** 查询 upstream ASN 列表。

**Files:**

- Modify: `app/providers/ripestat.py`
- Test: `tests/test_providers/test_ripestat.py`

**Endpoint:**

```text
https://stat.ripe.net/data/asn-neighbours/data.json?resource=AS{asn}
```

**Required behavior:**

- 过滤无效 ASN。
- limit 默认 80，范围 1..300。
- 标记 Tier-1 ASN。
- 返回稳定排序。

---

### Task I3: BGP cache with stale refresh

**Objective:** 实现 fresh/stale 缓存。

**Files:**

- Create: `app/core/bgp.py`
- Test: `tests/test_bgp_cache.py`

**Required behavior:**

- fresh 命中直接返回。
- stale 命中返回旧数据，并允许后台刷新。
- miss 同步拉取一次。
- 拉取失败返回 minimal topology 或错误，保持前端结构稳定。

---

### Task I4: `/api/bgp` endpoint

**Objective:** 兼容前端 BGP 拓扑请求。

**Files:**

- Create: `app/api/bgp.py`
- Modify: `app/main.py`
- Test: `tests/test_api_bgp.py`

**Required tests:**

- `?asn=AS13335` 成功。
- `?asn=13335` 成功。
- `?ip=1.1.1.1` 先解析 ASN 再查拓扑。
- invalid ASN 返回 400。
- limit clamp 到 1..300。
- 返回 `external_links`。

---

## Phase J：静态页面兼容

### Task J1: 复制现有 index.html

**Objective:** 保留 UI，先只替换服务方式。

**Files:**

- Copy: original `index.html` to `app/static/index.html`
- Modify: `app/main.py`
- Test: `tests/test_static.py`

**Required test:**

```python
def test_root_serves_index_html():
    resp = client.get("/")
    assert resp.status_code == 200
    assert "IPI.LI" in resp.text
```

---

### Task J2: vis-network 本地兜底

**Objective:** 保持 `/vis-network.min.js` 路由兼容。

**Files:**

- Modify: `app/main.py`
- Optional: `app/static/vendor/vis-network.min.js`
- Test: `tests/test_static.py`

**Behavior:**

- 如果本地 vendor 文件存在，返回它。
- 如果不存在，返回 404 或轻量 fallback，并确保前端仍可使用 CDN。

---

## Phase K：中间件和部署便利性

### Task K1: CORS, gzip, security headers

**Objective:** 迁移 Go 版本中间件。

**Files:**

- Create: `app/middleware.py`
- Modify: `app/main.py`
- Test: `tests/test_middleware.py`

**Required headers:**

- `Access-Control-Allow-Origin: *` for `/api/*`
- gzip 由 FastAPI/GZipMiddleware 处理
- 基础安全 header：
  - `X-Content-Type-Options: nosniff`
  - `Referrer-Policy`
  - 可选 CSP，注意不要破坏 Tailwind CDN / html2canvas / vis-network CDN

---

### Task K2: ETag for BGP JSON

**Objective:** `/api/bgp` 支持 ETag，减少重复传输。

**Files:**

- Create: `app/core/etag.py`
- Modify: `app/api/bgp.py`
- Test: `tests/test_etag.py`

**Required tests:**

- 第一次返回 ETag。
- 携带 `If-None-Match` 命中返回 304。

---

### Task K3: Dockerfile.dev、docker-compose.dev.yml 和 .dockerignore

**Objective:** 按用户选择的 C 方案提供项目级 Docker Compose 沙盒；不切换 Hermes 全局 backend，但所有 Python 依赖安装、pytest、uvicorn 都在容器内执行。

**Files:**

- Create: `Dockerfile.dev`
- Create: `docker-compose.dev.yml`
- Create: `.dockerignore`
- Test/Verify manually

**Dockerfile.dev:**

```dockerfile
FROM python:3.11-slim

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

COPY pyproject.toml ./
RUN pip install --upgrade pip \
    && pip install -e '.[dev]'

COPY . .

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]
```

**docker-compose.dev.yml:**

```yaml
services:
  myip:
    build:
      context: .
      dockerfile: Dockerfile.dev
    ports:
      - "8000:8000"
    volumes:
      - .:/app
    env_file:
      - .env
    environment:
      PYTHONDONTWRITEBYTECODE: "1"
      PYTHONUNBUFFERED: "1"
```

**.dockerignore:**

```gitignore
.git
.venv
__pycache__
.pytest_cache
.ruff_cache
.mypy_cache
.env
*.pyc
htmlcov
.coverage
```

**Commands:**

```bash
docker compose -f docker-compose.dev.yml build
docker compose -f docker-compose.dev.yml run --rm myip pytest -q
docker compose -f docker-compose.dev.yml up myip
```

**Verification:**

```bash
curl -s http://127.0.0.1:8000/api/health | python3 -m json.tool
```

**Security note:** 不挂载 Docker socket，不挂载主机敏感目录，不把真实 `.env` 打进镜像；`.env` 只在运行时通过 `env_file` 注入，并且 `.dockerignore` 排除 `.env`。

---

## Phase L：验收和切换

### Task L1: Golden sample comparison

**Objective:** 对固定 IP 比较 Go 版和 Python 版核心字段。

**Files:**

- Create: `scripts/compare_go_python.py`
- Create: `docs/api-compat.md`

**Sample IPs:**

```text
1.1.1.1      # Cloudflare
8.8.8.8      # Google
223.5.5.5    # Alibaba DNS
114.114.114.114
```

**Comparison fields:**

```text
ip
country_code
asn
asn_owner
org
isp
registry
reg_region
ip_source
ip_property
risk_score range
human_percent/bot_percent range
```

不要要求完全一致，provider 结果会波动；只要求结构兼容和分类合理。

---

### Task L2: Performance sanity check

**Objective:** 验证当前主机/沙盒资源足够。

**Commands:**

```bash
pytest -q
uvicorn app.main:app --host 0.0.0.0 --port 8000
curl -s http://127.0.0.1:8000/api/health
for ip in 1.1.1.1 8.8.8.8 223.5.5.5; do
  time curl -s "http://127.0.0.1:8000/api/ip?=$ip" >/dev/null
done
```

**Accept criteria:**

- pytest 全部通过。
- health 立即返回。
- 无 provider key 时仍可返回基础信息或优雅降级。
- 单次查询在外部 API 正常情况下目标小于 5-10 秒。
- BGP 查询可以慢一些，但不能阻塞 `/api/ip`。

---

### Task L3: README 更新

**Objective:** 写清楚沙盒运行、环境变量、开发命令。

**Files:**

- Create/Modify: `README.md`

**Required sections:**

- 项目简介
- 功能列表
- 沙盒开发方式
- 本地 Docker Compose 方式
- 环境变量说明
- 测试命令
- 启动命令
- API 示例
- 安全说明：不提交 `.env`，不硬编码 key

---

## 6. 实施顺序建议

建议按以下顺序执行：

```text
A1-A3  项目骨架和 health
B1-B3  模型、输入解析、IP 工具
C1-C3  cache/rate/http 基础设施
D1-D2  DNS 和目标解析
E1-E4  免费 provider 基础迁移
F1-F3  merge pipeline 和 /api/ip
G1-G5  分类、评分、人机比例
J1-J2  静态页面接入
H1-H2  RDAP/WHOIS
I1-I4  BGP
K1-K3  中间件、ETag、Docker compose
L1-L3  对比、性能、README
```

优先让页面核心查询跑起来，再迁移 BGP。不要一开始就追求 100% 完整。

---

## 7. Definition of Done

### MVP 完成标准

- [ ] 项目在 Docker/Hermes 沙盒中开发和测试。
- [ ] `pytest -q` 通过。
- [ ] `uvicorn app.main:app --host 0.0.0.0 --port 8000` 可启动。
- [ ] `/api/health` 可用且不泄露 secrets。
- [ ] `/api/ip?=1.1.1.1` 返回兼容 JSON。
- [ ] 私有 IP 不触发外部 provider。
- [ ] 至少支持 `ipapi.is`、`ipwho.is`、`ip-api.com`。
- [ ] 有基础 cache 和 rate limit。
- [ ] 有风险评分、人机比例、IP 来源/属性字段。
- [ ] `/` 能打开原页面。

### 完整兼容完成标准

- [ ] 所有 provider adapter 有 fixture 测试。
- [ ] RDAP/WHOIS registry fallback 可用。
- [ ] `/api/bgp` 可用，支持 ASN/IP/域名输入。
- [ ] BGP topology 支持缓存和 stale refresh。
- [ ] ETag/gzip/security headers 可用。
- [ ] 与 Go 版本 golden sample 对比通过。
- [ ] README 完整。
- [ ] 无硬编码真实 secret。

---

## 8. 后续可选优化

### 8.1 React/Vite 前端重构

等 Python API 稳定后再做。建议目录：

```text
frontend/
  src/
  package.json
  vite.config.ts
```

当前主机可以跑，但需要 Node/npm。若 Hermes Docker backend 使用 `nikolaik/python-nodejs:python3.11-nodejs20`，容器内已经适合做这一步。

### 8.2 SQLite 查询日志

可选记录：

- 查询目标
- 查询耗时
- provider 成功/失败
- 风险评分
- cache hit/miss

默认不开启，避免隐私风险。

### 8.3 管理后台

可选功能，不属于迁移 MVP。

---

## 9. 风险和规避

### 风险 1：外部 API 波动

规避：

- provider 单独 timeout
- mock/fixture 测试
- debug 模式暴露错误摘要
- 非 debug 模式优雅降级

### 风险 2：评分逻辑迁移偏差

规避：

- 先写 Go 行为对应的单元测试
- 评分模块纯函数化
- 使用 golden sample 做范围对比，而不是绝对值硬匹配

### 风险 3：BGP 查询慢

规避：

- `/api/ip` 不依赖 BGP 完整拓扑
- BGP 独立 endpoint
- fresh/stale cache
- limit 默认 80，最大 300

### 风险 4：沙盒误访问主机敏感信息

规避：

- 不挂载主机敏感目录
- 不挂载 Docker socket
- 不默认传 secrets
- 开发目录放 `/workspace/myip-py`

### 风险 5：一次性重写范围过大

规避：

- 严格分 phase
- 每个任务 TDD
- 每个任务完成后提交
- 先 MVP，后完整兼容

---

## 10. 下一步执行建议

下一步不要直接改 Go 版本。建议先做：

1. 确认是否启用 Hermes Docker backend。
2. 在沙盒内创建 `/workspace/myip-py`。
3. 执行 Phase A：项目骨架 + `/api/health`。
4. 每个任务完成后运行测试并提交。

如果由 Hermes 执行实现，应每次只执行 1-3 个小任务，避免大范围无测试改动。
