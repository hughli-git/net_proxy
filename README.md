# HTTP/HTTPS Forward Proxy

一个基于 Python `asyncio` 的轻量 HTTP/HTTPS 正向代理。支持实时流量日志、YAML 配置、域名与 IP 访问策略，以及 HTTP/HTTPS CONNECT 请求拦截。

## 功能

- 转发普通 HTTP 请求
- 通过 CONNECT 隧道转发 HTTPS 流量
- 实时显示源 IP、方向、目标域名、目标 IP 和数据块大小
- 按 `out` 或 `in` 过滤终端日志
- 将过滤前的完整日志写入 `logs/`
- 支持精确、后缀、通配符、正则和 IP/CIDR 规则
- 支持 `allow`、`deny` 和 `audit` 三种策略动作
- 对被拒绝的 HTTP 和 CONNECT 请求返回 `403 Forbidden`

HTTPS 使用透明 CONNECT 隧道，不进行 TLS 中间人解密。因此代理可以看到 CONNECT 目标域名、目标 IP 和加密数据块大小，但看不到 HTTPS 内部的 URL 路径、请求头、响应状态码或正文。

## 环境要求

- Python 3.10 或更高版本，推荐 Python 3.11
- Linux、macOS 或其他支持 `asyncio` 的环境
- PyYAML 6.0.3

## 环境安装

在项目目录创建虚拟环境：

```bash
python3 -m venv .venv
```

安装依赖：

```bash
.venv/bin/python -m pip install -r requirements.txt
```

确认环境正常：

```bash
.venv/bin/python --version
.venv/bin/python -m pip check
```

如果系统无法创建虚拟环境，Debian/Ubuntu 通常需要先安装：

```bash
sudo apt-get install python3-venv
```

## 文件说明

```text
.
├── proxy.py          # 代理程序
├── config.yaml       # 默认配置
├── requirements.txt  # Python 依赖
└── logs/             # 运行时自动创建的日志目录
```

## 快速启动

使用默认配置启动：

```bash
.venv/bin/python proxy.py
```

默认监听：

```text
127.0.0.1:8080
```

停止代理：

```text
Ctrl+C
```

代理停止时会将 `Proxy stopped` 写入当前日志文件。

## 客户端使用

通过代理访问 HTTP：

```bash
curl --proxy http://127.0.0.1:8080 http://example.com/
```

通过 CONNECT 隧道访问 HTTPS：

```bash
curl --proxy http://127.0.0.1:8080 https://example.com/
```

也可以设置环境变量：

```bash
export HTTP_PROXY=http://127.0.0.1:8080
export HTTPS_PROXY=http://127.0.0.1:8080
```

这里的 `HTTPS_PROXY` 仍使用 `http://`，因为客户端先通过 HTTP CONNECT 与代理建立隧道。

## 命令行参数

查看完整帮助：

```bash
.venv/bin/python proxy.py --help
```

| 参数 | 说明 | 默认值 |
| --- | --- | --- |
| `--config PATH` | 指定 YAML 配置文件 | 与 `proxy.py` 同目录的 `config.yaml` |
| `--host HOST` | 覆盖监听地址 | 配置文件中的 `host` |
| `--port PORT` | 覆盖监听端口 | 配置文件中的 `port` |
| `--buffer-size BYTES` | 覆盖每次 relay 的最大读取字节数 | 配置文件中的 `buffer_size` |
| `--connect-timeout SECONDS` | 覆盖 DNS/上游连接超时 | 配置文件中的 `connect_timeout` |
| `--filter out\|in` | 覆盖终端日志方向过滤 | 配置文件中的 `filter` |

配置文件先加载，命令行参数随后覆盖相应值。例如：

```bash
.venv/bin/python proxy.py --port 18080 --filter=out
```

使用其他配置文件：

```bash
.venv/bin/python proxy.py --config /path/to/proxy.yaml
```

访问策略只能通过 YAML 配置，不能通过命令行逐条设置。

## 基础配置

`config.yaml` 的基础字段：

```yaml
host: 127.0.0.1
port: 8080
buffer_size: 65536
connect_timeout: 10.0
filter: null
```

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `host` | 字符串 | 代理监听地址 |
| `port` | 整数 | 监听端口，范围为 `1-65535` |
| `buffer_size` | 正整数 | 每次从连接读取的最大应用层数据块大小 |
| `connect_timeout` | 正数 | DNS 解析或连接上游的超时秒数 |
| `filter` | `out`、`in` 或 `null` | 仅控制终端显示方向，日志文件始终记录全部方向 |

`filter` 的行为：

```yaml
filter: out   # 终端只显示 ->
filter: in    # 终端只显示 <-
filter: null  # 终端显示两个方向
```

## 访问策略配置

完整策略结构：

```yaml
domain_policy:
  default: allow
  rules:
    - action: allow
      match: exact
      domains:
        - required.analytics.example.com

    - action: deny
      match: exact
      domains:
        - ads.example.com
        - tracker.example.net

    - action: deny
      match: suffix
      domains:
        - example.org
        - analytics.example.com

    - action: deny
      match: wildcard
      domains:
        - "*.blocked.example"

    - action: deny
      match: regex
      patterns:
        - "^ad[0-9]+\\.example\\.com$"

    - action: deny
      match: ip_cidr
      networks:
        - 192.0.2.10
        - 198.51.100.0/24

    - action: audit
      match: suffix
      domains:
        - test.example.net
```

示例使用的是保留域名和测试网段，实际部署时应替换为真实规则。

### 默认动作

`domain_policy.default` 决定所有规则都未命中时的行为：

```yaml
domain_policy:
  default: allow  # 也可以是 deny 或 audit
```

### 匹配方式

| `match` | 值字段 | 行为 |
| --- | --- | --- |
| `exact` | `domains` | 精确匹配规范化后的域名或 IP |
| `suffix` | `domains` | 匹配根域名及其任意层级子域名 |
| `wildcard` | `domains` | 使用 ASCII 通配符匹配，例如 `*.example.com` |
| `regex` | `patterns` | 对完整的规范化域名执行不区分大小写的正则完整匹配 |
| `ip_cidr` | `networks` | 匹配解析后的单个 IP 或 CIDR 网段 |

匹配细节：

- 域名会转换为小写并移除末尾的 `.`。
- 国际化域名会转换为 IDNA ASCII 形式。
- `suffix: example.com` 同时匹配 `example.com` 和 `a.b.example.com`，但不会误匹配 `notexample.com`。
- `wildcard: "*.example.com"` 匹配子域名，不匹配根域名 `example.com`。
- 通配符规则必须使用 ASCII。
- 正则使用完整匹配；如需匹配前后任意内容，应在表达式中明确写出。
- `192.0.2.10` 会作为单个 IP 网络处理，CIDR 使用如 `198.51.100.0/24` 的格式。

### 匹配顺序

匹配分为两个阶段：

1. 按配置顺序检查 `exact`、`suffix`、`wildcard` 和 `regex`，第一个域名规则命中后立即生效。
2. 如果没有域名规则命中，再解析目标地址并按配置顺序检查 `ip_cidr`。
3. 如果仍未命中，则使用 `domain_policy.default`。

需要覆盖宽泛拒绝规则的 `allow` 例外必须放在前面：

```yaml
rules:
  - action: allow
    match: exact
    domains:
      - api.example.com

  - action: deny
    match: suffix
    domains:
      - example.com
```

### 策略动作

| `action` | 符号 | 行为 |
| --- | --- | --- |
| `allow` | `√` | 正常建立上游连接并转发数据 |
| `deny` | `×` | 不发送上游请求，记录 `bytes=0`，返回 `403 Forbidden` |
| `audit` | `*` | 记录策略命中，但继续建立连接和转发数据 |

域名 `deny` 在 DNS 解析前生效。IP/CIDR `deny` 需要先解析域名，但会在建立上游 TCP 连接前生效。

## 日志文件

代理启动时会在当前工作目录自动创建 `logs/`：

```text
logs/log_20260728_091708_001.log
```

文件名格式：

```text
log_YYYYMMDD_HHMMSS_mmm.log
```

其中日期、时间和三位毫秒是代理启动时的东八区时间。日志文件使用独占创建，不会覆盖已有同名文件。

终端过滤发生在文件写入之后，因此：

- `filter: out` 时终端只显示 `->`，文件仍记录 `->` 和 `<-`。
- `filter: in` 时终端只显示 `<-`，文件仍记录 `->` 和 `<-`。
- 启动、停止、错误和策略命中信息也写入同一个日志文件。

日志会在每次写入后立即刷新，便于使用 `tail -f` 实时查看：

```bash
tail -f logs/log_*.log
```

## 日志解读

允许流量：

```text
2026-07-28 17:38:03.962 √ source_ip=127.0.0.1 -> target_domain=localhost target_ip=127.0.0.1 bytes=87
```

拒绝流量：

```text
2026-07-28 17:38:03.961 × source_ip=127.0.0.1 -> target_domain=ads.example.com target_ip=unknown bytes=0
```

审计流量：

```text
2026-07-28 17:38:44.140 * source_ip=127.0.0.1 <- target_domain=localhost target_ip=127.0.0.1 bytes=195
```

### 字段说明

| 内容 | 说明 |
| --- | --- |
| `2026-07-28 17:38:03.962` | 固定东八区时间，毫秒始终为三位 |
| `√` | 当前连接的策略结果为 allow |
| `×` | 当前请求被 deny |
| `*` | 当前连接命中 audit 规则 |
| `source_ip` | 连接代理的客户端 IP |
| `->` | 客户端向目标服务器发送数据 |
| `<-` | 目标服务器向客户端返回数据 |
| `target_domain` | HTTP URL、Host 头或 CONNECT 中的目标域名 |
| `target_ip` | 实际连接或策略解析得到的目标 IP |
| `bytes` | 代理本次读取并转发的应用层数据块字节数 |

`bytes` 不是网卡抓包中的单个 TCP/IP 包长度。它受 `buffer_size`、操作系统缓冲区、客户端速度和上游响应方式影响。普通 HTTP 的统计可能包含 HTTP 头；HTTPS CONNECT 建立后统计的是加密 TLS 数据。

策略在 DNS 前拒绝域名时，目标尚未解析，因此会显示：

```text
target_ip=unknown bytes=0
```

`audit` 命中时会先产生一条 `bytes=0` 的 `*` 日志，随后该连接的所有转发数据继续使用 `*`。

运行日志示例：

```text
2026-07-28 17:37:52.340 Proxy listening on ('127.0.0.1', 8080) log_file=log_20260728_173752_340.log
2026-07-28 17:38:33.750 Proxy stopped
```

## 验证访问策略

验证允许请求：

```bash
curl --proxy http://127.0.0.1:8080 http://example.com/
```

验证 HTTP 拒绝规则：

```bash
curl -i --proxy http://127.0.0.1:8080 http://ads.example.com/
```

预期状态：

```text
HTTP/1.1 403 Forbidden
```

验证 HTTPS CONNECT 拒绝规则：

```bash
curl --proxy http://127.0.0.1:8080 https://ads.example.com/
```

预期 curl 输出包含：

```text
Received HTTP code 403 from proxy after CONNECT
```

## 配置校验

代理启动时会严格校验配置，包括：

- 未知的顶层字段
- 非法端口或非正数参数
- 非法 `filter` 值
- 未知策略字段
- 非法动作或匹配类型
- 空规则列表值
- 无效正则表达式
- 无效 IP 或 CIDR

配置错误会直接终止启动并输出具体原因，避免代理在部分规则失效的状态下运行。

## 常见问题

### 启动时报 `No module named 'yaml'`

重新安装依赖：

```bash
.venv/bin/python -m pip install -r requirements.txt
```

### 返回 `502 Bad Gateway`

通常表示 DNS 解析失败、目标端口拒绝连接或上游连接超时。检查目标域名、端口、网络和 `connect_timeout`。

### 返回 `403 Forbidden`

请求命中了 `deny` 规则或 `domain_policy.default` 被设置为 `deny`。查找对应的 `×` 日志。

### 端口已被占用

修改 `config.yaml`：

```yaml
port: 18080
```

或临时覆盖：

```bash
.venv/bin/python proxy.py --port 18080
```

## 安全说明

默认配置只监听 `127.0.0.1`。如果需要供局域网设备使用，可以设置：

```yaml
host: 0.0.0.0
```

当前代理没有用户认证。监听 `0.0.0.0` 前应配置防火墙，只允许可信网段访问。不要将该代理端口直接暴露到互联网，否则可能成为开放代理并被滥用。
