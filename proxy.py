#!/usr/bin/env python3
"""A small asynchronous HTTP/HTTPS CONNECT forward proxy."""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import datetime as dt
import ipaddress
import re
import socket
import sys
from dataclasses import dataclass
from fnmatch import fnmatchcase
from pathlib import Path
from typing import Any, Pattern, TextIO
from urllib.parse import urlsplit, urlunsplit

import yaml


DEFAULT_BUFFER_SIZE = 64 * 1024
DEFAULT_HEADER_LIMIT = 64 * 1024
LOG_TIMEZONE = dt.timezone(dt.timedelta(hours=8))
DEFAULT_CONFIG_PATH = Path(__file__).with_name("config.yaml")
DEFAULT_CONFIG: dict[str, Any] = {
    "host": "127.0.0.1",
    "port": 8080,
    "buffer_size": DEFAULT_BUFFER_SIZE,
    "connect_timeout": 10.0,
    "filter": None,
    "domain_policy": {
        "default": "allow",
        "rules": [],
    },
}
LOG_FILE: TextIO | None = None


@dataclass(frozen=True)
class Target:
    host: str
    port: int


@dataclass(frozen=True)
class ParsedRequest:
    method: str
    version: str
    target: Target
    outbound_target: str | None
    headers: list[tuple[str, str]]


@dataclass(frozen=True)
class PolicyDecision:
    action: str
    match_type: str
    rule_index: int | None
    matched_value: str
    matched_ip: str | None = None


@dataclass(frozen=True)
class DomainRule:
    action: str
    match_type: str
    values: tuple[str, ...] = ()
    patterns: tuple[Pattern[str], ...] = ()
    networks: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...] = ()

    def match_domain(self, host: str) -> str | None:
        if self.match_type == "exact":
            return next((value for value in self.values if host == value), None)
        if self.match_type == "suffix":
            return next(
                (
                    value
                    for value in self.values
                    if host == value or host.endswith(f".{value}")
                ),
                None,
            )
        if self.match_type == "wildcard":
            return next((value for value in self.values if fnmatchcase(host, value)), None)
        if self.match_type == "regex":
            return next(
                (pattern.pattern for pattern in self.patterns if pattern.fullmatch(host)),
                None,
            )
        return None

    def match_ips(self, addresses: list[str]) -> tuple[str, str] | None:
        if self.match_type != "ip_cidr":
            return None
        for address in addresses:
            ip = ipaddress.ip_address(address)
            for network in self.networks:
                if ip.version == network.version and ip in network:
                    return str(network), address
        return None


@dataclass(frozen=True)
class DomainPolicy:
    default_action: str
    rules: tuple[DomainRule, ...]

    @property
    def has_ip_rules(self) -> bool:
        return any(rule.match_type == "ip_cidr" for rule in self.rules)

    def match_domain(self, host: str) -> PolicyDecision | None:
        normalized_host = normalize_host(host)
        for index, rule in enumerate(self.rules, start=1):
            matched_value = rule.match_domain(normalized_host)
            if matched_value is not None:
                return PolicyDecision(rule.action, rule.match_type, index, matched_value)
        return None

    def match_ips(self, addresses: list[str]) -> PolicyDecision | None:
        for index, rule in enumerate(self.rules, start=1):
            match = rule.match_ips(addresses)
            if match is not None:
                matched_value, matched_ip = match
                return PolicyDecision(
                    rule.action,
                    rule.match_type,
                    index,
                    matched_value,
                    matched_ip,
                )
        return None

    def default_decision(self) -> PolicyDecision:
        return PolicyDecision(self.default_action, "default", None, "default")


class RequestBlocked(Exception):
    pass


def timestamp() -> str:
    return dt.datetime.now(LOG_TIMEZONE).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]


def log_filename(started_at: dt.datetime) -> str:
    milliseconds = started_at.microsecond // 1000
    return f"log_{started_at:%Y%m%d_%H%M%S}_{milliseconds:03d}.log"


def write_log(
    line: str,
    *,
    show: bool = True,
    stream: TextIO | None = None,
) -> None:
    if LOG_FILE is not None:
        print(line, file=LOG_FILE, flush=True)
    if show:
        print(line, file=sys.stdout if stream is None else stream, flush=True)


def normalize_host(host: str) -> str:
    normalized = host.strip().rstrip(".")
    if not normalized:
        raise ValueError("empty domain or IP address")
    try:
        return str(ipaddress.ip_address(normalized))
    except ValueError:
        try:
            return normalized.encode("idna").decode("ascii").lower()
        except UnicodeError as exc:
            raise ValueError(f"invalid internationalized domain: {host}") from exc


def normalize_wildcard(pattern: str) -> str:
    normalized = pattern.strip().rstrip(".").lower()
    if not normalized or any(ord(character) > 127 for character in normalized):
        raise ValueError("wildcard patterns must be non-empty ASCII strings")
    return normalized


def build_domain_policy(config: dict[str, Any]) -> DomainPolicy:
    if not isinstance(config, dict):
        raise SystemExit("config 'domain_policy' must be a mapping")

    unknown_keys = set(config) - {"default", "rules"}
    if unknown_keys:
        names = ", ".join(sorted(str(key) for key in unknown_keys))
        raise SystemExit(f"unknown domain_policy keys: {names}")

    default_action = config.get("default", "allow")
    if default_action not in {"allow", "deny", "audit"}:
        raise SystemExit("domain_policy 'default' must be allow, deny, or audit")

    raw_rules = config.get("rules", [])
    if not isinstance(raw_rules, list):
        raise SystemExit("domain_policy 'rules' must be a list")

    rules: list[DomainRule] = []
    value_keys = {
        "exact": "domains",
        "suffix": "domains",
        "wildcard": "domains",
        "regex": "patterns",
        "ip_cidr": "networks",
    }
    for index, raw_rule in enumerate(raw_rules, start=1):
        if not isinstance(raw_rule, dict):
            raise SystemExit(f"domain_policy rule {index} must be a mapping")
        action = raw_rule.get("action")
        match_type = raw_rule.get("match")
        if action not in {"allow", "deny", "audit"}:
            raise SystemExit(f"domain_policy rule {index} has invalid action")
        if match_type not in value_keys:
            raise SystemExit(f"domain_policy rule {index} has invalid match type")

        value_key = value_keys[match_type]
        unknown_rule_keys = set(raw_rule) - {"action", "match", value_key}
        if unknown_rule_keys:
            names = ", ".join(sorted(str(key) for key in unknown_rule_keys))
            raise SystemExit(f"domain_policy rule {index} has unknown keys: {names}")
        raw_values = raw_rule.get(value_key)
        if (
            not isinstance(raw_values, list)
            or not raw_values
            or any(not isinstance(value, str) or not value.strip() for value in raw_values)
        ):
            raise SystemExit(
                f"domain_policy rule {index} '{value_key}' must be a non-empty string list"
            )

        try:
            if match_type in {"exact", "suffix"}:
                values = tuple(normalize_host(value.lstrip(".")) for value in raw_values)
                rules.append(DomainRule(action, match_type, values=values))
            elif match_type == "wildcard":
                values = tuple(normalize_wildcard(value) for value in raw_values)
                rules.append(DomainRule(action, match_type, values=values))
            elif match_type == "regex":
                patterns = tuple(re.compile(value, re.IGNORECASE) for value in raw_values)
                rules.append(DomainRule(action, match_type, patterns=patterns))
            else:
                networks = tuple(ipaddress.ip_network(value, strict=False) for value in raw_values)
                rules.append(DomainRule(action, match_type, networks=networks))
        except (ValueError, re.error) as exc:
            raise SystemExit(f"domain_policy rule {index} is invalid: {exc}") from exc

    return DomainPolicy(default_action, tuple(rules))


def log_event(
    source_ip: str,
    target_host: str,
    target_ip: str,
    direction: str,
    size: int,
    filter_mode: str | None = None,
    policy_action: str = "allow",
) -> None:
    arrow = "->" if direction == "client->server" else "<-"
    symbol = {"allow": "√", "deny": "×", "audit": "*"}[policy_action]
    line = (
        f"{timestamp()} {symbol} source_ip={source_ip} {arrow} target_domain={target_host} "
        f"target_ip={target_ip} bytes={size}"
    )
    show = not (
        (filter_mode == "out" and direction != "client->server")
        or (filter_mode == "in" and direction != "server->client")
    )
    write_log(line, show=show)


def split_authority(authority: str, default_port: int) -> Target:
    authority = authority.strip()
    if not authority:
        raise ValueError("empty target authority")

    if authority.startswith("["):
        closing = authority.find("]")
        if closing < 0:
            raise ValueError("invalid IPv6 authority")
        host = authority[1:closing]
        suffix = authority[closing + 1 :]
        if not suffix:
            port = default_port
        elif suffix.startswith(":"):
            port = int(suffix[1:])
        else:
            raise ValueError("invalid IPv6 authority")
    elif authority.count(":") == 1:
        host, port_text = authority.rsplit(":", 1)
        port = int(port_text)
    else:
        host = authority
        port = default_port

    if not host or not 1 <= port <= 65535:
        raise ValueError("invalid target host or port")
    return Target(host=host, port=port)


def parse_headers(header_lines: list[str]) -> tuple[list[tuple[str, str]], str | None]:
    headers: list[tuple[str, str]] = []
    host_header: str | None = None
    for line in header_lines:
        if not line:
            continue
        if line[0] in " \t":
            raise ValueError("folded headers are not supported")
        name, separator, value = line.partition(":")
        if not separator or not name.strip():
            raise ValueError("invalid HTTP header")
        name = name.strip()
        value = value.strip()
        if name.lower() == "host":
            host_header = value
        if name.lower() not in {"proxy-connection", "proxy-authorization"}:
            headers.append((name, value))
    return headers, host_header


def parse_request(request_head: bytes) -> ParsedRequest:
    try:
        text = request_head.decode("iso-8859-1")
        lines = text[:-4].split("\r\n")
        method, request_target, version = lines[0].split(" ", 2)
    except (UnicodeDecodeError, ValueError, IndexError) as exc:
        raise ValueError("invalid HTTP request line") from exc

    if version not in {"HTTP/1.0", "HTTP/1.1"}:
        raise ValueError("invalid HTTP version")
    headers, host_header = parse_headers(lines[1:])

    if method.upper() == "CONNECT":
        target = split_authority(request_target, 443)
        return ParsedRequest(method, version, target, None, headers)

    parsed = urlsplit(request_target)
    if parsed.scheme:
        if parsed.scheme.lower() != "http":
            raise ValueError("non-CONNECT requests must use an http:// URL")
        if not parsed.hostname:
            raise ValueError("absolute URL has no host")
        default_port = 80
        try:
            port = parsed.port or default_port
        except ValueError as exc:
            raise ValueError("invalid URL port") from exc
        target = Target(parsed.hostname, port)
        origin_target = urlunsplit(("", "", parsed.path or "/", parsed.query, ""))
    else:
        if not host_header:
            raise ValueError("request has no Host header")
        target = split_authority(host_header, 80)
        origin_target = request_target

    return ParsedRequest(method, version, target, origin_target, headers)


def build_http_request(request: ParsedRequest) -> bytes:
    if request.outbound_target is None:
        raise ValueError("CONNECT request cannot be forwarded as plain HTTP")
    request_line = f"{request.method} {request.outbound_target} {request.version}\r\n"
    header_block = "".join(f"{name}: {value}\r\n" for name, value in request.headers)
    return (request_line + header_block + "\r\n").encode("iso-8859-1")


def peer_ip(writer: asyncio.StreamWriter) -> str:
    peer = writer.get_extra_info("peername")
    return str(peer[0]) if peer else "unknown"


async def send_error(writer: asyncio.StreamWriter, status: int, reason: str) -> None:
    body = f"{status} {reason}\n".encode("utf-8")
    response = (
        f"HTTP/1.1 {status} {reason}\r\n"
        f"Content-Type: text/plain; charset=utf-8\r\n"
        f"Content-Length: {len(body)}\r\n"
        "Connection: close\r\n\r\n"
    ).encode("ascii") + body
    writer.write(response)
    with contextlib.suppress(ConnectionError):
        await writer.drain()


async def relay(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    *,
    source_ip: str,
    target_host: str,
    target_ip: str,
    direction: str,
    buffer_size: int,
    filter_mode: str | None,
    policy_action: str,
) -> None:
    while data := await reader.read(buffer_size):
        writer.write(data)
        await writer.drain()
        log_event(
            source_ip,
            target_host,
            target_ip,
            direction,
            len(data),
            filter_mode,
            policy_action,
        )

    if writer.can_write_eof():
        with contextlib.suppress(ConnectionError):
            writer.write_eof()
            await writer.drain()


class ProxyServer:
    def __init__(
        self,
        buffer_size: int,
        connect_timeout: float,
        filter_mode: str | None,
        domain_policy: DomainPolicy,
    ) -> None:
        self.buffer_size = buffer_size
        self.connect_timeout = connect_timeout
        self.filter_mode = filter_mode
        self.domain_policy = domain_policy

    def apply_policy_decision(
        self,
        decision: PolicyDecision,
        source_ip: str,
        target: Target,
        target_ip: str = "unknown",
    ) -> str:
        if decision.action in {"deny", "audit"}:
            log_event(
                source_ip,
                target.host,
                target_ip,
                "client->server",
                0,
                self.filter_mode,
                decision.action,
            )
        if decision.action == "deny":
            raise RequestBlocked("domain policy denied the request")
        return decision.action

    async def resolve_target(self, target: Target) -> list[tuple[Any, ...]]:
        loop = asyncio.get_running_loop()
        return await asyncio.wait_for(
            loop.getaddrinfo(target.host, target.port, type=socket.SOCK_STREAM),
            timeout=self.connect_timeout,
        )

    async def connect_resolved(
        self,
        addresses: list[tuple[Any, ...]],
    ) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        loop = asyncio.get_running_loop()
        last_error: OSError | TimeoutError | None = None
        for family, socktype, protocol, _, address in addresses:
            upstream_socket = socket.socket(family, socktype, protocol)
            upstream_socket.setblocking(False)
            try:
                await asyncio.wait_for(
                    loop.sock_connect(upstream_socket, address),
                    timeout=self.connect_timeout,
                )
                return await asyncio.open_connection(sock=upstream_socket)
            except (OSError, TimeoutError) as exc:
                last_error = exc
                upstream_socket.close()
            except asyncio.CancelledError:
                upstream_socket.close()
                raise
            except Exception:
                upstream_socket.close()
                raise

        if last_error is not None:
            raise last_error
        raise OSError("DNS resolution returned no usable addresses")

    async def open_target(
        self,
        target: Target,
        source_ip: str,
    ) -> tuple[asyncio.StreamReader, asyncio.StreamWriter, str]:
        domain_decision = self.domain_policy.match_domain(target.host)
        if domain_decision is not None:
            policy_action = self.apply_policy_decision(domain_decision, source_ip, target)
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(target.host, target.port),
                timeout=self.connect_timeout,
            )
            return reader, writer, policy_action

        if self.domain_policy.has_ip_rules:
            addresses = await self.resolve_target(target)
            resolved_ips = list(dict.fromkeys(str(address[4][0]) for address in addresses))
            ip_decision = self.domain_policy.match_ips(resolved_ips)
            decision = ip_decision or self.domain_policy.default_decision()
            policy_action = self.apply_policy_decision(
                decision,
                source_ip,
                target,
                ",".join(resolved_ips),
            )
            if (
                decision.action == "allow"
                and decision.match_type == "ip_cidr"
                and decision.matched_ip is not None
            ):
                addresses = [
                    address
                    for address in addresses
                    if str(address[4][0]) == decision.matched_ip
                ]
            reader, writer = await self.connect_resolved(addresses)
            return reader, writer, policy_action

        policy_action = self.apply_policy_decision(
            self.domain_policy.default_decision(),
            source_ip,
            target,
        )
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(target.host, target.port),
            timeout=self.connect_timeout,
        )
        return reader, writer, policy_action

    async def handle_client(
        self, client_reader: asyncio.StreamReader, client_writer: asyncio.StreamWriter
    ) -> None:
        source_ip = peer_ip(client_writer)
        upstream_writer: asyncio.StreamWriter | None = None
        response_started = False
        try:
            request_head = await client_reader.readuntil(b"\r\n\r\n")
            request = parse_request(request_head)
            target = request.target

            if request.method.upper() == "CONNECT":
                upstream_reader, upstream_writer, policy_action = await self.open_target(
                    target,
                    source_ip,
                )
                target_ip = peer_ip(upstream_writer)
                client_writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                await client_writer.drain()
                response_started = True
            else:
                outbound_head = build_http_request(request)
                upstream_reader, upstream_writer, policy_action = await self.open_target(
                    target,
                    source_ip,
                )
                target_ip = peer_ip(upstream_writer)
                upstream_writer.write(outbound_head)
                await upstream_writer.drain()
                log_event(
                    source_ip,
                    target.host,
                    target_ip,
                    "client->server",
                    len(outbound_head),
                    self.filter_mode,
                    policy_action,
                )

            relay_tasks = (
                asyncio.create_task(relay(
                    client_reader,
                    upstream_writer,
                    source_ip=source_ip,
                    target_host=target.host,
                    target_ip=target_ip,
                    direction="client->server",
                    buffer_size=self.buffer_size,
                    filter_mode=self.filter_mode,
                    policy_action=policy_action,
                )),
                asyncio.create_task(relay(
                    upstream_reader,
                    client_writer,
                    source_ip=source_ip,
                    target_host=target.host,
                    target_ip=target_ip,
                    direction="server->client",
                    buffer_size=self.buffer_size,
                    filter_mode=self.filter_mode,
                    policy_action=policy_action,
                )),
            )
            try:
                await asyncio.gather(*relay_tasks)
            finally:
                for task in relay_tasks:
                    task.cancel()
                await asyncio.gather(*relay_tasks, return_exceptions=True)
        except asyncio.IncompleteReadError:
            pass
        except asyncio.LimitOverrunError:
            await send_error(client_writer, 431, "Request Header Fields Too Large")
        except RequestBlocked:
            await send_error(client_writer, 403, "Forbidden")
        except (ValueError, UnicodeError) as exc:
            write_log(
                f"{timestamp()} source_ip={source_ip} error={exc}",
                stream=sys.stderr,
            )
            await send_error(client_writer, 400, "Bad Request")
        except (TimeoutError, socket.gaierror, ConnectionError, OSError) as exc:
            write_log(
                f"{timestamp()} source_ip={source_ip} error={exc}",
                stream=sys.stderr,
            )
            if not response_started and upstream_writer is None:
                await send_error(client_writer, 502, "Bad Gateway")
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            write_log(
                f"{timestamp()} source_ip={source_ip} unexpected_error={exc!r}",
                stream=sys.stderr,
            )
            if not response_started and upstream_writer is None:
                await send_error(client_writer, 500, "Internal Server Error")
        finally:
            if upstream_writer is not None:
                upstream_writer.close()
                with contextlib.suppress(Exception):
                    await upstream_writer.wait_closed()
            client_writer.close()
            with contextlib.suppress(Exception):
                await client_writer.wait_closed()


def positive_int(value: str) -> int:
    parsed = int(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be greater than zero")
    return parsed


def load_config(path: Path) -> dict[str, Any]:
    try:
        with path.open("r", encoding="utf-8") as config_file:
            loaded = yaml.safe_load(config_file)
    except FileNotFoundError as exc:
        raise SystemExit(f"config file not found: {path}") from exc
    except OSError as exc:
        raise SystemExit(f"cannot read config file {path}: {exc}") from exc
    except yaml.YAMLError as exc:
        raise SystemExit(f"invalid YAML in {path}: {exc}") from exc

    if loaded is None:
        loaded = {}
    if not isinstance(loaded, dict):
        raise SystemExit(f"config root must be a mapping: {path}")

    unknown_keys = set(loaded) - set(DEFAULT_CONFIG)
    if unknown_keys:
        names = ", ".join(sorted(str(key) for key in unknown_keys))
        raise SystemExit(f"unknown config keys: {names}")

    config = DEFAULT_CONFIG | loaded
    if isinstance(loaded.get("domain_policy"), dict):
        config["domain_policy"] = DEFAULT_CONFIG["domain_policy"] | loaded["domain_policy"]
    if not isinstance(config["host"], str) or not config["host"].strip():
        raise SystemExit("config 'host' must be a non-empty string")
    if type(config["port"]) is not int or not 1 <= config["port"] <= 65535:
        raise SystemExit("config 'port' must be an integer between 1 and 65535")
    if type(config["buffer_size"]) is not int or config["buffer_size"] <= 0:
        raise SystemExit("config 'buffer_size' must be a positive integer")
    if (
        isinstance(config["connect_timeout"], bool)
        or not isinstance(config["connect_timeout"], (int, float))
        or config["connect_timeout"] <= 0
    ):
        raise SystemExit("config 'connect_timeout' must be a positive number")
    if config["filter"] not in {None, "out", "in"}:
        raise SystemExit("config 'filter' must be 'out', 'in', or null")
    build_domain_policy(config["domain_policy"])
    return config


def build_parser(config: dict[str, Any]) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="HTTP/HTTPS forward proxy with traffic logs")
    parser.set_defaults(domain_policy=config["domain_policy"])
    parser.add_argument(
        "--config",
        default=str(DEFAULT_CONFIG_PATH),
        help="YAML config path (default: %(default)s)",
    )
    parser.add_argument("--host", default=config["host"], help="listen address (default: %(default)s)")
    parser.add_argument(
        "--port",
        type=int,
        default=config["port"],
        help="listen port (default: %(default)s)",
    )
    parser.add_argument(
        "--buffer-size",
        type=positive_int,
        default=config["buffer_size"],
        help="relay read size in bytes (default: %(default)s)",
    )
    parser.add_argument(
        "--connect-timeout",
        type=float,
        default=config["connect_timeout"],
        help="upstream connection timeout in seconds (default: %(default)s)",
    )
    parser.add_argument(
        "--filter",
        choices=("out", "in"),
        dest="filter_mode",
        default=config["filter"],
        help="log only outbound (->) or inbound (<-) traffic",
    )
    return parser


def parse_args() -> argparse.Namespace:
    config_parser = argparse.ArgumentParser(add_help=False)
    config_parser.add_argument("--config", default=str(DEFAULT_CONFIG_PATH))
    config_args, _ = config_parser.parse_known_args()
    config = load_config(Path(config_args.config))
    return build_parser(config).parse_args()


async def run(args: argparse.Namespace) -> None:
    global LOG_FILE

    started_at = dt.datetime.now(LOG_TIMEZONE)
    logs_directory = Path.cwd() / "logs"
    logs_directory.mkdir(parents=True, exist_ok=True)
    log_path = logs_directory / log_filename(started_at)
    with log_path.open("x", encoding="utf-8") as log_file:
        LOG_FILE = log_file
        try:
            proxy = ProxyServer(
                args.buffer_size,
                args.connect_timeout,
                args.filter_mode,
                build_domain_policy(args.domain_policy),
            )
            server = await asyncio.start_server(
                proxy.handle_client,
                args.host,
                args.port,
                limit=DEFAULT_HEADER_LIMIT,
            )
            addresses = ", ".join(str(sock.getsockname()) for sock in server.sockets or [])
            write_log(
                f"{timestamp()} Proxy listening on {addresses} log_file={log_path.name}"
            )
            async with server:
                await server.serve_forever()
        finally:
            write_log(f"{timestamp()} Proxy stopped")
            LOG_FILE = None


def main() -> None:
    args = parse_args()
    if not 1 <= args.port <= 65535:
        raise SystemExit("--port must be between 1 and 65535")
    if args.connect_timeout <= 0:
        raise SystemExit("--connect-timeout must be greater than zero")
    try:
        asyncio.run(run(args))
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
