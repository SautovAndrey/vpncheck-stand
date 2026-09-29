"""Запуск сервера агентов под systemd: uvicorn со своим слушающим сокетом и своим протоколом HTTP.

    python run.py --host 0.0.0.0 --port 8787 --limit-concurrency 5000
    python run.py --host 0.0.0.0 --port 8787 --tls-port 8788 --tls-cert tls/cert.pem --tls-key tls/key.pem

Что добавлено к `uvicorn app:app`:
- TCP keepalive (180/30/3) на слушающем сокете и на каждом принятом: соединение умершего телефона закрывается
  через ~4.5 минуты, а не держится до перезапуска;
- соединение, по которому за REQUEST_TIMEOUT не пришёл полный запрос (заголовки и тело), закрывается - пустые и
  недописанные сокеты не копят --limit-concurrency; тело медленнее MIN_BODY_RATE после первых REQUEST_TIMEOUT
  тоже обрывается, большой APK по нормальному каналу успевает;
- заголовки запроса (строка запроса и поля) - не больше MAX_HEAD_BYTES, дальше 431 и закрытие;
- с одного адреса не больше MAX_CONN_PER_IP соединений (кроме loopback - там TLS-прокси);
- --tls-port: второй слушающий сокет с TLS 1.2+ (самоподписанный сертификат, агенты сверяют отпечаток ключа) на
  тот же app и с теми же защитами; соединение попадает в предел на адрес ДО рукопожатия (TlsAcceptor), так что
  висящие рукопожатия с одного адреса не копят дескрипторы и память. Сертификат не читается или порт занят -
  сервер работает только по http, а app получает об этом строку в журнал ошибок и тревогу (app.tls_down);
  /health говорит "tls": true только при живом TLS-порте.
Тесты и ручной запуск `uvicorn app:app` по-прежнему работают: app.py от этого файла не зависит.
"""
import argparse
import asyncio
import contextlib
import ipaddress
import os
import socket
import ssl
import struct
import sys
import threading

import uvicorn
from uvicorn.protocols.http.httptools_impl import HttpToolsProtocol

REQUEST_TIMEOUT = 30.0
MIN_BODY_RATE = 32 * 1024
UPLOAD_BODY_RATE = 4 * 1024
UPLOAD_PATHS = ("/v1/admin/upload",)
MAX_HEAD_BYTES = 64 * 1024
MAX_CONN_PER_IP = 256
KEEPALIVE_IDLE, KEEPALIVE_INTERVAL, KEEPALIVE_COUNT = 180, 30, 3
LOOPBACK = ("127.", "::1", "::ffff:127.")


def keepalive_options():
    options = [(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)]
    user_timeout = (KEEPALIVE_IDLE + KEEPALIVE_INTERVAL * KEEPALIVE_COUNT) * 1000
    for name, value in (("TCP_KEEPIDLE", KEEPALIVE_IDLE), ("TCP_KEEPINTVL", KEEPALIVE_INTERVAL),
                        ("TCP_KEEPCNT", KEEPALIVE_COUNT), ("TCP_USER_TIMEOUT", user_timeout)):
        if hasattr(socket, name):
            options.append((socket.IPPROTO_TCP, getattr(socket, name), value))
    return options


def peer_key(host):
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return host
    if address.version == 4:
        return str(address)
    if address.ipv4_mapped is not None:
        return str(address.ipv4_mapped)
    return str(ipaddress.ip_network("%s/64" % address, strict=False))


def set_keepalive(sock):
    for level, name, value in keepalive_options():
        with contextlib.suppress(OSError):
            sock.setsockopt(level, name, value)


def counted_peer(host):
    return peer_key(host) if host and not host.startswith(LOOPBACK) else ""


def take_slot(peer):
    count = GuardedProtocol.per_ip.get(peer, 0) + 1
    GuardedProtocol.per_ip[peer] = count
    return count <= MAX_CONN_PER_IP


def free_slot(peer):
    left = GuardedProtocol.per_ip.get(peer, 1) - 1
    if left > 0:
        GuardedProtocol.per_ip[peer] = left
    else:
        GuardedProtocol.per_ip.pop(peer, None)


class GuardedProtocol(HttpToolsProtocol):
    """HttpToolsProtocol с таймером на недописанный запрос, пределом заголовков и числа соединений с адреса."""

    per_ip: dict = {}

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._guard = None
        self._deadline = 0.0
        self._pending = True
        self._in_head = True
        self._head_bytes = 0
        self._peer = ""
        self._adopted = None
        self._rate = MIN_BODY_RATE

    def adopt(self, peer):
        """Соединение уже учтено в пределе на адрес (TlsAcceptor до рукопожатия) - второй раз не считать."""
        self._adopted = peer

    def release_adopted(self):
        """Рукопожатие не состоялось: True - слот так и не перешёл к соединению, его освобождает TlsAcceptor."""
        pending = self._adopted is not None
        self._adopted = None
        return pending

    def connection_made(self, transport):
        super().connection_made(transport)
        sock = transport.get_extra_info("socket")
        if sock is not None:
            set_keepalive(sock)
        if self._adopted is not None:
            self._peer, self._adopted = self._adopted, None
        else:
            self._peer = counted_peer(self.client[0] if self.client else "")
            if self._peer and not take_slot(self._peer):
                transport.close()
                return
        self._deadline = self.loop.time() + REQUEST_TIMEOUT
        self._arm()

    def connection_lost(self, exc):
        self._disarm()
        if self._peer:
            free_slot(self._peer)
            self._peer = ""
        super().connection_lost(exc)

    def _idle(self):
        return self.cycle is None or self.cycle.response_complete

    def _arm(self):
        if self._guard is None:
            self._guard = self.loop.call_later(max(0.0, self._deadline - self.loop.time()), self._expire)

    def _disarm(self):
        if self._guard is not None:
            self._guard.cancel()
            self._guard = None

    def _expire(self):
        self._guard = None
        if self.transport is None or self.transport.is_closing():
            return
        idle = self._idle()
        if not self._pending and not idle:
            return
        now = self.loop.time()
        if not idle and ((self.flow is not None and self.flow.read_paused) or not self.cycle.more_body):
            self._deadline = max(self._deadline, now + REQUEST_TIMEOUT)
        if now < self._deadline:
            self._arm()
            return
        self.transport.close()

    def data_received(self, data):
        if self._guard is None and self._idle():
            self._deadline = self.loop.time() + REQUEST_TIMEOUT
            self._arm()
        while data and self.parser is not None and not self.transport.is_closing():
            if not self._in_head:
                super().data_received(data)
                return
            room = MAX_HEAD_BYTES - self._head_bytes
            if room <= 0:
                self._reject_head()
                return
            piece, data = data[:room], data[room:]
            self._head_bytes += len(piece)
            super().data_received(piece)

    def _reject_head(self):
        if self._idle():
            message = b"request header too large"
            self.transport.write(b"HTTP/1.1 431 Request Header Fields Too Large\r\n"
                                 b"content-type: text/plain; charset=utf-8\r\n"
                                 b"content-length: %d\r\nconnection: close\r\n\r\n%s" % (len(message), message))
        self.transport.close()

    def on_message_begin(self):
        super().on_message_begin()
        self._pending = True
        self._deadline = self.loop.time() + REQUEST_TIMEOUT
        self._arm()

    def on_headers_complete(self):
        self._in_head = False
        super().on_headers_complete()
        self._rate = UPLOAD_BODY_RATE if self.scope.get("path") in UPLOAD_PATHS else MIN_BODY_RATE

    def on_body(self, body):
        self._deadline += len(body) / self._rate
        super().on_body(body)

    def on_message_complete(self):
        self._pending = False
        self._in_head = True
        self._head_bytes = 0
        self._disarm()
        super().on_message_complete()


class TlsAcceptor:
    """Приём на TLS-порту: слот в пределе на адрес берётся сразу после accept, до рукопожатия (висящие рукопожатия
    с одного адреса не копят дескрипторы и память), затем loop.connect_accepted_socket с TLS и таймаутом
    REQUEST_TIMEOUT; слот переходит к GuardedProtocol (adopt), не удалось - освобождается здесь. Сокет оборачивается
    в TLS с первого байта: ClientHello, пришедший сразу за accept, не теряется (uvloop читает до connection_made).
    Для uvicorn выглядит как asyncio.Server: close() и wait_closed() при остановке."""

    def __init__(self, loop, sock, context, make_protocol, backlog):
        self.loop = loop
        self.sock = sock
        self.context = context
        self.make_protocol = make_protocol
        self.handshakes = set()
        sock.setblocking(False)
        sock.listen(backlog)
        self.task = loop.create_task(self.accept_loop())

    async def accept_loop(self):
        while True:
            try:
                conn, address = await self.loop.sock_accept(self.sock)
            except asyncio.CancelledError:
                raise
            except OSError:
                await asyncio.sleep(0.1)
                continue
            set_keepalive(conn)
            peer = counted_peer(address[0] if address else "")
            if peer and not take_slot(peer):
                free_slot(peer)
                with contextlib.suppress(OSError):
                    conn.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
                conn.close()
                continue
            task = self.loop.create_task(self.handshake(conn, peer))
            self.handshakes.add(task)
            task.add_done_callback(self.handshakes.discard)

    async def handshake(self, conn, peer):
        protocol = self.make_protocol()
        protocol.adopt(peer)
        try:
            await self.loop.connect_accepted_socket(lambda: protocol, sock=conn, ssl=self.context,
                                                    ssl_handshake_timeout=REQUEST_TIMEOUT)
        except asyncio.CancelledError:
            self.drop(conn, peer, protocol)
            raise
        except Exception:  # noqa: BLE001 - рукопожатие не удалось, оборвалось или истекло
            self.drop(conn, peer, protocol)

    @staticmethod
    def drop(conn, peer, protocol):
        if protocol.release_adopted() and peer:
            free_slot(peer)
        with contextlib.suppress(OSError):
            conn.close()

    def close(self):
        self.task.cancel()
        for task in list(self.handshakes):
            task.cancel()
        with contextlib.suppress(OSError):
            self.sock.close()

    async def wait_closed(self):
        await asyncio.gather(self.task, *self.handshakes, return_exceptions=True)


def app_module():
    return sys.modules.get("app")


class Server(uvicorn.Server):
    def __init__(self, config, tls=None, tls_error="", tls_files=("", "")):
        super().__init__(config)
        self.tls = tls
        self.tls_error = tls_error
        self.tls_files = tls_files

    def tls_failed(self, reason):
        text = "TLS is off, serving plain HTTP only: %s" % reason
        module = app_module()
        if module is None or not hasattr(module, "tls_down"):
            print(text, file=sys.stderr, flush=True)
            return
        threading.Thread(target=module.tls_down, args=(text,), daemon=True, name="tls-down").start()

    async def startup(self, sockets=None):
        module = app_module()
        if module is not None and hasattr(module, "TLS_STATE"):
            module.TLS_STATE.update(on=False, cert=self.tls_files[0], key=self.tls_files[1])
        await super().startup(sockets=sockets)
        if not self.started:
            return
        if self.tls is None:
            if self.tls_error:
                self.tls_failed(self.tls_error)
            return
        sock, context = self.tls
        config = self.config
        loop = asyncio.get_running_loop()

        def create_protocol(_loop=None):
            return config.http_protocol_class(config=config, server_state=self.server_state,
                                              app_state=self.lifespan.state, _loop=_loop)
        try:
            acceptor = TlsAcceptor(loop, sock, context, create_protocol, config.backlog)
        except OSError as exc:
            self.tls_failed(exc)
            return
        self.servers.append(acceptor)
        if module is not None and hasattr(module, "TLS_STATE"):
            module.TLS_STATE["on"] = True


def tls_context(cert, key):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(cert, key)
    context.set_alpn_protocols(["http/1.1"])
    return context


def bind(host, port):
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_STREAM)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((host, port))
    except OSError:
        sock.close()
        raise
    sock.set_inheritable(True)
    return sock


def tls_listener(args):
    """(сокет, SSL-контекст) и пустая причина, либо None и причина, почему TLS-порт не поднят."""
    if not args.tls_port:
        return None, ""
    if not args.tls_cert or not args.tls_key:
        return None, "--tls-port needs --tls-cert and --tls-key"
    try:
        context = tls_context(args.tls_cert, args.tls_key)
        sock = bind(args.host, args.tls_port)
    except (OSError, ssl.SSLError, ValueError) as exc:
        return None, str(exc)
    set_keepalive(sock)
    return (sock, context), ""


def build(argv=None):
    parser = argparse.ArgumentParser(description="VPNCheck agent server")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8787)
    parser.add_argument("--tls-port", type=int, default=0)
    parser.add_argument("--tls-cert", default="")
    parser.add_argument("--tls-key", default="")
    parser.add_argument("--limit-concurrency", type=int, default=5000)
    parser.add_argument("--proxy-headers", action="store_true")
    parser.add_argument("--log-level", default="info")
    args = parser.parse_args(argv)
    config = uvicorn.Config("app:app", host=args.host, port=args.port, proxy_headers=True,
                            limit_concurrency=args.limit_concurrency, http=GuardedProtocol,
                            log_level=args.log_level)
    sock = config.bind_socket()
    set_keepalive(sock)
    tls, error = tls_listener(args)
    files = (os.path.abspath(args.tls_cert), os.path.abspath(args.tls_key)) \
        if args.tls_port and args.tls_cert and args.tls_key else ("", "")
    return Server(config, tls, error, files), sock


def main(argv=None):
    server, sock = build(argv)
    server.run(sockets=[sock])
    return 0 if server.started else 1


if __name__ == "__main__":
    sys.exit(main())
