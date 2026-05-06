import asyncio
import os
import socket
import sys
import traceback
import threading
import json
import platform

# from utils.proxy_protocols import parse_vless_protocol
from utils.network_tools import get_default_interface_ipv4
from utils.packet_templates import ClientHelloMaker
from utils.socket_tools import enable_keepalive
from fake_tcp import FakeInjectiveConnection, FakeTcpInjector


def get_exe_dir():
    """Returns the directory where the .exe (or script) is located."""
    if getattr(sys, 'frozen', False):
        # Running as a PyInstaller EXE
        return os.path.dirname(sys.executable)
    else:
        # Running as a normal Python script
        return os.path.dirname(os.path.abspath(__file__))


# Build the path to config.json
config_path = os.path.join(get_exe_dir(), 'config.json')

# Load the config
with open(config_path, 'r') as f:
    config = json.load(f)

LISTEN_HOST = config["LISTEN_HOST"]
LISTEN_PORT = config["LISTEN_PORT"]
FAKE_SNI = config["FAKE_SNI"].encode()
CONNECT_IP = config["CONNECT_IP"]
CONNECT_PORT = config["CONNECT_PORT"]
INTERFACE_IPV4 = config.get("INTERFACE_IPV4") or get_default_interface_ipv4(CONNECT_IP)
DATA_MODE = config.get("DATA_MODE", "tls")
BYPASS_METHOD = config.get("BYPASS_METHOD", "wrong_seq")
INJECTOR_BACKEND = config.get("INJECTOR_BACKEND", "auto").lower()

##################

fake_injective_connections: dict[tuple, FakeInjectiveConnection] = {}


def is_android() -> bool:
    return bool(os.environ.get("ANDROID_ROOT") or os.environ.get("TERMUX_VERSION"))


def is_packet_injection_enabled() -> bool:
    if INJECTOR_BACKEND == "none":
        return False
    if INJECTOR_BACKEND == "pydivert":
        return True
    return platform.system() == "Windows" and BYPASS_METHOD == "wrong_seq"


def effective_bypass_method() -> str:
    if BYPASS_METHOD == "wrong_seq" and not is_packet_injection_enabled():
        return "none"
    return BYPASS_METHOD


def print_startup_info() -> None:
    print(f"Listening on {LISTEN_HOST}:{LISTEN_PORT}")
    print(f"Connecting to {CONNECT_IP}:{CONNECT_PORT} with fake SNI {FAKE_SNI.decode(errors='replace')}")
    if is_packet_injection_enabled():
        print("Packet injection backend: pydivert/WinDivert")
    else:
        reason = "Termux/Android" if is_android() else platform.system()
        print(f"Packet injection backend: none ({reason}); packet spoofing disabled")
        print("Note: wrong_seq packet injection requires Windows + WinDivert/pydivert. Termux cannot load WinDivert DLLs.")


def log_connection_error(context: str, exc: BaseException) -> None:
    print(f"{context}: {exc.__class__.__name__}: {exc}")


def close_socket(sock: socket.socket | None) -> None:
    if sock is None:
        return
    try:
        sock.shutdown(socket.SHUT_RDWR)
    except OSError:
        pass
    try:
        sock.close()
    except OSError:
        pass


def stop_fake_connection(fake_injective_conn: FakeInjectiveConnection | None) -> None:
    if fake_injective_conn is None:
        return
    fake_injective_conn.monitor = False
    fake_injective_connections.pop(fake_injective_conn.id, None)


def set_windows_event_loop_policy() -> None:
    if sys.platform == "win32" and hasattr(asyncio, "WindowsSelectorEventLoopPolicy"):
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())


async def relay_main_loop(sock_1: socket.socket, sock_2: socket.socket, peer_task: asyncio.Task | None,
                          first_prefix_data: bytes):
    loop = asyncio.get_running_loop()
    while True:
        try:
            data = await loop.sock_recv(sock_1, 65575)
        except (asyncio.CancelledError, ConnectionError, OSError):
            return
        except Exception as exc:
            log_connection_error("relay receive failed", exc)
            return

        if not data:
            return

        if first_prefix_data:
            data = first_prefix_data + data
            first_prefix_data = b""

        try:
            await loop.sock_sendall(sock_2, data)
        except (asyncio.CancelledError, ConnectionError, OSError):
            return
        except Exception as exc:
            log_connection_error("relay send failed", exc)
            return


async def relay_bidirectional(incoming_sock: socket.socket, outgoing_sock: socket.socket) -> None:
    incoming_to_outgoing = asyncio.create_task(
        relay_main_loop(incoming_sock, outgoing_sock, None, b""))
    outgoing_to_incoming = asyncio.create_task(
        relay_main_loop(outgoing_sock, incoming_sock, None, b""))
    tasks = {incoming_to_outgoing, outgoing_to_incoming}

    try:
        done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        for task in done:
            try:
                await task
            except asyncio.CancelledError:
                pass

        close_socket(incoming_sock)
        close_socket(outgoing_sock)

        for task in pending:
            task.cancel()
        await asyncio.gather(*pending, return_exceptions=True)
    finally:
        close_socket(incoming_sock)
        close_socket(outgoing_sock)


async def handle(incoming_sock: socket.socket, incoming_remote_addr):
    loop = asyncio.get_running_loop()
    outgoing_sock: socket.socket | None = None
    fake_injective_conn: FakeInjectiveConnection | None = None

    try:
        # try:
        #     data = await loop.sock_recv(incoming_sock, 65575)
        #     if not data:
        #         raise ValueError("eof")
        # except Exception:
        #     close_socket(incoming_sock)
        #     return
        # try:
        #     version, uuid_bytes, transport_protocol, remote_address_type, remote_address, remote_port, payload_index = parse_vless_protocol(
        #         data)
        # except Exception as e:
        #     print("No Vless Request!, Connection Closed", repr(e), data)
        #     close_socket(incoming_sock)
        #     return
        # if transport_protocol != "tcp":
        #     print("Transport Protocol Error!, Connection Closed", transport_protocol, data)
        #     close_socket(incoming_sock)
        #     return
        # if remote_address_type == "hostname":
        #     print("hostname address not implemented yet!", data)
        #     close_socket(incoming_sock)
        #     return
        # if remote_address_type == "ipv4":
        #     if not INTERFACE_IPV4:
        #         print("no interface ipv4!", data)
        #         close_socket(incoming_sock)
        #         return
        #     family = socket.AF_INET
        #     src_ip = INTERFACE_IPV4
        #
        # elif remote_address_type == "ipv6":
        #     if not INTERFACE_IPV6:
        #         print("no interface ipv6!", data)
        #         close_socket(incoming_sock)
        #         return
        #     family = socket.AF_INET6
        #     src_ip = INTERFACE_IPV6
        #
        # else:
        #     print(data)
        #     log_connection_error("impossible address type", ValueError(remote_address_type))
        #     return

        # try:
        #     fake_sni_host, data_mode, bypass_method = UUID_FAKE_MAP[uuid_bytes]
        # except KeyError:
        #     print("unmatched uuid", uuid_bytes)
        #     close_socket(incoming_sock)
        #     return

        # if data_mode == "http":
        #     ...
        if DATA_MODE == "tls":
            fake_data = ClientHelloMaker.get_client_hello_with(os.urandom(32), os.urandom(32), FAKE_SNI,
                                                               os.urandom(32))
        else:
            log_connection_error("unsupported DATA_MODE", ValueError(DATA_MODE))
            return

        outgoing_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        outgoing_sock.setblocking(False)

        if INTERFACE_IPV4:
            try:
                outgoing_sock.bind((INTERFACE_IPV4, 0))
            except OSError as exc:
                log_connection_error(f"cannot bind outgoing socket to INTERFACE_IPV4={INTERFACE_IPV4}", exc)
                return

        enable_keepalive(outgoing_sock)
        src_port = outgoing_sock.getsockname()[1]

        if is_packet_injection_enabled():
            fake_injective_conn = FakeInjectiveConnection(outgoing_sock, INTERFACE_IPV4, CONNECT_IP, src_port, CONNECT_PORT,
                                                          fake_data,
                                                          BYPASS_METHOD, incoming_sock)
            fake_injective_connections[fake_injective_conn.id] = fake_injective_conn

        try:
            await loop.sock_connect(outgoing_sock, (CONNECT_IP, CONNECT_PORT))
        except (ConnectionError, OSError) as exc:
            log_connection_error(f"connect to {CONNECT_IP}:{CONNECT_PORT} failed", exc)
            return

        # if bypass_method == "wrong_checksum":
        #     ...

        bypass_method = effective_bypass_method()

        if bypass_method == "none":
            pass
        elif bypass_method == "direct":
            try:
                await loop.sock_sendall(outgoing_sock, fake_data)
            except (ConnectionError, OSError) as exc:
                log_connection_error("sending direct fake data failed", exc)
                return
        elif bypass_method == "wrong_seq":
            if fake_injective_conn is None:
                log_connection_error("wrong_seq requires packet injection", RuntimeError("packet injector is disabled"))
                return
            try:
                await asyncio.wait_for(fake_injective_conn.t2a_event.wait(), 2)
                if fake_injective_conn.t2a_msg == "unexpected_close":
                    raise ConnectionError("unexpected close while waiting for injected packet ack")
                if fake_injective_conn.t2a_msg != "fake_data_ack_recv":
                    log_connection_error("unexpected packet injection state", RuntimeError(fake_injective_conn.t2a_msg))
                    return
            except (asyncio.TimeoutError, ConnectionError, OSError) as exc:
                log_connection_error("packet injection handshake failed", exc)
                return
        else:
            log_connection_error("unknown BYPASS_METHOD", ValueError(bypass_method))
            return

        stop_fake_connection(fake_injective_conn)
        fake_injective_conn = None

        # early_data = data[payload_index:]
        # if early_data:
        #     try:
        #         sent_len = await loop.sock_sendall(outgoing_sock, early_data)
        #         if sent_len != len(early_data):
        #             raise ValueError("incomplete send")
        #     except Exception:
        #         close_socket(outgoing_sock)
        #         close_socket(incoming_sock)
        #         return

        await relay_bidirectional(incoming_sock, outgoing_sock)
        outgoing_sock = None

    except asyncio.CancelledError:
        raise
    except Exception as exc:
        log_connection_error(f"connection handler failed for {incoming_remote_addr}", exc)
        traceback.print_exc()
    finally:
        stop_fake_connection(fake_injective_conn)
        close_socket(outgoing_sock)
        close_socket(incoming_sock)

async def main():
    mother_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    mother_sock.setblocking(False)
    mother_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    mother_sock.bind((LISTEN_HOST, LISTEN_PORT))
    enable_keepalive(mother_sock)
    mother_sock.listen()
    loop = asyncio.get_running_loop()
    while True:
        try:
            incoming_sock, addr = await loop.sock_accept(mother_sock)
        except (ConnectionError, OSError) as exc:
            log_connection_error("accept failed", exc)
            continue
        incoming_sock.setblocking(False)
        enable_keepalive(incoming_sock)
        asyncio.create_task(handle(incoming_sock, addr))


if __name__ == "__main__":
    set_windows_event_loop_policy()
    if is_packet_injection_enabled():
        if not INTERFACE_IPV4:
            sys.exit("INTERFACE_IPV4 is required for pydivert packet injection")
        w_filter = "tcp and " + "(" + "(ip.SrcAddr == " + INTERFACE_IPV4 + " and ip.DstAddr == " + CONNECT_IP + ")" + " or " + "(ip.SrcAddr == " + CONNECT_IP + " and ip.DstAddr == " + INTERFACE_IPV4 + ")" + ")"
        fake_tcp_injector = FakeTcpInjector(w_filter, fake_injective_connections)
        threading.Thread(target=fake_tcp_injector.run, args=(), daemon=True).start()
    print_startup_info()
    print("هشن شومافر تیامح دینکیم هدافتسا دازآ تنرتنیا هب یسرتسد یارب همانرب نیا زا رگا")
    print(
        "دراد امش تیامح هب زاین هک مراد رظن رد دازآ تنرتنیا هب ناریا مدرم مامت یسرتسد یارب یدایز یاه همانرب و اه هژورپ")
    print("\n")
    print("USDT (BEP20): 0x76a768B53Ca77B43086946315f0BDF21156bF424\n")
    print("@patterniha")
    asyncio.run(main())
