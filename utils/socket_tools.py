import socket


def enable_keepalive(sock: socket.socket) -> None:
    """Enable TCP keepalive using only options available on this platform."""
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    keepalive_options = (
        ("TCP_KEEPIDLE", 11),
        ("TCP_KEEPINTVL", 2),
        ("TCP_KEEPCNT", 3),
    )
    for option_name, value in keepalive_options:
        option = getattr(socket, option_name, None)
        if option is not None:
            sock.setsockopt(socket.IPPROTO_TCP, option, value)
