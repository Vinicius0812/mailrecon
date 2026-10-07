"""Run pytest with outbound sockets, DNS and SMTP disabled for this process."""

import os
import smtplib
import socket
import sys

import pytest


def forbidden(*args, **kwargs):
    raise AssertionError('Real network is forbidden in the synthetic test suite')


if __name__ == '__main__':
    os.environ['PYTHON_DOTENV_DISABLED'] = '1'
    socket.socket.connect = forbidden
    socket.socket.connect_ex = forbidden
    socket.create_connection = forbidden
    socket.getaddrinfo = forbidden
    socket.socket.sendto = forbidden
    socket.socket.send = forbidden
    socket.socket.sendall = forbidden
    smtplib.SMTP = forbidden
    raise SystemExit(pytest.main(sys.argv[1:] or ['-q']))
