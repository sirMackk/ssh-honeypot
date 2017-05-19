# test logging on start, log in, lost

import pytest

from sshhoneypot.honeypot import HoneypotServer


@pytest.fixture
def log_adapter(mocker):
    logger = mocker.Mock()
    return logger


@pytest.fixture
def connection(mocker):
    conn = mocker.Mock()
    extra_info = {
        'peername': ('127.0.254.1', 12312),
        'client_version': 'ssh-test-version 0.1',
    }

    def extra_info(info_type):
        return extra_info[info_type]

    conn.get_extra_info.side_effect = extra_info
    return conn


def test_server_log_ip_on_conn_start(log_adapter, connection):
    server = HoneypotServer(logger=log_adapter)
    server.connection_made(connection)

    # think up decent log schema
    # assert connection called to get peer info
    log_adapter.info.assert_called_with('Got connection!')
