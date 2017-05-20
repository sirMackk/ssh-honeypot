import pytest

from sshhoneypot.honeypot import HoneypotServer


@pytest.fixture
def log_adapter(mocker):
    logger = mocker.Mock()
    return logger


@pytest.fixture
def client_info():
    return {
        'peername': ('127.0.254.1', 12312),
        'client_version': 'ssh-test-version 0.1',
    }


@pytest.fixture
def connection(mocker, client_info):
    conn = mocker.Mock()
    _extra_info = client_info

    def extra_info(info_type):
        return _extra_info[info_type]

    conn.get_extra_info.side_effect = extra_info
    return conn


def test_server_log_ip_on_conn_start(log_adapter, connection, client_info):
    server = HoneypotServer(logger=log_adapter)
    server.connection_made(connection)

    expected = '[127.0.254.1:12312] Established connection'
    assert expected in log_adapter.call_args[0]
    connection.get_extra_info.assert_called_with('peername')
    assert server._peer_ip == client_info['peername'][0]
    assert server._peer_port == client_info['peername'][1]


def test_server_log_details_on_login(log_adapter, connection, client_info):
    server = HoneypotServer(logger=log_adapter)
    server.conn = connection
    server._peer_ip = client_info['peername'][0]
    server._peer_port = client_info['peername'][1]
    res = server.validate_password('username', 'password')

    expected = ('[127.0.254.1:12312] Log-in attempt from "username" with '
                '"password", using "ssh-test-version 0.1"')
    assert not res
    assert expected in log_adapter.call_args[0]
    connection.get_extra_info.assert_called_with('client_version')


def test_server_log_conn_lost(log_adapter, client_info):
    server = HoneypotServer(logger=log_adapter)
    server._peer_ip = client_info['peername'][0]
    server._peer_port = client_info['peername'][1]
    server.connection_lost(None)

    expected = '[127.0.254.1:12312] Connection closed'
    assert log_adapter.call_count == 1
    assert expected in log_adapter.call_args[0]


def test_server_log_conn_lost_exception(log_adapter, client_info):
    class Exc:
        def __str__(self):
            return 'Horrendous Exception: All is lost'

    server = HoneypotServer(logger=log_adapter)
    server._peer_ip = client_info['peername'][0]
    server._peer_port = client_info['peername'][1]
    server.connection_lost(Exc())

    expected = '[127.0.254.1:12312] Connection lost, reason: {}'.format(
            str(Exc()))
    assert expected in log_adapter.call_args[0]


def test_begin_auth_is_true():
    server = HoneypotServer()

    assert server.begin_auth('whoever')


def test_password_auth_supported_is_true():
    server = HoneypotServer()

    assert server.password_auth_supported()
