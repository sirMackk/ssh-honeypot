import argparse
import asyncio
import logging
import sys

import asyncssh

from sshhoneypot import __version__

DEFAULT_SSH_BANNER = 'OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.8'


class HoneypotServer(asyncssh.SSHServer):
    def __init__(self, *args, logger=None, **kwargs):
        self._log = logger

    def connection_made(self, conn):
        self._log.info('Got connection!')
        self.conn = conn

    def begin_auth(self, username):
        self._log.info('Getting connection!')
        # Accept authentication for ANY username
        return True

    def validate_password(self, username, password):
        # Always validate password as false
        ip, port = self.conn.get_extra_info('peername')
        client_version = self.conn.get_extra_info('client_version')
        self._log.info('LOG IN ATTEMPT: {username}@{ip}:{port}, password: {password}, client: {client_v}'.format(
            username=username,
            password=password,
            ip=ip,
            port=port,
            client_v=client_version))
        return False

    def password_auth_supported(self):
        return True

    def connection_lost(self, exc):
        self._log.info('Connection closed')
        if exc is not None:
            self._log.info('Connection lost - {0}'.format(exc))


class HoneyPotFactory:
    def __init__(self, args, serverClass):
        self.args = args
        self.serverClass = serverClass
        self.banner = args.banner
        self._get_key(args)

    def _get_key(self, args):
        """Sets either random or user-provided ssh-rsa key.

        args:
            args (dict): Dict that should contain 'key_file' key.
        """
        if args.key_file is None:
            key = asyncssh.generate_private_key('ssh-rsa', 'RandomKey', key_size=1024)
        else:
            with open(args.key_file, 'rb') as f:
                key = asyncssh.import_private_key(f.read())
        self.ssh_key = key

    def __call__(self):
        return self.serverClass(logger=args.logger)



async def start_server(server_factory, host='', port=22):
    await asyncssh.create_server(server_factory, '', port, server_host_keys=[server_factory.ssh_key], server_version=server_factory.banner)

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--host', default='0.0.0.0', help='Host address. Default: 0.0.0.0')
    parser.add_argument('-p', '--port', type=int, help='Listening port. Default: 22')
    parser.add_argument('-b', '--banner', default=DEFAULT_SSH_BANNER, help='Set custom ssh banner. Default: {0}'.format(DEFAULT_SSH_BANNER))
    parser.add_argument('-k', '--key-file', help='Path to SSH private key file for the SSH server. If not given, will generate a new 1024-bit key on every start')
    parser.add_argument('-v', '--verbose', action='store_true')
    parser.add_argument('--version', action='store_true', help='Log debug information')
    args = parser.parse_args()

    if args.version:
        print('SSH-HoneyPot {version}'.format(version=__version__))
        sys.exit(0)

    log_level = logging.DEBUG if args.verbose else logging.INFO

    logger = logging.getLogger('ssh-honeypot')
    handler = logging.StreamHandler(stream=sys.stdout)
    handler.setLevel(log_level)
    logger.setLevel(log_level)
    formatter = logging.Formatter('%(asctime)s [%(levelname)s] %(message)s')

    handler.setFormatter(formatter)
    logger.addHandler(handler)
    args.logger = logger

    host = args.host
    port = args.port
    server_factory = HoneyPotFactory(args, HoneypotServer)

    loop = asyncio.get_event_loop()
    try:
        loop.run_until_complete(start_server(server_factory, host, port))
    except (OSError, asyncssh.Error) as e:
        logger.error('Exc: {0}'.format(e))
        sys.exit(1)

    loop.run_forever()
