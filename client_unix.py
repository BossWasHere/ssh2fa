import client_base as cb
from security_settings import SecuritySettings


class UnixClient(cb.SSHClientBase):

    def __init__(self, process_args: [str], security_settings: SecuritySettings, interactive=True, verbose=False):
        super().__init__(process_args, security_settings, interactive, verbose)

    def run(self):
        print('Client not yet supported.')
        pass

    def kill(self):
        pass
