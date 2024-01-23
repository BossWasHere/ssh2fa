import abc
import os
import shutil
import sys

from security_settings import SecuritySettings

HOST_AUTHENTICITY_PROMPT_MATCH = 'The authenticity of host '
HOST_KEY_CHANGED_PROMPT_MATCH = 'WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!'

SSH_DONE, SSH_ERROR, SSH_HOST_UNKNOWN, SSH_HOST_UNSAFE, SSH_PROMPT_TIMEOUT, OTP_COMMAND_ERROR, OTP_UNSET, ARGS_EXCEPT = range(8)


class SSHClientBase(abc.ABC):

    def __init__(self, process_args: [str], security_settings: SecuritySettings, interactive=True, verbose=False):
        self.process_args = process_args
        self.security_settings = security_settings
        self.interactive = interactive
        self.verbose = verbose

    @abc.abstractmethod
    def run(self):
        pass

    @abc.abstractmethod
    def kill(self):
        pass

    def check_process_path(self, process_path: str, path_env: str) -> str:
        proc = shutil.which(process_path, path=path_env)
        if proc is None and self.verbose:
            print(f'Could not find executable: {process_path}', file=sys.stderr)

        return proc

    @staticmethod
    def preferred_terminal_size() -> (int, int):
        try:
            return os.get_terminal_size()
        except OSError:
            return 80, 24
