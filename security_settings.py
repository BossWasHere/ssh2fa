import base64
import hmac
import os
import struct
import subprocess
import time

PASSWORD_FILE_MAX_SIZE = 256
PROMPT_PASS, PROMPT_OTP = 'password', 'otp'
INPUT_PASS, INPUT_OTP, INPUT_TOTP, INPUT_OTP_COMMAND, INPUT_REPEAT = range(5)


class SettingsException(Exception):

    def __init__(self, message):
        super().__init__(message)


class SecuritySettings(object):
    """ Security settings for SSH connection
    """

    def __init__(self, password_prompt='assword', otp_prompt='erification code', quiet_prompt=False):
        self.__sequence_idx = 0

        self.sequence = []
        self.envs = set()
        self.password_prompt = password_prompt
        self.otp_prompt = otp_prompt
        self.quiet_prompt = quiet_prompt

    def __iter__(self) -> 'SecuritySettings':
        self.__sequence_idx = -1
        return self

    def __next__(self) -> str:
        self.__sequence_idx += 1
        if self.__sequence_idx >= len(self.sequence):
            raise StopIteration

        input_type, data = self.sequence[self.__sequence_idx]
        if input_type == INPUT_REPEAT:
            input_type = self.sequence[data][0]

        if input_type >= INPUT_OTP:
            return PROMPT_OTP
        else:
            return PROMPT_PASS

    def next_input(self):
        if self.__sequence_idx >= len(self.sequence):
            raise SettingsException('No more inputs')

        input_type, data = self.sequence[self.__sequence_idx]
        if input_type == INPUT_REPEAT:
            input_type, data = self.sequence[data]

        if input_type == INPUT_PASS:
            return data
        elif input_type == INPUT_OTP:
            return data
        elif input_type == INPUT_TOTP:
            return run_totp(*data)
        elif input_type == INPUT_OTP_COMMAND:
            return self.run_command(data)

        raise SettingsException('Unknown input type: ' + str(input_type))

    def add_password(self, password):
        self.sequence.append((INPUT_PASS, password))

    def add_password_env_var(self, env_var):
        password = os.environ.get(env_var)
        if password is None:
            raise SettingsException('Environment variable not set: ' + env_var)

        self.envs.add(env_var)
        self.sequence.append((INPUT_PASS, password))

    def add_password_file(self, file_path):
        try:
            with open(file_path, 'r') as f:
                password = f.read().strip()

            read_size = len(password)
            if read_size > PASSWORD_FILE_MAX_SIZE:
                raise SettingsException('Password from file too large: ' + file_path)
            elif read_size == 0:
                raise SettingsException('Password file empty: ' + file_path)

            self.sequence.append((INPUT_PASS, password))

        except IOError as e:
            raise SettingsException('Error reading password file: ' + file_path + ' (' + str(e) + ')')

    def add_otp(self, otp):
        self.sequence.append((INPUT_OTP, otp))

    def add_otp_env_var(self, env_var):
        otp = os.environ.get(env_var)
        if otp is None:
            raise SettingsException('Environment variable not set: ' + env_var)

        self.envs.add(env_var)
        self.sequence.append((INPUT_OTP, otp))

    def add_totp_file(self, path: str):
        """ Load TOTP key from file
        :param path: Path to keyfile
        :return: (key, interval, digits, digest)
        """
        totp = [None, 30, 6, 'sha1']
        parsers = [str, int, int, str]

        with open(path, 'r') as f:
            data = f.read().strip()

        if len(data) == 0:
            raise SettingsException('TOTP keyfile empty: ' + path)

        tokens = data.split(':')
        expected = len(parsers)

        i = 0
        for token in tokens:
            if i >= expected:
                break
            if len(token) == 0:
                continue

            try:
                totp[i] = parsers[i](token)
                i += 1
            except ValueError:
                raise SettingsException('TOTP keyfile invalid: ' + path)

        self.add_totp(*totp)

    def add_otp_command(self, command):
        self.sequence.append((INPUT_OTP_COMMAND, command))

    def add_totp(self, totp_secret, totp_interval=30, totp_digits=6, totp_digest='sha1'):
        self.sequence.append((INPUT_TOTP, (totp_secret, totp_interval, totp_digits, totp_digest)))

    def add_repeated_input(self, idx):
        if idx >= len(self.sequence) or idx < 0:
            raise SettingsException('Repeated input index out of range: ' + str(idx))

        if self.sequence[idx][0] == INPUT_REPEAT:
            raise SettingsException('Cannot repeat a repeating input (use the original instead): ' + str(idx))

        self.sequence.append((INPUT_REPEAT, idx))

    def clear_envs(self):
        for env in self.envs:
            del os.environ[env]

    def clear_all(self):
        self.clear_envs()
        self.sequence = []

    def safe_environment(self):
        """ Return a copy of the environment with sensitive variables removed
        """
        env = os.environ.copy()
        for env_var in self.envs:
            del env[env_var]

        return env

    def run_command(self, cmd):
        """ Run command and return output
        """
        try:
            output = subprocess.check_output(cmd, shell=True, env=self.safe_environment())
            return output.decode('utf-8').strip()
        except subprocess.CalledProcessError as e:
            raise SettingsException('Command failed: ' + str(e))


def run_totp(totp_secret, totp_interval=30, totp_digits=6, totp_digest='sha1'):
    key = base64.b32decode(totp_secret.upper() + '=' * ((8 - len(totp_secret)) % 8))
    counter = struct.pack('>Q', int(time.time() / totp_interval))
    mac = hmac.new(key, counter, totp_digest).digest()
    offset = mac[-1] & 0x0f
    binary = struct.unpack('>L', mac[offset:offset + 4])[0] & 0x7fffffff
    return str(binary)[-totp_digits:].zfill(totp_digits)
