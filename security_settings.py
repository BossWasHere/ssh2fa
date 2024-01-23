import base64
import hmac
import os
import struct
import subprocess
import time

PASSWORD_FILE_MAX_SIZE = 256
PROMPT_PASS = 0
PROMPT_OTP = 1


class SettingsException(Exception):

    def __init__(self, message):
        super().__init__(message)


class SecuritySettings(object):
    """ Security settings for SSH connection
    """

    def __init__(self, password_prompt='assword', otp_prompt='erification code', quiet_prompt=False):
        self.password_mode = None
        self.password_env_var = None
        self.password = None
        self.otp_mode = None
        self.otp_command = None
        self.otp = None
        self.totp_secret = None
        self.totp_interval = None
        self.totp_digits = None
        self.totp_digest = None
        self.prompt_sequence = None
        self.password_prompt = password_prompt
        self.otp_prompt = otp_prompt
        self.quiet_prompt = quiet_prompt

    def ensure_virgin_password(self):
        if self.password_mode:
            raise SettingsException('Password mode already set')

    def ensure_virgin_otp(self):
        if self.otp_mode:
            raise SettingsException('OTP mode already set')

    def set_password(self, password):
        self.ensure_virgin_password()
        self.password_mode = 'password'
        self.password = password

    def set_password_env_var(self, env_var):
        self.ensure_virgin_password()
        self.password_mode = 'password_env_var'
        self.password_env_var = env_var

        self.password = os.environ.get(self.password_env_var)
        if self.password is None:
            raise SettingsException('Environment variable not set: ' + self.password_env_var)

        del os.environ[self.password_env_var]

    def set_password_file(self, filename):
        self.ensure_virgin_password()
        self.password_mode = 'password_file'

        try:
            with open(filename, 'r') as f:
                self.password = f.read()

            read_size = len(self.password)
            if read_size > PASSWORD_FILE_MAX_SIZE:
                raise SettingsException('Password from file too large: ' + filename)
            elif read_size == 0:
                raise SettingsException('Password file empty: ' + filename)
            if self.password[-1] == '\n':
                self.password = self.password[:-1]
            if self.password[-1] == '\r':
                self.password = self.password[:-1]

        except IOError as e:
            raise SettingsException('Error reading password file: ' + filename + ' (' + str(e) + ')')

    def set_otp(self, otp):
        self.ensure_virgin_otp()
        self.otp_mode = 'otp'
        self.otp = otp

    def set_otp_command(self, command):
        self.ensure_virgin_otp()
        self.otp_mode = 'otp_command'
        self.otp_command = command

    def set_totp(self, totp_secret, totp_interval=30, totp_digits=6, totp_digest='sha1'):
        self.ensure_virgin_otp()
        self.otp_mode = 'totp'
        self.totp_secret = totp_secret
        self.totp_interval = totp_interval
        self.totp_digits = totp_digits
        self.totp_digest = totp_digest

    def set_prompt_sequence(self, sequence):
        self.prompt_sequence = sequence

    def get_prompt_sequence(self):
        if self.prompt_sequence is None:
            self.prompt_sequence = []
            if self.password_mode:
                self.prompt_sequence.append(PROMPT_PASS)
            if self.otp_mode:
                self.prompt_sequence.append(PROMPT_OTP)

        if not self.password_mode and PROMPT_PASS in self.prompt_sequence:
            raise SettingsException('Password mode not set but is required by sequence')
        if not self.otp_mode and PROMPT_OTP in self.prompt_sequence:
            raise SettingsException('OTP mode not set but is required by sequence')

        return self.prompt_sequence

    def clear_password(self):
        self.password = None

    def clear_otp(self):
        self.otp = None
        self.otp_command = None
        self.totp_secret = None

    def clear_all(self):
        self.clear_password()
        self.clear_otp()

    def safe_environment(self):
        """ Return a copy of the environment with sensitive variables removed
        """
        env = os.environ.copy()
        if self.password_mode == 'password_env_var':
            del env[self.password_env_var]

        return env

    def run_otp_command(self):
        """ Run OTP command and set OTP if successful
        """
        try:
            output = subprocess.check_output(self.otp_command, shell=True, env=self.safe_environment())
            self.otp = output.decode('utf-8').strip()
            return 0
        except subprocess.CalledProcessError as e:
            print('OTP command failed: ' + str(e))
            return e.returncode

    def run_totp(self):
        key = base64.b32decode(self.totp_secret.upper() + '=' * ((8 - len(self.totp_secret)) % 8))
        counter = struct.pack('>Q', int(time.time() / self.totp_interval))
        mac = hmac.new(key, counter, self.totp_digest).digest()
        offset = mac[-1] & 0x0f
        binary = struct.unpack('>L', mac[offset:offset + 4])[0] & 0x7fffffff
        self.otp = str(binary)[-self.totp_digits:].zfill(self.totp_digits)


def load_totp_keyfile(path: str):
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

    return tuple(totp)
