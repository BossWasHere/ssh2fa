"""SSH2FA client for Windows
   Copyright (C) 2023-2024 Thomas Stephenson
"""

import argparse
import os
import signal
import sys

if os.name == 'posix':
    from client_unix import UnixClient as Client
elif os.name == 'nt':
    from client_win import WinClient as Client
else:
    raise Exception('Unsupported OS: ' + os.name)

import client_base as cb
from security_settings import SecuritySettings

ssh_client: cb.SSHClientBase | None = None


def main():
    # ssh2fa.py [-h] [-v] [-i TYPE VALUE] [-P PASSWORD_PROMPT] [-O OTP_PROMPT] [-q] [-n] [-x] ssh_args
    argparser = argparse.ArgumentParser()
    argparser.add_argument('-v', '--verbose', action='store_true', help='Use verbose output')
    argparser.add_argument('-i', '--input', nargs=2, action='append', metavar=('TYPE', 'VALUE'),
                           help='Input order to send to prompts. Can be specified multiple times. The following type-'
                                'value pairs are supported: [pp PASSWORD] [pe ENV_VAR] [pf FILE_PATH] '
                                '[op OTP] [oe ENV_VAR] [of FILE_PATH] [oc COMMAND] [rp REPEAT_IDX]')
    argparser.add_argument('-P', '--password-prompt', default='assword', help='Password prompt to look for')
    argparser.add_argument('-O', '--otp-prompt', default='erification code', help='OTP prompt to look for')
    argparser.add_argument('-q', '--quiet-prompt', action='store_true', help='Do not print received prompts')
    argparser.add_argument('-n', '--no-ssh', action='store_true', help='Use custom SSH executable in ssh_args')
    argparser.add_argument('-x', '--no-shell', action='store_true',
                           help='Disables interaction after SSH connection is established')
    argparser.add_argument('ssh_args', nargs='+', help='Arguments to pass to SSH')

    # Parse the arguments
    args = argparser.parse_args()

    # Clear argv (might not help)
    sys.argv = sys.argv[:1]

    # Create security settings
    security_settings = SecuritySettings(args.password_prompt, args.otp_prompt, args.quiet_prompt)
    for input_type, value in args.input or []:
        input_type = input_type.lower()

        if input_type == 'pp':
            security_settings.add_password(value)
        elif input_type == 'pe':
            security_settings.add_password_env_var(value)
        elif input_type == 'pf':
            security_settings.add_password_file(value)
        elif input_type == 'op':
            security_settings.add_otp(value)
        elif input_type == 'oe':
            security_settings.add_otp_env_var(value)
        elif input_type == 'of':
            security_settings.add_totp_file(value)
        elif input_type == 'oc':
            security_settings.add_otp_command(value)
        elif input_type == 'rp':
            security_settings.add_repeated_input(int(value))
        else:
            print('Unknown input type: ' + input_type, file=sys.stderr)
            return cb.ARGS_EXCEPT

    # Finish security settings
    security_settings.clear_envs()

    # If args quoted, split them here (allows for -flags)
    if len(args.ssh_args) == 1:
        args_to_pass = args.ssh_args[0].split()
    else:
        args_to_pass = args.ssh_args

    if not args.no_ssh:
        args_to_pass.insert(0, 'ssh')

    # Create SSH client
    global ssh_client
    ssh_client = Client(args_to_pass, security_settings, not args.no_shell, args.verbose)

    # Run SSH client
    result = ssh_client.run()
    if args.verbose and result != 0:
        print(f'\nSSH client exited with code: {result}', file=sys.stderr)

    return result


def signal_handler(sig, frame):
    print('Caught signal: ' + str(sig))

    global ssh_client
    if ssh_client:
        ssh_client.kill()


if __name__ == '__main__':
    signal.signal(signal.SIGINT, signal_handler)
    code = main()
    sys.exit(code)
