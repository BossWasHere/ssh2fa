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
from security_settings import SecuritySettings, SettingsException, load_totp_keyfile, PROMPT_PASS, PROMPT_OTP


ssh_client: cb.SSHClientBase | None = None


def main():
    # ssh2fa.py [-h] [-v] [-P PASSWORD_PROMPT] [-p PASSWORD] [-e PASS_ENV_VAR] [-f PASS_FILE] [-O OTP_PROMPT]
    # [-o OTP] [-c OTP_COMMAND] [-t TOTP_KEYFILE] [-q] [-s PROMPT_SEQUENCE] [-n] [-x] ssh_args
    argparser = argparse.ArgumentParser()
    argparser.add_argument('-v', '--verbose', action='store_true', help='Use verbose output')
    argparser.add_argument('-P', '--password-prompt', default='assword', help='Password prompt to look for')
    argparser.add_argument('-p', '--password', help='Password to use')
    argparser.add_argument('-e', '--pass-env-var', help='Environment variable containing password')
    argparser.add_argument('-f', '--pass-file', help='File containing password')
    argparser.add_argument('-O', '--otp-prompt', default='erification code', help='OTP prompt to look for')
    argparser.add_argument('-o', '--otp', help='OTP to use')
    argparser.add_argument('-c', '--otp-command', help='Command to generate OTP')
    argparser.add_argument('-t', '--totp-keyfile', help='File containng TOTP key')
    argparser.add_argument('-q', '--quiet-prompt', action='store_true', help='Do not print prompts')
    argparser.add_argument('-s', '--prompt-sequence', required=False, help='Order of prompts to look for (p = password, o = OTP)')
    argparser.add_argument('-n', '--no-ssh', action='store_true', help='Use custom SSH executable in ssh_args')
    argparser.add_argument('-x', '--no-shell', action='store_true', help='Disables interaction after SSH connection is established')
    argparser.add_argument('ssh_args', nargs=argparse.REMAINDER, help='Arguments to pass to SSH')
    args = argparser.parse_args()

    # Clear argv (might not help)
    sys.argv = sys.argv[:1]

    # Create security settings
    security_settings = SecuritySettings(args.password_prompt, args.otp_prompt, args.quiet_prompt)
    try:
        if args.password:
            security_settings.set_password(args.password)
        if args.pass_env_var:
            security_settings.set_password_env_var(args.pass_env_var)
        if args.pass_file:
            security_settings.set_password_file(args.pass_file)
    except SettingsException:
        print('Only expected one of -p, -e, -f', file=sys.stderr)
        return cb.ARGS_EXCEPT

    try:
        if args.otp:
            security_settings.set_otp(args.otp)
        if args.otp_command:
            security_settings.set_otp_command(args.otp_command)
        if args.totp_keyfile:
            security_settings.set_totp(*load_totp_keyfile(args.totp_keyfile))
    except SettingsException:
        print('Only expected one of -o, -c', file=sys.stderr)
        return cb.ARGS_EXCEPT

    if args.prompt_sequence:
        seq = args.prompt_sequence.lower()
        if any(c not in 'po' for c in seq):
            print('Invalid prompt sequence (only "p" and "o" accepted)', file=sys.stderr)
            return cb.ARGS_EXCEPT

        security_settings.set_prompt_sequence([PROMPT_PASS if c == 'p' else PROMPT_OTP for c in seq])

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
