import os
import signal
import subprocess
import sys
import time
import threading

import winpty
import client_base as cb
from security_settings import SecuritySettings, PROMPT_PASS, PROMPT_OTP


class WinClient(cb.SSHClientBase):

    def __init__(self, process_args: [str], security_settings: SecuritySettings, interactive=True, verbose=False, pty_kill_delay=0.1, read_interval=0.001):
        super().__init__(process_args, security_settings, interactive, verbose)
        self.pty_kill_delay = pty_kill_delay
        self.read_interval = read_interval
        self.pty: winpty.PTY | None = None

    def run(self):
        # Check process path valid
        child_environ = self.security_settings.safe_environment()
        path = child_environ.get('PATH', os.defpath)

        actual_process = self.check_process_path(self.process_args[0], path)
        if not actual_process:
            return cb.SSH_ERROR

        # Create environment
        actual_process_args = subprocess.list2cmdline(self.process_args[1:])
        cwd = os.getcwd()
        env_pairs = ['%s=%s' % (key, value) for (key, value) in child_environ.items()]
        condensed_env = ('\0'.join(env_pairs) + '\0')

        # Start process
        startup_dims = self.preferred_terminal_size()
        self.pty = winpty.PTY(startup_dims[0], startup_dims[1])
        # noinspection PyTypeChecker
        self.pty.spawn(actual_process, cmdline=actual_process_args, cwd=cwd, env=condensed_env)

        for prompt_type in self.security_settings.get_prompt_sequence():

            if prompt_type == PROMPT_PASS:
                result = self.await_password_entry()
                if result != cb.SSH_DONE:
                    self.kill_pty()
                    return result

            elif prompt_type == PROMPT_OTP:
                result = self.await_otp_entry()
                if result != cb.SSH_DONE:
                    self.kill_pty()
                    return result

        self.security_settings.clear_all()
        self.user_io()
        self.kill_pty(force=True)
        return cb.SSH_DONE

    def kill(self):
        self.kill_pty(force=True)

    def user_io(self):
        if self.interactive:
            # Start interactive input thread
            input_thread = threading.Thread(target=_interactive_input_thread, args=(self.pty,))
            input_thread.daemon = True
            input_thread.start()

        while self.pty.isalive():
            try:
                # noinspection PyTypeChecker
                data: str = self.pty.read(4096, blocking=False)
                if data:
                    sys.stdout.buffer.write(data.encode(sys.stdout.encoding))
                    sys.stdout.flush()
                else:
                    time.sleep(self.read_interval)
            except winpty.WinptyError:
                time.sleep(self.read_interval)
              
        # TODO ensure thread exited
        # if input_thread:
        #     input_thread.

    def kill_pty(self, force=False) -> bool:
        if not self.pty.isalive():
            return True

        os.kill(self.pty.pid, signal.SIGINT)
        time.sleep(self.pty_kill_delay)
        if not self.pty.isalive():
            return True

        if force:
            os.kill(self.pty.pid, signal.SIGTERM)
            time.sleep(self.pty_kill_delay)

        return not self.pty.isalive()

    def read_buf_until_match(self, matches: [str], bufsize=4096, timeout=5.0, show_output=False) -> int:
        if not self.pty.isalive():
            return -1

        start = time.time()
        data = self.pty.read(bufsize, blocking=False)
        printed_bytes = 0
        current_byte_head = 0
        run = True

        while run:
            if data:
                try:
                    data_len = len(data)
                    content = data  #.decode('utf-8')
                    current_byte_head += data_len

                    if show_output:
                        bytes_to_print = current_byte_head - printed_bytes
                        decoded_range = data[-bytes_to_print:]  #.decode('utf-8')
                        sys.stdout.write(decoded_range)
                        printed_bytes = current_byte_head

                    for i in range(len(matches)):
                        if matches[i] in content:
                            return i

                    more_data = None
                    while run and not more_data:
                        if time.time() - start > timeout:
                            run = False
                        time.sleep(self.read_interval)
                        if self.pty.isalive():
                            more_data = self.pty.read(bufsize, blocking=False)
                        else:
                            run = False

                    if run:
                        data += more_data
                        new_data_len = len(data)
                        # Make sure buffer doesn't get too large
                        if new_data_len > bufsize * 2:
                            data = data[-bufsize:]
                            printed_bytes -= new_data_len - bufsize

                except UnicodeDecodeError:
                    # Decode error - probably not UTF-8 yet
                    more_data = None
                    while run and not more_data:
                        if time.time() - start > timeout:
                            run = False
                        time.sleep(self.read_interval)
                        if self.pty.isalive():
                            more_data = self.pty.read(bufsize, blocking=False)
                        else:
                            run = False

                    if run:
                        data += more_data

            elif time.time() - start > timeout:
                run = False

            else:
                time.sleep(self.read_interval)
                if self.pty.isalive():
                    data = self.pty.read(bufsize, blocking=False)
                else:
                    run = False
                printed_bytes = 0
                current_byte_head = 0

        return -1

    def await_password_entry(self) -> int:
        # Wait for password prompt
        password_prompt = self.security_settings.password_prompt
        match_patterns = [cb.HOST_AUTHENTICITY_PROMPT_MATCH, cb.HOST_KEY_CHANGED_PROMPT_MATCH, password_prompt]
        match_idx = self.read_buf_until_match(match_patterns, show_output=not self.security_settings.quiet_prompt)

        match match_idx:
            case -1:
                sys.stderr.write('Password prompt not detected - aborting\n')
                return cb.SSH_PROMPT_TIMEOUT
            case 0:
                sys.stderr.write('Host authenticity prompt detected - aborting\n')
                return cb.SSH_HOST_UNKNOWN
            case 1:
                sys.stderr.write('Host key changed prompt detected - aborting\n')
                return cb.SSH_HOST_UNSAFE
            case 2:
                pass
            case _:
                return self.pty.get_exitstatus() or cb.SSH_ERROR

        if self.pty.isalive():
            # Send password and clear
            self.pty.write(self.security_settings.password + '\n')

        else:
            # Clear password and OTP
            self.security_settings.clear_all()
            return self.announce_dead()

        return cb.SSH_DONE

    def await_otp_entry(self) -> int:
        # Wait for OTP prompt
        otp_prompt = self.security_settings.otp_prompt

        match_patterns = [otp_prompt]
        match_idx = self.read_buf_until_match(match_patterns, show_output=not self.security_settings.quiet_prompt)
        match match_idx:
            case -1:
                sys.stderr.write('OTP prompt not detected - aborting\n')
                return cb.SSH_PROMPT_TIMEOUT
            case 0:
                pass
            case _:
                return self.pty.get_exitstatus() or cb.SSH_ERROR

        if self.pty.isalive():
            # Send OTP
            otp_mode = self.security_settings.otp_mode
            if otp_mode == 'otp_command' and self.security_settings.run_otp_command() != 0:
                return cb.OTP_COMMAND_ERROR
            if otp_mode == 'totp':
                self.security_settings.run_totp()
            if self.security_settings.otp is None:
                return cb.OTP_UNSET

            self.pty.write(self.security_settings.otp + "\n")

        else:
            # Clear password and OTP
            self.security_settings.clear_all()
            return self.announce_dead()

        return cb.SSH_DONE

    def announce_dead(self) -> int:
        exit_code = self.pty.get_exitstatus()
        sys.stderr.write(f'Process died with code {exit_code}\n')
        return exit_code or cb.SSH_ERROR


def _interactive_input_thread(pty: winpty.PTY, bufsize=4096, read_interval=0.001):
    while pty.isalive():
        try:
            data = sys.stdin.buffer.read()
            if data:
                pty.write(data.decode(sys.stdin.encoding))
            else:
                time.sleep(read_interval)
        except winpty.WinptyError:
            time.sleep(read_interval)
